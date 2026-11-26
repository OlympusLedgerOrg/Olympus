// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Minimal model backend for wiserepo: talks to a local Ollama daemon over
// fetch, no vendor SDK required. There is deliberately no cloud backend --
// see README's trust-boundary section. Repo contents (file bodies, diffs,
// grep hits) are handed to this module verbatim, and the default destination
// is a process on localhost (overridable via WISEREPO_OLLAMA_URL), which
// makes that safe by construction rather than by policy when kept local.

import { Agent } from "undici";

import { DEFAULT_NUM_CTX as BASE_NUM_CTX } from "./budget.mjs";

// Declared before the URL validation below, not after it. These are `class`
// declarations, so their bindings are in the temporal dead zone until their
// definition is evaluated — which is where a throw from that validation lands if
// it is ever evaluated at module scope, turning a misconfigured URL into
// `ReferenceError: Cannot access 'ModelRequestError' before initialization`
// instead of the real message. Ordering is what keeps the specific type.
/**
 * The backend could not be reached or could not produce usable output:
 * daemon not running, network failure, timeout, or a 200 whose body has no
 * usable text. Callers treat this as "the check did not run", NOT "the check
 * failed" — it must never block a commit.
 */
export class ModelUnavailableError extends Error {
  constructor(message, { cause } = {}) {
    super(message);
    this.name = "ModelUnavailableError";
    this.cause = cause;
  }
}

/**
 * The request itself was wrong — model not pulled, malformed body, or a
 * misconfigured environment variable. This is a bug in wiserepo or its
 * config, and is surfaced as a real failure rather than silently skipped: a
 * gate that fails OPEN on a typo is worse than no gate, because it reports
 * "skipping" instead of "misconfigured".
 */
export class ModelRequestError extends Error {
  constructor(message, { cause } = {}) {
    super(message);
    this.name = "ModelRequestError";
    this.cause = cause;
  }
}

/**
 * The endpoint to talk to, validated on every call rather than once at import.
 *
 * Evaluated at module scope, a bad WISEREPO_OLLAMA_URL throws before any handler
 * exists to catch it: bin/wiserepo.mjs's main() and mcp-server.mjs's tool
 * handler both only see a Node stack trace, so the operator gets a crash instead
 * of "request error — ...". Resolving here keeps exactly the same fail-closed
 * guard (it runs before the first request and before any repo content is
 * gathered), while letting the caller classify what went wrong.
 */
function ollamaBaseUrl() {
  const raw = process.env.WISEREPO_OLLAMA_URL || "http://localhost:11434";
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new ModelRequestError(`WISEREPO_OLLAMA_URL is not a valid URL: ${raw}`);
  }
  const loopback =
    url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (
    !loopback ||
    url.protocol !== "http:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new ModelRequestError(
      "WISEREPO_OLLAMA_URL must be a credential-free http URL on localhost, 127.0.0.1, or ::1",
    );
  }
  return url.origin;
}
// qwen2.5-coder:7b-instruct: a 7.61B code-specialised model (5.5T code tokens,
// 92 languages, HumanEval 88.4 / MBPP 83.5). Wiserepo's work is reading code and
// reviewing diffs, which is what that training buys; the cost is ~4.7GB of
// Q4_K_M weights and CPU-only inference (Ollama drops the Intel Arc iGPU unless
// OLLAMA_IGPU_ENABLE=1), so a qa call over a 30-40KB file takes minutes. Set
// WISEREPO_OLLAMA_MODEL to a smaller tag — e.g. qwen3.5:4b, pulled separately —
// to trade review quality for speed; the 404 path names whichever tag is
// configured, so a wrong value points at the fix.
const DEFAULT_OLLAMA_MODEL = process.env.WISEREPO_OLLAMA_MODEL || "qwen2.5-coder:7b-instruct";

// Per-tool model overrides. `summarize` does not need the review model, and on
// CPU the difference is minutes, so a deployment can point the cheap tools at a
// small tag and keep the strong one for review_diff. Unset -> the default above.
const TOOL_MODEL_ENV = {
  qa: "WISEREPO_MODEL_QA",
  review: "WISEREPO_MODEL_REVIEW",
  summarize: "WISEREPO_MODEL_SUMMARIZE",
};

export function modelForTool(tool) {
  const envName = TOOL_MODEL_ENV[tool];
  const override = envName ? process.env[envName] : undefined;
  return (override && override.trim()) || DEFAULT_OLLAMA_MODEL;
}

// Upper bound for every request deadline. WISEREPO_TIMEOUT_MS is validated
// against it and the undici dispatcher below is set a minute above it, so the
// dispatcher can never cut a call off before the AbortController's own deadline
// — which is what makes the timeout error say "timed out" instead of "failed".
const MAX_TIMEOUT_MS = 1_800_000;

// Number() returns NaN for any non-numeric string and never throws.
// WISEREPO_TIMEOUT_MS=45s would silently become NaN, setTimeout coerces NaN
// to 1ms, the abort fires before the request can complete, and the result
// is a ModelUnavailableError that reports "backend unavailable" forever —
// a misconfiguration that looks identical to a network problem and never
// gets fixed because nothing says "misconfigured". Validate at load time
// instead and raise loudly.
function numericEnv(name, fallback, { min, max }) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < min || value > max) {
    throw new ModelRequestError(`${name}="${raw}" is not a finite number in [${min}, ${max}]`);
  }
  return value;
}

// Same reasoning as numericEnv, for switches: a typo'd WISEREPO_THINK=treu
// must not silently fall back to the default and leave someone convinced they
// enabled something they did not. Accept the obvious spellings, reject the
// rest loudly.
function boolEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = raw.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(value)) return true;
  if (["0", "false", "no", "off"].includes(value)) return false;
  throw new ModelRequestError(`${name}="${raw}" is not a boolean (use 1/0, true/false, on/off)`);
}

// Low temperature reduces wording churn between runs on unchanged input. It
// does NOT make output byte-reproducible — sampling variance survives, and a
// model tag can be re-pulled underneath you. Nothing in this tool may assume
// byte-identical regeneration; compare structure, not bytes, when judging one.
const DEFAULT_TEMPERATURE = numericEnv("WISEREPO_TEMPERATURE", 0, { min: 0, max: 2 });
// Local generation on a 30B model is a lot slower per token than a hosted
// frontier API, and review_diff can emit thousands of tokens, so this default
// is much larger than a cloud-backed tool would
// need. Raise it further (or drop to a smaller model) if a big regeneration
// still times out.
const DEFAULT_TIMEOUT_MS = numericEnv("WISEREPO_TIMEOUT_MS", 300_000, {
  min: 1_000,
  max: MAX_TIMEOUT_MS,
});

// Ollama unloads an idle model after 5 minutes, and reloading this 7B costs
// ~17s of wall clock before the first token. Wiserepo is used in bursts
// (question, follow-up, review), so keeping the model resident across a
// working session is nearly free and removes that reload from every call.
// Accepts Ollama's duration syntax ("30m", "1h") or seconds; "-1" pins it.
const DEFAULT_KEEP_ALIVE = (() => {
  const raw = process.env.WISEREPO_KEEP_ALIVE;
  if (raw === undefined || raw === "") return "30m";
  const trimmed = raw.trim();
  if (!trimmed) throw new ModelRequestError("WISEREPO_KEEP_ALIVE must not be blank");
  return /^-?\d+$/.test(trimmed) ? Number(trimmed) : trimmed;
})();

// Node's fetch (undici) applies its OWN 300s headersTimeout/bodyTimeout to every
// request, independent of the AbortController in postChat. That fired first on
// the first real 7B-on-CPU call: a 40KB source file is ~13k prompt tokens,
// prompt processing ran past 300s, and the request died as an opaque
// "fetch failed" with WISEREPO_TIMEOUT_MS=600000 having had no effect at all.
// One shared Agent, its timeouts a minute above MAX_TIMEOUT_MS, puts the
// AbortController back in charge of every deadline. Slow local generation makes
// this the normal path for any non-trivial file, not an edge case.
const MODEL_DISPATCHER = new Agent({
  headersTimeout: MAX_TIMEOUT_MS + 60_000,
  bodyTimeout: MAX_TIMEOUT_MS + 60_000,
  connectTimeout: 30_000,
});

// Ollama's own default window is sized from available VRAM and lands at 4096
// on a CPU-only box. An oversized prompt is then truncated by the daemon
// SILENTLY — no error, no warning — so the model would answer confidently
// from a partial view while `gatherContext` reported nothing missing. Pin the
// window explicitly (and clamp it to what the model declares — see
// effectiveNumCtx), and let `budgetCharsFor` size every caller's char budget
// from the same number so "what the model saw" and "the tool said it sent"
// cannot disagree.
const DEFAULT_NUM_CTX = numericEnv("WISEREPO_NUM_CTX", BASE_NUM_CTX, {
  min: 2_048,
  max: 262_144,
});

// Ollama turns reasoning ON by default for thinking-capable models (qwen3.5 is
// one; qwen2.5-coder is not, and ignores the flag). On CPU that is thousands of
// extra tokens before the first answer token — minutes for a repo question. Off
// unless explicitly asked for (WISEREPO_THINK=1), which is worth it only for a
// hard review_diff on a thinking model.
const DEFAULT_THINK = boolEnv("WISEREPO_THINK", false);

// Known daemon-side failures worth naming. A 500 whose body says
// "llama-server binary not found" used to surface as a generic backend error,
// which is precisely how an hour gets spent hunting a network problem that is
// actually a broken install. Matching the body turns each of these into the
// next action.
const DAEMON_FAILURE_HINTS = [
  {
    match: /llama-server binary not found/i,
    hint: () =>
      "the Ollama install is missing its model runner — restore lib/ollama from the " +
      "matching ollama-windows-amd64.zip release (see tools/wiserepo/README.md)",
  },
  {
    match: /out of memory|failed to allocate|insufficient memory|requires more system memory/i,
    hint: () => "the model does not fit in available RAM — use a smaller tag or free memory",
  },
  {
    match: /failed to load model|error loading model|unknown model architecture/i,
    hint: () =>
      "the daemon could not load this model file — check `ollama list` and re-pull the tag",
  },
];

// Map an HTTP failure onto the right error class. Server errors and
// request-timeout (408) are transient => unavailable (non-blocking). A 404
// (model not pulled) or 400 (bad request body) means retrying never fixes
// it => request error (blocking), because silence would hide the bug.
//
// Ollama needs no credential, so unlike a cloud backend there is no 401/403
// path and nothing secret to redact from an error body.
function classifyHttpFailure(
  status,
  body,
  { provider = "Ollama", model = DEFAULT_OLLAMA_MODEL } = {},
) {
  const detail = typeof body === "string" ? body : "";
  const base = `${provider} API error ${status}: ${detail}`;

  for (const known of DAEMON_FAILURE_HINTS) {
    if (known.match.test(detail)) {
      return new ModelUnavailableError(`${base} — ${known.hint()}`);
    }
  }
  if (status === 404) {
    return new ModelRequestError(
      `${base} (model "${model}" not pulled? try: ollama pull ${model})`,
    );
  }
  if (status === 408 || status >= 500) {
    return new ModelUnavailableError(base);
  }
  return new ModelRequestError(base);
}

/**
 * Progress reporter for streaming generation.
 *
 * A 5-minute CPU call that prints nothing is indistinguishable from a hang, and
 * that is exactly the shape of every large qa/review call here. One dot per
 * ~128 characters of answer proves liveness without drowning the terminal.
 * Silent when stderr is not a TTY (MCP clients, CI) or WISEREPO_PROGRESS=0.
 */
function defaultProgressReporter() {
  if (process.env.WISEREPO_PROGRESS === "0") return undefined;
  if (!process.stderr.isTTY) return undefined;
  let shown = 0;
  return (chars) => {
    while (shown + 128 <= chars) {
      process.stderr.write(".");
      shown += 128;
    }
  };
}

// Reads the body INSIDE the timed section and returns it alongside the
// response. `fetch()` resolves as soon as headers arrive — the body is
// still streaming — so a version of this that only timed `fetch()` and let
// callers read `res.text()` afterward left the body read completely
// unbounded: a daemon that returns 200 with headers and then stalls mid-body
// would hang the process with no diagnostic — for a CLI or MCP call that is a
// silent stall the caller never learns about. The same reason is why the NDJSON
// stream below is consumed here rather than by the caller.
async function withTimeout(url, options, timeoutMs, consume) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      dispatcher: MODEL_DISPATCHER,
    });
    // The caller's consumer runs HERE, while the timer is still armed, so the
    // deadline covers the whole response — headers and streamed body — and not
    // just the time to first byte.
    return await consume(res);
  } catch (err) {
    // Anything we classified deliberately (bad request, unpulled model, known
    // daemon failure) already says what to do; re-wrap it and the hint is lost.
    if (err instanceof ModelUnavailableError || err instanceof ModelRequestError) {
      throw err;
    }
    // Sanitize URL before interpolating into error messages: strip userinfo,
    // query string, and fragment to prevent credential leakage.
    let sanitizedUrl;
    try {
      const parsed = new URL(url);
      parsed.username = "";
      parsed.password = "";
      parsed.search = "";
      parsed.hash = "";
      sanitizedUrl = parsed.href;
    } catch {
      sanitizedUrl = "[invalid URL]";
    }

    if (err.name === "AbortError") {
      throw new ModelUnavailableError(`request to ${sanitizedUrl} timed out after ${timeoutMs}ms`, {
        cause: err,
      });
    }
    // Connection-refused lands here, which is the overwhelmingly common
    // case: the Ollama daemon isn't running. That's environmental, not a
    // bug in the request, so it stays non-blocking.
    throw new ModelUnavailableError(
      `request to ${sanitizedUrl} failed: ${err.message} (is the Ollama daemon running?)`,
      { cause: err },
    );
  } finally {
    clearTimeout(timer);
  }
}

function parseJsonBody(body, provider) {
  try {
    return JSON.parse(body);
  } catch (err) {
    throw new ModelUnavailableError(`${provider} returned a non-JSON body`, { cause: err });
  }
}

function extractCompletion(data) {
  const text = data?.message?.content ?? "";
  if (!text.trim()) {
    throw new ModelUnavailableError("Ollama returned an empty or unparseable completion");
  }
  return text;
}

// Ollama reports the token counts itself, on the final stream event (or the
// single body when stream:false). Passing them out is what makes a local call
// measurable: without this, "the local tier spent 1,200 prompt tokens" would be
// an estimate derived from character counts, and an estimate in a cost log is
// indistinguishable from a measurement once it is written down.
const tokenCount = (value) => (Number.isInteger(value) && value >= 0 ? value : null);

function statsFromEvent(event) {
  return {
    promptTokens: tokenCount(event?.prompt_eval_count),
    completionTokens: tokenCount(event?.eval_count),
    doneReason: typeof event?.done_reason === "string" ? event.done_reason : null,
  };
}

/**
 * Turn an NDJSON completion into text.
 *
 * `/api/chat` streams newline-delimited JSON events; only the `message.content`
 * fragments are the answer (`message.thinking` is reasoning, which
 * WISEREPO_THINK controls server-side and is deliberately not returned). A
 * fetch stub in tests has no `body` stream, so that case falls back to parsing
 * a single JSON object — the same shape the daemon returns for stream:false.
 */
async function readCompletion(res, provider, onProgress, onStats) {
  if (!res.body) {
    const parsed = parseJsonBody(await res.text(), provider);
    onStats?.(statsFromEvent(parsed));
    return extractCompletion(parsed);
  }

  const decoder = new TextDecoder();
  let buffer = "";
  let content = "";

  const handleLine = (line) => {
    const event = parseJsonBody(line, provider);
    if (event.error) {
      throw new ModelUnavailableError(`${provider} error mid-stream: ${event.error}`);
    }
    const piece = event.message?.content;
    if (typeof piece === "string" && piece) {
      content += piece;
      onProgress?.(content.length);
    }
    if (event.done === true) {
      onStats?.(statsFromEvent(event));
      return true;
    }
    return false;
  };

  for await (const chunk of res.body) {
    buffer += decoder.decode(chunk, { stream: true });
    let newline;
    while ((newline = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (line && handleLine(line)) return extractCompletion({ message: { content } });
    }
  }
  buffer += decoder.decode();
  if (buffer.trim()) handleLine(buffer.trim());
  return extractCompletion({ message: { content } });
}

// The daemon reports the model's real window in /api/show as
// "<architecture>.context_length", and the digest of the weights it has loaded
// for that tag. Cached per model: neither can change without the tag being
// re-pulled, and this must not add a round trip per call.
const modelInfoCache = new Map();

// /api/show carries the window but not always the digest (the daemon here
// omits it); /api/tags lists every pulled tag with one. Separate request, only
// made when show had nothing, and only once per model thanks to the cache.
async function digestFromTags(model) {
  try {
    const res = await fetch(`${ollamaBaseUrl().replace(/\/+$/, "")}/api/tags`, {
      dispatcher: MODEL_DISPATCHER,
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return null;
    const models = (await res.json())?.models ?? [];
    const match = models.find((entry) => entry?.name === model || entry?.model === model);
    return typeof match?.digest === "string" ? match.digest : null;
  } catch {
    return null;
  }
}

async function showModel(model) {
  if (modelInfoCache.has(model)) return modelInfoCache.get(model);
  let info = { digest: null, declaredContextLength: null };
  try {
    const res = await fetch(`${ollamaBaseUrl().replace(/\/+$/, "")}/api/show`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model }),
      dispatcher: MODEL_DISPATCHER,
      signal: AbortSignal.timeout(10_000),
    });
    if (res.ok) {
      const body = await res.json();
      let declared = null;
      for (const [key, value] of Object.entries(body?.model_info ?? {})) {
        if (key.endsWith(".context_length") && typeof value === "number" && value > 0) {
          declared = value;
          break;
        }
      }
      info = {
        digest: typeof body?.digest === "string" ? body.digest : await digestFromTags(model),
        declaredContextLength: declared,
      };
    }
  } catch {
    // Daemon down or old enough to lack /api/show: fall back to the configured
    // value rather than failing the call over metadata.
  }
  // Cache only a real answer. When the probe learned neither the window nor
  // the digest — daemon down, model not pulled yet, /api/show too old to carry
  // the field — `info` means "could not find out", not "the model declares
  // nothing". Caching that pins the fallback for the whole process lifetime,
  // so a model pulled (or a daemon restarted) a minute later would keep getting
  // the wrong budget and the wrong num_ctx clamp.
  if (info.digest !== null || info.declaredContextLength !== null) {
    modelInfoCache.set(model, info);
  }
  return info;
}

/**
 * What an eval baseline has to record about the model behind a score: which
 * weights answered (the digest, not just the tag — a re-pull can change the
 * weights under an unchanged tag) and the window the prompt was truncated to.
 *
 * null digest means the daemon could not report one; recording it as null is
 * honest, and the eval prints it as unknown rather than inventing a value.
 */
export async function modelProvenance(model = DEFAULT_OLLAMA_MODEL) {
  const { digest, declaredContextLength } = await showModel(model);
  return {
    digest,
    num_ctx: declaredContextLength
      ? Math.min(DEFAULT_NUM_CTX, declaredContextLength)
      : DEFAULT_NUM_CTX,
  };
}

/**
 * The context window actually usable for `model`: the configured
 * WISEREPO_NUM_CTX, clamped to what the model declares it can hold. Setting
 * 262144 for a 32K model would otherwise be accepted by validation and then
 * silently truncated by the server.
 */
export async function effectiveNumCtx(model = DEFAULT_OLLAMA_MODEL) {
  return (await modelProvenance(model)).num_ctx;
}

/**
 * @param {{ system?: string, prompt: string, maxTokens?: number, temperature?: number,
 *           timeoutMs?: number, model?: string, onProgress?: (chars: number) => void,
 *           onStats?: (stats: {promptTokens: number|null, completionTokens: number|null,
 *                               doneReason: string|null}) => void }} args
 * @returns {Promise<string>}
 */
export async function callModel({
  system = "",
  prompt,
  maxTokens,
  temperature,
  timeoutMs,
  model = DEFAULT_OLLAMA_MODEL,
  onProgress = defaultProgressReporter(),
  onStats,
}) {
  const url = `${ollamaBaseUrl().replace(/\/+$/, "")}/api/chat`;
  const options = {
    temperature: temperature ?? DEFAULT_TEMPERATURE,
    num_ctx: await effectiveNumCtx(model),
  };
  // Ollama's cap is num_predict, not max_tokens. Only set it when a caller
  // actually asked for one -- omitting it lets the model run to its natural
  // stop, whereas passing undefined through would serialize as null and be
  // rejected.
  if (maxTokens !== undefined) options.num_predict = maxTokens;

  return withTimeout(
    url,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model,
        think: DEFAULT_THINK,
        keep_alive: DEFAULT_KEEP_ALIVE,
        // stream: true is what makes progress reporting possible at all; the
        // response is NDJSON and readCompletion reassembles it.
        stream: true,
        options,
        messages: [
          { role: "system", content: system },
          { role: "user", content: prompt },
        ],
      }),
    },
    timeoutMs ?? DEFAULT_TIMEOUT_MS,
    async (res) => {
      if (!res.ok) {
        throw classifyHttpFailure(res.status, await res.text(), { model });
      }
      return readCompletion(res, "Ollama", onProgress, onStats);
    },
  );
}

export {
  classifyHttpFailure,
  numericEnv,
  boolEnv,
  DEFAULT_OLLAMA_MODEL,
  ollamaBaseUrl,
  DEFAULT_NUM_CTX,
  DEFAULT_THINK,
  DEFAULT_KEEP_ALIVE,
  MAX_TIMEOUT_MS,
};
