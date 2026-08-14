// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Minimal model backend for wiserepo: talks to Claude or Codex (OpenAI)
// directly over fetch, no vendor SDK required. Keys come from the
// environment only — never hardcode, never log, never write to disk.

const ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";
const OPENAI_URL = "https://api.openai.com/v1/chat/completions";
// No trailing path baked in here (unlike the two above) because the ollama
// backend appends /api/chat itself — this constant is just the daemon's
// origin, overridable for a non-default port or a remote/tunneled instance.
const DEFAULT_OLLAMA_URL = process.env.WISEREPO_OLLAMA_URL || "http://localhost:11434";

const DEFAULT_CLAUDE_MODEL = process.env.WISEREPO_CLAUDE_MODEL || "claude-sonnet-5";
const DEFAULT_OPENAI_MODEL = process.env.WISEREPO_OPENAI_MODEL || "gpt-5-codex";
// qwen3-coder:30b: strongest coding-tier model that fits a 24GB card (e.g.
// RTX 3090) at Q4 with room to spare. See WISEREPO_OLLAMA_MODEL to override.
const DEFAULT_OLLAMA_MODEL = process.env.WISEREPO_OLLAMA_MODEL || "qwen3-coder:30b";

/**
 * The backend could not be reached or could not produce usable output:
 * missing key, network failure, timeout, rate limit, auth rejection, or a
 * 200 whose body has no usable text. Callers treat this as "the check did
 * not run", NOT "the check failed" — it must never block a commit.
 */
export class ModelUnavailableError extends Error {
  constructor(message, { cause } = {}) {
    super(message);
    this.name = "ModelUnavailableError";
    this.cause = cause;
  }
}

/**
 * The request itself was wrong — bad model name, malformed body, a 400 that
 * will recur on every retry, or a misconfigured environment variable. This
 * is a bug in wiserepo or its config, and is surfaced as a real failure
 * rather than silently skipped: a gate that fails OPEN on a typo is worse
 * than no gate, because it reports "skipping" instead of "misconfigured".
 */
export class ModelRequestError extends Error {
  constructor(message, { cause } = {}) {
    super(message);
    this.name = "ModelRequestError";
    this.cause = cause;
  }
}

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

// Low temperature reduces wording churn between runs on unchanged input. It
// does NOT make output byte-reproducible — sampling variance survives, and a
// floating model alias can change underneath you. Nothing in this tool may
// assume byte-identical regeneration; see sync-agent-docs.mjs, which compares
// structure rather than bytes for exactly this reason.
const DEFAULT_TEMPERATURE = numericEnv("WISEREPO_TEMPERATURE", 0, { min: 0, max: 2 });
const DEFAULT_TIMEOUT_MS = numericEnv("WISEREPO_TIMEOUT_MS", 45_000, { min: 1_000, max: 600_000 });

// Model families that reject `max_tokens` (requiring `max_completion_tokens`)
// and reject any `temperature` other than the default.
function isRestrictedOpenAiModel(model) {
  return /^(o\d|gpt-5)/.test(model);
}

const KNOWN_BACKENDS = ["claude", "openai", "ollama"];

function resolveBackend(explicit) {
  const backend = (explicit || process.env.WISEREPO_BACKEND || "claude").toLowerCase();
  if (!KNOWN_BACKENDS.includes(backend)) {
    throw new ModelRequestError(
      `Unknown wiserepo backend "${backend}" — expected one of: ${KNOWN_BACKENDS.join(", ")}`,
    );
  }
  return backend;
}

// A provider error body can echo back a submitted credential (some auth
// failure responses include the offending header value). Strip every
// caller-supplied secret out of the body before it becomes part of an error
// message that gets logged, printed by the pre-commit hook, or surfaced in
// CI output.
function redactSecrets(text, secrets) {
  let redacted = text;
  for (const secret of secrets) {
    if (secret) redacted = redacted.split(secret).join("[REDACTED]");
  }
  return redacted;
}

// Map an HTTP failure onto the right error class. Auth/rate-limit/server
// errors, plus billing (402) and request-timeout (408), are transient-or-
// environmental => unavailable (non-blocking): a 402 from an exhausted
// OpenAI quota, or a 408, would otherwise block every developer with that
// key exported until someone edits this file. A 400/404/422 means we built
// a bad request => request error (blocking), because retrying never fixes
// it and silence would hide the bug.
function classifyHttpFailure(status, rawBody, provider, secrets = []) {
  const body = redactSecrets(rawBody, secrets);
  const msg = `${provider} API error ${status}: ${body}`;
  if (status === 401 || status === 403) {
    return new ModelUnavailableError(`${msg} (check your API key)`);
  }
  if (status === 402 || status === 408 || status === 429 || status >= 500) {
    return new ModelUnavailableError(msg);
  }
  return new ModelRequestError(msg);
}

// Reads the body INSIDE the timed section and returns it alongside the
// response. `fetch()` resolves as soon as headers arrive — the body is
// still streaming — so a version of this that only timed `fetch()` and let
// callers read `res.text()`/`res.json()` afterward left the body read
// completely unbounded: a provider that returns 200 with headers and then
// stalls mid-body would hang the process with no diagnostic, which for
// `sync-agent-docs.mjs` invoked from the pre-commit hook means hanging the
// developer's commit.
async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    const body = await res.text();
    return { res, body };
  } catch (err) {
    if (err.name === "AbortError") {
      throw new ModelUnavailableError(`request to ${url} timed out after ${timeoutMs}ms`, {
        cause: err,
      });
    }
    throw new ModelUnavailableError(`request to ${url} failed: ${err.message}`, { cause: err });
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

async function callClaude({ system, prompt, maxTokens, temperature, timeoutMs }) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new ModelUnavailableError(
      "ANTHROPIC_API_KEY is not set — export it before using the claude backend",
    );
  }
  const { res, body } = await fetchWithTimeout(
    ANTHROPIC_URL,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: DEFAULT_CLAUDE_MODEL,
        max_tokens: maxTokens ?? 4096,
        temperature,
        system,
        messages: [{ role: "user", content: prompt }],
      }),
    },
    timeoutMs,
  );
  if (!res.ok) {
    throw classifyHttpFailure(res.status, body, "Anthropic", [apiKey]);
  }
  const data = parseJsonBody(body, "Anthropic");
  const text = data.content?.map((block) => block.text ?? "").join("") ?? "";
  if (!text.trim()) {
    throw new ModelUnavailableError("Anthropic returned an empty or unparseable completion");
  }
  return text;
}

async function callOpenAI({ system, prompt, maxTokens, temperature, timeoutMs }) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    throw new ModelUnavailableError(
      "OPENAI_API_KEY is not set — export it before using the openai backend",
    );
  }
  const model = DEFAULT_OPENAI_MODEL;
  const body = {
    model,
    messages: [
      { role: "system", content: system },
      { role: "user", content: prompt },
    ],
  };
  // Reasoning / gpt-5-class models reject `max_tokens` and any non-default
  // `temperature`; older chat models reject `max_completion_tokens`.
  if (isRestrictedOpenAiModel(model)) {
    body.max_completion_tokens = maxTokens ?? 4096;
  } else {
    body.max_tokens = maxTokens ?? 4096;
    body.temperature = temperature;
  }

  const { res, body: responseBody } = await fetchWithTimeout(
    OPENAI_URL,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
    },
    timeoutMs,
  );
  if (!res.ok) {
    throw classifyHttpFailure(res.status, responseBody, "OpenAI", [apiKey]);
  }
  const data = parseJsonBody(responseBody, "OpenAI");
  const text = data.choices?.[0]?.message?.content ?? "";
  if (!text.trim()) {
    throw new ModelUnavailableError("OpenAI returned an empty or unparseable completion");
  }
  return text;
}

// Ollama needs no API key (it's a local daemon), so "unavailable" here means
// "the daemon isn't running" or "the model hasn't been pulled" rather than
// "no credential configured" — fetchWithTimeout's catch already covers
// connection-refused (daemon down) by wrapping any fetch() throw as
// ModelUnavailableError, so this function only needs to handle the HTTP
// layer (non-2xx) and the response shape.
async function callOllama({ system, prompt, temperature, timeoutMs }) {
  const url = `${DEFAULT_OLLAMA_URL.replace(/\/+$/, "")}/api/chat`;
  const { res, body } = await fetchWithTimeout(
    url,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: DEFAULT_OLLAMA_MODEL,
        stream: false,
        options: { temperature },
        messages: [
          { role: "system", content: system },
          { role: "user", content: prompt },
        ],
      }),
    },
    timeoutMs,
  );
  if (!res.ok) {
    // A 404 here almost always means "model not pulled yet" (e.g. `ollama
    // pull qwen3-coder:30b` was never run) — that's a config problem the
    // caller needs to fix, not a transient condition, so it stays in
    // classifyHttpFailure's blocking (ModelRequestError) branch same as any
    // other 4xx that isn't auth/quota/timeout.
    throw classifyHttpFailure(res.status, body, "Ollama");
  }
  const data = parseJsonBody(body, "Ollama");
  const text = data.message?.content ?? "";
  if (!text.trim()) {
    throw new ModelUnavailableError("Ollama returned an empty or unparseable completion");
  }
  return text;
}

/**
 * @param {{ system?: string, prompt: string, backend?: string, maxTokens?: number, temperature?: number, timeoutMs?: number }} args
 * @returns {Promise<string>}
 */
export async function callModel({
  system = "",
  prompt,
  backend,
  maxTokens,
  temperature,
  timeoutMs,
}) {
  const resolved = resolveBackend(backend);
  const resolvedTemperature = temperature ?? DEFAULT_TEMPERATURE;
  const resolvedTimeout = timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const args = {
    system,
    prompt,
    maxTokens,
    temperature: resolvedTemperature,
    timeoutMs: resolvedTimeout,
  };
  if (resolved === "claude") return callClaude(args);
  if (resolved === "openai") return callOpenAI(args);
  return callOllama(args);
}

export {
  resolveBackend,
  isRestrictedOpenAiModel,
  classifyHttpFailure,
  redactSecrets,
  numericEnv,
  KNOWN_BACKENDS,
};
