// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Minimal model backend for wiserepo: talks to a local Ollama daemon over
// fetch, no vendor SDK required. There is deliberately no cloud backend --
// see README's trust-boundary section. Repo contents (file bodies, diffs,
// grep hits) are handed to this module verbatim, and keeping the only
// possible destination a process on localhost is what makes that safe by
// construction rather than by policy.

const DEFAULT_OLLAMA_URL = process.env.WISEREPO_OLLAMA_URL || "http://localhost:11434";
// qwen3-coder:30b: strongest coding-tier model that fits a 24GB card (e.g.
// RTX 3090) at Q4. Override with WISEREPO_OLLAMA_MODEL -- e.g.
// qwen2.5-coder:7b on an 8GB card, or qwen2.5-coder:14b for more speed.
const DEFAULT_OLLAMA_MODEL = process.env.WISEREPO_OLLAMA_MODEL || "qwen3-coder:30b";

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
// model tag can be re-pulled underneath you. Nothing in this tool may assume
// byte-identical regeneration; see sync-agent-docs.mjs, which compares
// structure rather than bytes for exactly this reason.
const DEFAULT_TEMPERATURE = numericEnv("WISEREPO_TEMPERATURE", 0, { min: 0, max: 2 });
// Local generation on a 30B model is a lot slower per token than a hosted
// frontier API, and review_diff/sync-agent-docs can emit thousands of
// tokens, so this default is much larger than a cloud-backed tool would
// need. Raise it further (or drop to a smaller model) if a big regeneration
// still times out.
const DEFAULT_TIMEOUT_MS = numericEnv("WISEREPO_TIMEOUT_MS", 300_000, {
  min: 1_000,
  max: 1_800_000,
});

// Map an HTTP failure onto the right error class. Server errors and
// request-timeout (408) are transient => unavailable (non-blocking). A 404
// (model not pulled) or 400 (bad request body) means retrying never fixes
// it => request error (blocking), because silence would hide the bug.
//
// Ollama needs no credential, so unlike a cloud backend there is no 401/403
// path and nothing secret to redact from an error body.
function classifyHttpFailure(status, body, provider = "Ollama") {
  const msg = `${provider} API error ${status}: ${body}`;
  if (status === 404) {
    return new ModelRequestError(
      `${msg} (model "${DEFAULT_OLLAMA_MODEL}" not pulled? try: ollama pull ${DEFAULT_OLLAMA_MODEL})`,
    );
  }
  if (status === 408 || status >= 500) {
    return new ModelUnavailableError(msg);
  }
  return new ModelRequestError(msg);
}

// Reads the body INSIDE the timed section and returns it alongside the
// response. `fetch()` resolves as soon as headers arrive — the body is
// still streaming — so a version of this that only timed `fetch()` and let
// callers read `res.text()`/`res.json()` afterward left the body read
// completely unbounded: a daemon that returns 200 with headers and then
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
    // Connection-refused lands here, which is the overwhelmingly common
    // case: the Ollama daemon isn't running. That's environmental, not a
    // bug in the request, so it stays non-blocking.
    throw new ModelUnavailableError(
      `request to ${url} failed: ${err.message} (is the Ollama daemon running?)`,
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

/**
 * @param {{ system?: string, prompt: string, maxTokens?: number, temperature?: number, timeoutMs?: number }} args
 * @returns {Promise<string>}
 */
export async function callModel({ system = "", prompt, maxTokens, temperature, timeoutMs }) {
  const url = `${DEFAULT_OLLAMA_URL.replace(/\/+$/, "")}/api/chat`;
  const options = { temperature: temperature ?? DEFAULT_TEMPERATURE };
  // Ollama's cap is num_predict, not max_tokens. Only set it when a caller
  // actually asked for one -- omitting it lets the model run to its natural
  // stop, whereas passing undefined through would serialize as null and be
  // rejected.
  if (maxTokens !== undefined) options.num_predict = maxTokens;

  const { res, body } = await fetchWithTimeout(
    url,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: DEFAULT_OLLAMA_MODEL,
        stream: false,
        options,
        messages: [
          { role: "system", content: system },
          { role: "user", content: prompt },
        ],
      }),
    },
    timeoutMs ?? DEFAULT_TIMEOUT_MS,
  );
  if (!res.ok) {
    throw classifyHttpFailure(res.status, body);
  }
  const data = parseJsonBody(body, "Ollama");
  const text = data.message?.content ?? "";
  if (!text.trim()) {
    throw new ModelUnavailableError("Ollama returned an empty or unparseable completion");
  }
  return text;
}

export { classifyHttpFailure, numericEnv, DEFAULT_OLLAMA_MODEL, DEFAULT_OLLAMA_URL };
