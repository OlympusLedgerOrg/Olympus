// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Minimal model backend for wiserepo: talks to Claude or Codex (OpenAI)
// directly over fetch, no vendor SDK required. Keys come from the
// environment only — never hardcode, never log, never write to disk.

const ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";
const OPENAI_URL = "https://api.openai.com/v1/chat/completions";

const DEFAULT_CLAUDE_MODEL = process.env.WISEREPO_CLAUDE_MODEL || "claude-sonnet-5";
const DEFAULT_OPENAI_MODEL = process.env.WISEREPO_OPENAI_MODEL || "gpt-5-codex";

// Low temperature reduces wording churn between runs on unchanged input. It
// does NOT make output byte-reproducible — sampling variance survives, and a
// floating model alias can change underneath you. Nothing in this tool may
// assume byte-identical regeneration; see sync-agent-docs.mjs, which compares
// structure rather than bytes for exactly this reason.
const DEFAULT_TEMPERATURE =
  process.env.WISEREPO_TEMPERATURE !== undefined ? Number(process.env.WISEREPO_TEMPERATURE) : 0;

const DEFAULT_TIMEOUT_MS = process.env.WISEREPO_TIMEOUT_MS
  ? Number(process.env.WISEREPO_TIMEOUT_MS)
  : 45_000;

// Model families that reject `max_tokens` (requiring `max_completion_tokens`)
// and reject any `temperature` other than the default.
function isRestrictedOpenAiModel(model) {
  return /^(o\d|gpt-5)/.test(model);
}

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
 * will recur on every retry. This is a bug in wiserepo or its config, and is
 * surfaced as a real failure rather than silently skipped.
 */
export class ModelRequestError extends Error {
  constructor(message, { cause } = {}) {
    super(message);
    this.name = "ModelRequestError";
    this.cause = cause;
  }
}

function resolveBackend(explicit) {
  const backend = (explicit || process.env.WISEREPO_BACKEND || "claude").toLowerCase();
  if (backend !== "claude" && backend !== "openai") {
    throw new ModelRequestError(
      `Unknown wiserepo backend "${backend}" — expected "claude" or "openai"`,
    );
  }
  return backend;
}

// Map an HTTP failure onto the right error class. Auth/rate-limit/server
// errors are transient-or-environmental => unavailable (non-blocking).
// A 400/404/422 means we built a bad request => request error (blocking),
// because retrying will never fix it and silence would hide the bug.
function classifyHttpFailure(status, body, provider) {
  const msg = `${provider} API error ${status}: ${body}`;
  if (status === 401 || status === 403) {
    return new ModelUnavailableError(`${msg} (check your API key)`);
  }
  if (status === 429 || status >= 500) {
    return new ModelUnavailableError(msg);
  }
  return new ModelRequestError(msg);
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
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

async function callClaude({ system, prompt, maxTokens, temperature, timeoutMs }) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new ModelUnavailableError(
      "ANTHROPIC_API_KEY is not set — export it before using the claude backend",
    );
  }
  const res = await fetchWithTimeout(
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
    throw classifyHttpFailure(res.status, await res.text(), "Anthropic");
  }
  const data = await res.json();
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

  const res = await fetchWithTimeout(
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
    throw classifyHttpFailure(res.status, await res.text(), "OpenAI");
  }
  const data = await res.json();
  const text = data.choices?.[0]?.message?.content ?? "";
  if (!text.trim()) {
    throw new ModelUnavailableError("OpenAI returned an empty or unparseable completion");
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
  return resolved === "claude" ? callClaude(args) : callOpenAI(args);
}

export { resolveBackend, isRestrictedOpenAiModel, classifyHttpFailure };
