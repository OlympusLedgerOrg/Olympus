// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ModelUnavailableError,
  ModelRequestError,
  classifyHttpFailure,
  numericEnv,
  callModel,
  DEFAULT_OLLAMA_MODEL,
  DEFAULT_OLLAMA_URL,
} from "../src/backend.mjs";

// Stubs global.fetch for one call, captures what was sent, and always
// restores the real fetch. `respond` returns the { ok, status, text } shape
// callModel consumes, or throws to simulate a dead daemon.
async function withStubbedFetch(respond, fn) {
  const realFetch = global.fetch;
  const calls = [];
  global.fetch = async (url, options) => {
    calls.push({ url, options });
    return respond();
  };
  try {
    return { result: await fn(), calls };
  } finally {
    global.fetch = realFetch;
  }
}

function okResponse(bodyObj) {
  return () => ({ ok: true, status: 200, text: async () => JSON.stringify(bodyObj) });
}

// The exit-code contract in bin/sync-agent-docs.mjs rests entirely on this
// classification: "unavailable" must never block a commit, "request error"
// always must. Getting it backwards either hides a broken config behind a
// green build, or blocks commits on a transient local blip.

test("server errors classify as unavailable (non-blocking)", () => {
  for (const status of [500, 502, 503]) {
    assert.ok(classifyHttpFailure(status, "boom") instanceof ModelUnavailableError, `${status}`);
  }
});

test("request-timeout (408) classifies as unavailable (non-blocking)", () => {
  assert.ok(classifyHttpFailure(408, "timed out") instanceof ModelUnavailableError);
});

// A 404 from Ollama means the model tag isn't pulled. Retrying never fixes
// that, so it must block AND say what to actually run -- a bare "API error
// 404" would send someone hunting a network problem that doesn't exist.
test("404 classifies as blocking and names the pull command", () => {
  const err = classifyHttpFailure(404, 'model "x" not found');
  assert.ok(err instanceof ModelRequestError);
  assert.match(err.message, /ollama pull/);
  assert.ok(
    err.message.includes(DEFAULT_OLLAMA_MODEL),
    `expected the configured model name in: ${err.message}`,
  );
});

test("client request errors classify as blocking bugs", () => {
  for (const status of [400, 422]) {
    assert.ok(classifyHttpFailure(status, "bad request") instanceof ModelRequestError, `${status}`);
  }
});

test("classified errors carry the status and body for debugging", () => {
  const err = classifyHttpFailure(400, "invalid options.num_predict");
  assert.match(err.message, /Ollama API error 400/);
  assert.match(err.message, /num_predict/);
});

// numericEnv guards WISEREPO_TIMEOUT_MS / WISEREPO_TEMPERATURE. Before this,
// Number("45s") silently produced NaN with no throw; setTimeout(fn, NaN)
// coerces to 1ms, so the very next model call would abort almost instantly,
// get classified as ModelUnavailableError, and the pre-commit hook would
// report "backend unavailable, skipping AGENTS.md sync" forever — a typo'd
// env var indistinguishable from an actual daemon-down condition, with no
// diagnostic pointing at the real cause. numericEnv must reject that at
// load time instead, loudly, as a blocking ModelRequestError.
test("numericEnv returns the fallback when unset or empty", () => {
  assert.equal(numericEnv("WISEREPO_TEST_UNSET_VAR", 42, { min: 0, max: 100 }), 42);
});

test("numericEnv accepts a valid value in range", () => {
  process.env.WISEREPO_TEST_VAR = "50";
  try {
    assert.equal(numericEnv("WISEREPO_TEST_VAR", 42, { min: 0, max: 100 }), 50);
  } finally {
    delete process.env.WISEREPO_TEST_VAR;
  }
});

test("numericEnv rejects a non-numeric value loudly instead of silently becoming NaN", () => {
  process.env.WISEREPO_TEST_VAR = "45s";
  try {
    assert.throws(
      () => numericEnv("WISEREPO_TEST_VAR", 42, { min: 0, max: 100 }),
      (err) => err instanceof ModelRequestError && /45s.*not a finite number/.test(err.message),
    );
  } finally {
    delete process.env.WISEREPO_TEST_VAR;
  }
});

test("numericEnv rejects an out-of-range value", () => {
  process.env.WISEREPO_TEST_VAR = "-5";
  try {
    assert.throws(
      () => numericEnv("WISEREPO_TEST_VAR", 42, { min: 0, max: 100 }),
      ModelRequestError,
    );
  } finally {
    delete process.env.WISEREPO_TEST_VAR;
  }
});

// ── callModel wire contract ────────────────────────────────────────────────
//
// These stub global.fetch rather than talk to a real daemon, so they run in
// CI with no Ollama installed. That is a genuine limit: they prove wiserepo
// sends what Ollama's /api/chat documents and parses the response shape it
// documents, NOT that a live daemon accepts it. A first real run against
// qwen3-coder:30b is still the thing that closes that gap. What they do
// close is the silent-drift case -- an edit that swaps num_predict back to
// max_tokens, or reads data.choices[0] instead of data.message.content,
// now fails here instead of at the first use on the GPU box.

test("callModel POSTs the documented Ollama /api/chat request shape", async () => {
  const { result, calls } = await withStubbedFetch(
    okResponse({ message: { content: "hello" } }),
    () => callModel({ system: "SYS", prompt: "PROMPT" }),
  );

  assert.equal(result, "hello");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${DEFAULT_OLLAMA_URL}/api/chat`);
  assert.equal(calls[0].options.method, "POST");
  assert.equal(calls[0].options.headers["content-type"], "application/json");

  const sent = JSON.parse(calls[0].options.body);
  assert.equal(sent.model, DEFAULT_OLLAMA_MODEL);
  // stream:false is load-bearing -- a streaming response body is NDJSON, and
  // parseJsonBody would reject the whole thing as non-JSON.
  assert.equal(sent.stream, false);
  assert.deepEqual(sent.messages, [
    { role: "system", content: "SYS" },
    { role: "user", content: "PROMPT" },
  ]);
  assert.equal(sent.options.temperature, 0);
});

// Ollama's cap is options.num_predict, NOT max_tokens (that's the OpenAI
// spelling this backend used to carry). Sending the wrong key doesn't error
// -- Ollama ignores unknown options -- so an unbounded generation would just
// silently run long. Assert both directions.
test("callModel omits num_predict unless maxTokens was requested", async () => {
  const { calls } = await withStubbedFetch(okResponse({ message: { content: "x" } }), () =>
    callModel({ prompt: "p" }),
  );
  const sent = JSON.parse(calls[0].options.body);
  assert.ok(!("num_predict" in sent.options), `unexpected num_predict: ${calls[0].options.body}`);
  assert.ok(!("max_tokens" in sent), "max_tokens is the OpenAI spelling; Ollama ignores it");
});

test("callModel maps maxTokens onto options.num_predict", async () => {
  const { calls } = await withStubbedFetch(okResponse({ message: { content: "x" } }), () =>
    callModel({ prompt: "p", maxTokens: 8192 }),
  );
  assert.equal(JSON.parse(calls[0].options.body).options.num_predict, 8192);
});

test("callModel forwards an explicit temperature", async () => {
  const { calls } = await withStubbedFetch(okResponse({ message: { content: "x" } }), () =>
    callModel({ prompt: "p", temperature: 0.7 }),
  );
  assert.equal(JSON.parse(calls[0].options.body).options.temperature, 0.7);
});

// A 200 carrying no usable text must not be handed back as a "successful"
// empty generation -- sync-agent-docs.mjs would write an empty AGENTS.md.
test("callModel rejects a 200 with an empty or whitespace-only completion", async () => {
  for (const body of [{ message: { content: "" } }, { message: { content: "   \n" } }, {}]) {
    await assert.rejects(
      () => withStubbedFetch(okResponse(body), () => callModel({ prompt: "p" })),
      ModelUnavailableError,
      `body ${JSON.stringify(body)} should be rejected`,
    );
  }
});

test("callModel treats a non-JSON 200 body as unavailable, not as content", async () => {
  await assert.rejects(
    () =>
      withStubbedFetch(
        () => ({ ok: true, status: 200, text: async () => "<html>proxy error</html>" }),
        () => callModel({ prompt: "p" }),
      ),
    ModelUnavailableError,
  );
});

test("callModel surfaces an unpulled model (404) as blocking, with the pull command", async () => {
  await assert.rejects(
    () =>
      withStubbedFetch(
        () => ({ ok: false, status: 404, text: async () => 'model "x" not found' }),
        () => callModel({ prompt: "p" }),
      ),
    (err) => err instanceof ModelRequestError && /ollama pull/.test(err.message),
  );
});

test("callModel treats a dead daemon (fetch throws) as unavailable, not as a bug", async () => {
  await assert.rejects(
    () =>
      withStubbedFetch(
        () => {
          throw new Error("connect ECONNREFUSED 127.0.0.1:11434");
        },
        () => callModel({ prompt: "p" }),
      ),
    (err) => err instanceof ModelUnavailableError && /Ollama daemon running/.test(err.message),
  );
});

// REGRESSION (CodeRabbit #1641): WISEREPO_OLLAMA_URL is operator-supplied and
// may carry userinfo or a token query for a proxied/remote daemon. The whole
// URL used to be interpolated into ModelUnavailableError, and
// sync-agent-docs.mjs prints err.message straight to stdout -- so a
// credentialed endpoint leaked into CI logs and pre-commit output. Constants
// are read at module load, so this re-imports with a cache-busting query to
// get a module instance bound to the credentialed URL.
test("callModel strips credentials from the endpoint before putting it in an error", async () => {
  const original = process.env.WISEREPO_OLLAMA_URL;
  process.env.WISEREPO_OLLAMA_URL = "http://user:sup3rs3cret@ollama.internal:11434/?token=abc123";
  try {
    const mod = await import(`../src/backend.mjs?credleak=${Date.now()}`);
    await assert.rejects(
      () =>
        withStubbedFetch(
          () => {
            throw new Error("connect ECONNREFUSED");
          },
          () => mod.callModel({ prompt: "p" }),
        ),
      (err) => {
        assert.ok(!err.message.includes("sup3rs3cret"), `password leaked: ${err.message}`);
        assert.ok(!err.message.includes("abc123"), `token leaked: ${err.message}`);
        assert.ok(!err.message.includes("user:"), `userinfo leaked: ${err.message}`);
        // Still useful for debugging: the host must survive.
        assert.match(err.message, /ollama\.internal/);
        return true;
      },
    );
  } finally {
    if (original !== undefined) process.env.WISEREPO_OLLAMA_URL = original;
    else delete process.env.WISEREPO_OLLAMA_URL;
  }
});

test("callModel tolerates trailing slashes on WISEREPO_OLLAMA_URL", async () => {
  const original = process.env.WISEREPO_OLLAMA_URL;
  process.env.WISEREPO_OLLAMA_URL = "http://localhost:11434///";
  try {
    const mod = await import(`../src/backend.mjs?slash=${Date.now()}`);
    const { calls } = await withStubbedFetch(okResponse({ message: { content: "x" } }), () =>
      mod.callModel({ prompt: "p" }),
    );
    assert.equal(calls[0].url, "http://localhost:11434/api/chat");
  } finally {
    if (original !== undefined) process.env.WISEREPO_OLLAMA_URL = original;
    else delete process.env.WISEREPO_OLLAMA_URL;
  }
});
