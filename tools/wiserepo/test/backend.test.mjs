// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { Agent } from "undici";
import {
  ModelUnavailableError,
  ModelRequestError,
  classifyHttpFailure,
  numericEnv,
  boolEnv,
  callModel,
  effectiveNumCtx,
  modelProvenance,
  modelForTool,
  DEFAULT_OLLAMA_MODEL,
  ollamaBaseUrl,
  DEFAULT_NUM_CTX,
  DEFAULT_KEEP_ALIVE,
} from "../src/backend.mjs";

// Stubs global.fetch for one call, captures what was sent, and always
// restores the real fetch. `respond` gets ({ url, options }) and returns the
// { ok, status, text, body?, json? } shape the backend consumes, or throws to
// simulate a dead daemon.
async function withStubbedFetch(respond, fn) {
  const realFetch = global.fetch;
  const calls = [];
  global.fetch = async (url, options) => {
    const entry = { url, options };
    calls.push(entry);
    return respond(entry);
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

// Every callModel now first asks /api/show for the model's window, so the chat
// request is no longer calls[0]. Selection is by URL rather than index so the
// lookup can be reordered or cached without silently retargeting these tests.
function chatCalls(calls) {
  return calls.filter((call) => call.url.endsWith("/api/chat"));
}

function lastChatBody(calls) {
  const chat = chatCalls(calls).at(-1);
  assert.ok(chat, `no /api/chat call captured (got ${calls.map((c) => c.url).join(", ")})`);
  return JSON.parse(chat.options.body);
}

// ── error classification ───────────────────────────────────────────────────
// The classification drives what the CLI and MCP server tell a caller: an
// "unavailable" backend is worth retrying, a "request error" is our bug and
// must surface loudly. (It used to decide whether a commit was blocked; that
// gate is gone, but swapping the two still misreports the cause.)

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
test("404 classifies as blocking and names the model that was actually requested", () => {
  const err = classifyHttpFailure(404, 'model "x" not found', { model: "foo:1b" });
  assert.ok(err instanceof ModelRequestError);
  assert.match(err.message, /ollama pull foo:1b/);
});

test("404 falls back to the configured default model name", () => {
  const err = classifyHttpFailure(404, 'model "x" not found');
  assert.ok(err.message.includes(DEFAULT_OLLAMA_MODEL), err.message);
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

// The failure that cost the most time in practice: a 500 whose body named the
// real cause, surfaced to the user as a generic backend error. Each known body
// must now name the cause and the next action.
test("a missing llama-server runner is named, not reported as a generic 500", () => {
  const err = classifyHttpFailure(
    500,
    "error starting llama-server: llama-server binary not found (checked: C:\\...\\lib\\ollama\\llama-server.exe)",
  );
  assert.ok(
    err instanceof ModelUnavailableError,
    "a broken install is environmental, not a request bug",
  );
  assert.match(err.message, /missing its model runner/);
  assert.match(err.message, /llama-windows-amd64\.zip/);
});

test("an out-of-memory failure is named as a memory problem", () => {
  const err = classifyHttpFailure(500, "failed to allocate 8123 MiB: out of memory");
  assert.ok(err instanceof ModelUnavailableError);
  assert.match(err.message, /smaller tag or free memory/);
});

// ── numericEnv / boolEnv ───────────────────────────────────────────────────

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

// boolEnv guards WISEREPO_THINK, where a typo's failure mode is invisible:
// silently keeping the default leaves the operator certain they enabled (or
// disabled) reasoning when nothing changed — the same fail-open shape
// numericEnv exists to prevent.
test("boolEnv accepts the documented spellings and rejects the rest loudly", () => {
  assert.equal(boolEnv("WISEREPO_TEST_UNSET_BOOL", false), false);
  // One true and one false spelling: the point is that the parse happens at
  // all and is case-insensitive, not that every alias is enumerated.
  for (const [raw, expected] of [
    ["1", true],
    ["Off", false],
  ]) {
    process.env.WISEREPO_TEST_BOOL = raw;
    try {
      assert.equal(boolEnv("WISEREPO_TEST_BOOL", !expected), expected, `raw ${raw}`);
    } finally {
      delete process.env.WISEREPO_TEST_BOOL;
    }
  }

  process.env.WISEREPO_TEST_BOOL = "treu";
  try {
    assert.throws(
      () => boolEnv("WISEREPO_TEST_BOOL", false),
      (err) => err instanceof ModelRequestError && /treu.*not a boolean/.test(err.message),
    );
  } finally {
    delete process.env.WISEREPO_TEST_BOOL;
  }
});

// ── per-tool model routing ─────────────────────────────────────────────────

test("modelForTool falls back to the default model when no override is set", () => {
  assert.equal(modelForTool("summarize"), DEFAULT_OLLAMA_MODEL);
  assert.equal(modelForTool("review"), DEFAULT_OLLAMA_MODEL);
});

test("modelForTool honours a per-tool override", () => {
  process.env.WISEREPO_MODEL_SUMMARIZE = "qwen3.5:4b";
  try {
    assert.equal(modelForTool("summarize"), "qwen3.5:4b");
    assert.equal(
      modelForTool("review"),
      DEFAULT_OLLAMA_MODEL,
      "overrides must not leak across tools",
    );
  } finally {
    delete process.env.WISEREPO_MODEL_SUMMARIZE;
  }
});

// ── callModel wire contract ────────────────────────────────────────────────
//
// These stub global.fetch rather than talk to a real daemon, so they run in
// CI with no Ollama installed. That is a genuine limit: they prove wiserepo
// sends what Ollama's /api/chat documents and parses the response shape it
// documents, NOT that a live daemon accepts it. A run against a real daemon is
// what closes that gap; one has been done against qwen2.5-coder:7b-instruct on
// this machine, but CI has no daemon and never exercises that path. What these
// do close is the silent-drift case -- an edit that swaps num_predict back to
// max_tokens, or reads data.choices[0] instead of data.message.content, fails
// here instead of at first use.

test("callModel POSTs the documented Ollama /api/chat request shape", async () => {
  const { result, calls } = await withStubbedFetch(
    okResponse({ message: { content: "hello" } }),
    () => callModel({ system: "SYS", prompt: "PROMPT" }),
  );

  assert.equal(result, "hello");
  const chat = chatCalls(calls);
  assert.equal(chat.length, 1);
  assert.equal(chat[0].url, `${ollamaBaseUrl()}/api/chat`);
  assert.equal(chat[0].options.method, "POST");
  assert.equal(chat[0].options.headers["content-type"], "application/json");

  const sent = JSON.parse(chat[0].options.body);
  assert.equal(sent.model, DEFAULT_OLLAMA_MODEL);
  // stream:true is what makes progress reporting possible; the NDJSON
  // response is reassembled by readCompletion, which is why the older
  // stream:false contract (and its "NDJSON would break the parser" note) is
  // gone.
  assert.equal(sent.stream, true);
  assert.deepEqual(sent.messages, [
    { role: "system", content: "SYS" },
    { role: "user", content: "PROMPT" },
  ]);
  assert.equal(sent.options.temperature, 0);
});

test("callModel reports Ollama's token counts to onStats", async () => {
  const seen = [];
  const streaming = () => ({
    ok: true,
    status: 200,
    text: async () => "",
    body: (async function* () {
      yield Buffer.from(JSON.stringify({ message: { content: "he" }, done: false }) + "\n");
      yield Buffer.from(
        JSON.stringify({
          message: { content: "llo" },
          done: true,
          prompt_eval_count: 1234,
          eval_count: 56,
          done_reason: "stop",
        }) + "\n",
      );
    })(),
  });
  const { result } = await withStubbedFetch(
    (entry) =>
      entry.url.endsWith("/api/chat")
        ? streaming()
        : { ok: false, status: 500, text: async () => "" },
    () => callModel({ prompt: "p", onStats: (stats) => seen.push(stats) }),
  );

  assert.equal(result, "hello");
  assert.deepEqual(seen, [{ promptTokens: 1234, completionTokens: 56, doneReason: "stop" }]);
});

test("callModel keeps the model resident between calls", async () => {
  const { calls } = await withStubbedFetch(okResponse({ message: { content: "x" } }), () =>
    callModel({ prompt: "p" }),
  );
  const sent = lastChatBody(calls);
  // Without keep_alive the daemon unloads after 5 minutes and every call in a
  // working session pays ~17s to reload the 7B.
  assert.equal(sent.keep_alive, DEFAULT_KEEP_ALIVE);
  assert.equal(sent.think, false, "thinking must default to off");
});

// REGRESSION: Node's fetch (undici) applies its own 300s headersTimeout and
// bodyTimeout, independent of the AbortController. On the first real 7B-on-CPU
// call — a 40KB file is ~13k prompt tokens, and prompt processing ran past
// 300s — that fired first and surfaced as an opaque "fetch failed" even with
// WISEREPO_TIMEOUT_MS=600000 set. Without the dispatcher wired here, any
// non-trivial local qa/review call fails, so its removal must fail this test.
// (The Agent's configured timeouts are private to undici, so this asserts the
// dispatcher is wired at all; the values themselves sit just above the
// 30-minute MAX_TIMEOUT_MS in backend.mjs.)
test("callModel passes a dispatcher so undici's 300s cap cannot preempt its own timeout", async () => {
  const { calls } = await withStubbedFetch(okResponse({ message: { content: "x" } }), () =>
    callModel({ prompt: "p" }),
  );
  const chat = chatCalls(calls)[0];
  assert.ok(
    chat.options.dispatcher instanceof Agent,
    `expected an undici Agent, got ${chat.options.dispatcher}`,
  );
});

// Ollama truncates a prompt longer than the loaded window SILENTLY — no error,
// no warning — so a request sized for a window the model does not have comes
// back as a confident answer drawn from content the model never saw. Pinning
// num_ctx is what makes that impossible to do by accident, and it is why
// mcp-server.mjs can size its char budget from the same number.
test("callModel pins an explicit num_ctx rather than inheriting the daemon default", async () => {
  const { calls } = await withStubbedFetch(okResponse({ message: { content: "x" } }), () =>
    callModel({ prompt: "p" }),
  );
  assert.equal(lastChatBody(calls).options.num_ctx, DEFAULT_NUM_CTX);
});

// Configuring 262144 against a 32K model would pass validation and then be
// truncated by the server. The declared window is the ceiling.
test("effectiveNumCtx clamps the configured window to what the model declares", async () => {
  const { result } = await withStubbedFetch(
    (entry) => {
      if (entry.url.endsWith("/api/show")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ model_info: { "qwen2.context_length": 4_096 } }),
        };
      }
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ message: { content: "x" } }),
      };
    },
    () => effectiveNumCtx("clamp-test:tiny"),
  );
  assert.equal(result, 4_096);
});

// A daemon that is down (or an older one without /api/show) must not turn a
// metadata lookup into a failed call.
test("effectiveNumCtx falls back to the configured window when the daemon cannot report one", async () => {
  const { result } = await withStubbedFetch(
    () => {
      throw new Error("connect ECONNREFUSED");
    },
    () => effectiveNumCtx("clamp-test:offline"),
  );
  assert.equal(result, DEFAULT_NUM_CTX);
});

// /api/show has the window but this daemon omits the digest; /api/tags lists it.
// The digest is the only thing that tells a re-pull from the same tag, so a
// baseline that loses it silently cannot prove which weights produced a score.
test("modelProvenance takes the digest from /api/tags when /api/show omits it", async () => {
  const { result } = await withStubbedFetch(
    (entry) => {
      if (entry.url.endsWith("/api/show")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ model_info: { "qwen2.context_length": 32_768 } }),
        };
      }
      if (entry.url.endsWith("/api/tags")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            models: [{ name: "digest-test:1b", model: "digest-test:1b", digest: "sha256:abc123" }],
          }),
        };
      }
      throw new Error(`unexpected request ${entry.url}`);
    },
    () => modelProvenance("digest-test:1b"),
  );
  // The declared 32K is the ceiling, not the value: the configured window wins
  // when it is smaller, which is what the truncation budget is sized from.
  assert.deepEqual(result, { digest: "sha256:abc123", num_ctx: DEFAULT_NUM_CTX });
});

// Unknown must stay unknown: inventing a digest would make every baseline look
// like it was recorded against the same weights.
test("modelProvenance reports an unknown digest as null rather than guessing", async () => {
  const { result } = await withStubbedFetch(
    () => ({ ok: true, status: 200, json: async () => ({ model_info: {} }) }),
    () => modelProvenance("digest-test:missing"),
  );
  assert.equal(result.digest, null);
  assert.equal(result.num_ctx, DEFAULT_NUM_CTX);
});

// Ollama's cap is options.num_predict, NOT max_tokens (that's the OpenAI
// spelling this backend used to carry). Sending the wrong key doesn't error
// -- Ollama ignores unknown options -- so an unbounded generation would just
// silently run long. Assert both directions.
test("callModel omits num_predict unless maxTokens was requested", async () => {
  const { calls } = await withStubbedFetch(okResponse({ message: { content: "x" } }), () =>
    callModel({ prompt: "p" }),
  );
  const sent = lastChatBody(calls);
  assert.ok(
    !("num_predict" in sent.options),
    `unexpected num_predict: ${JSON.stringify(sent.options)}`,
  );
  assert.ok(!("max_tokens" in sent), "max_tokens is the OpenAI spelling; Ollama ignores it");
});

test("callModel maps maxTokens onto options.num_predict", async () => {
  const { calls } = await withStubbedFetch(okResponse({ message: { content: "x" } }), () =>
    callModel({ prompt: "p", maxTokens: 8192 }),
  );
  assert.equal(lastChatBody(calls).options.num_predict, 8192);
});

test("callModel forwards an explicit temperature", async () => {
  const { calls } = await withStubbedFetch(okResponse({ message: { content: "x" } }), () =>
    callModel({ prompt: "p", temperature: 0.7 }),
  );
  assert.equal(lastChatBody(calls).options.temperature, 0.7);
});

// ── streaming ──────────────────────────────────────────────────────────────

function ndjsonResponse(lines, { status = 200 } = {}) {
  return () => ({
    ok: status < 400,
    status,
    body: new ReadableStream({
      start(controller) {
        for (const line of lines) controller.enqueue(new TextEncoder().encode(line));
        controller.close();
      },
    }),
    text: async () => lines.join(""),
  });
}

test("callModel reassembles an NDJSON stream into the answer", async () => {
  const { result } = await withStubbedFetch(
    ndjsonResponse([
      '{"message":{"content":"Hel"},"done":false}\n',
      '{"message":{"content":"lo, "},"done":false}\n',
      '{"message":{"content":"world"},"done":true}\n',
    ]),
    () => callModel({ prompt: "p" }),
  );
  assert.equal(result, "Hello, world");
});

// Reasoning tokens are not the answer; only message.content is accumulated.
test("callModel ignores thinking fragments in the stream", async () => {
  const { result } = await withStubbedFetch(
    ndjsonResponse([
      '{"message":{"thinking":"hmm"},"done":false}\n',
      '{"message":{"content":"OK"},"done":true}\n',
    ]),
    () => callModel({ prompt: "p" }),
  );
  assert.equal(result, "OK");
});

test("callModel reports progress as the answer streams in", async () => {
  const seen = [];
  const long = "x".repeat(300);
  await withStubbedFetch(
    ndjsonResponse([
      `{"message":{"content":"${long}"},"done":false}\n`,
      '{"message":{"content":"end"},"done":true}\n',
    ]),
    () => callModel({ prompt: "p", onProgress: (chars) => seen.push(chars) }),
  );
  assert.ok(seen.length > 0, "progress callback must fire during generation");
  assert.equal(seen.at(-1), 303);
});

// A 200 carrying no usable text must not be handed back as a "successful"
// empty generation -- an empty answer must be an error, never a success.
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
// URL used to be interpolated into ModelUnavailableError, and the CLI and MCP
// surfaces print err.message straight through -- so a credentialed endpoint
// leaked into logs. Constants
// are read at module load, so this re-imports with a cache-busting query to
// get a module instance bound to the credentialed URL.
// Asserted by name and by NOT being a ReferenceError, not by instanceof: each
// cache-busted import above evaluates backend.mjs into a fresh module instance
// with its own ModelRequestError binding, so the class identity the test file
// imported statically can never match it. A ReferenceError here would mean the
// class is declared after the URL check again (temporal dead zone), which is
// exactly the bug that made this guard report the wrong error.
function assertRequestError(err) {
  assert.ok(!(err instanceof ReferenceError), `TDZ ReferenceError: ${err.message}`);
  assert.equal(
    err.name,
    "ModelRequestError",
    `expected ModelRequestError, got ${err.name}: ${err.message}`,
  );
  return true;
}

// The URL is read per call now, so the variable has to stay set for the whole
// callback — restoring it before the module is used would silently fall back to
// the default endpoint and make every rejection test pass for the wrong reason.
async function withBackendBoundTo(raw, fn) {
  const original = process.env.WISEREPO_OLLAMA_URL;
  process.env.WISEREPO_OLLAMA_URL = raw;
  try {
    // The query string is what defeats the module cache; encodeURIComponent
    // keeps a raw URL with `?`/`#` out of the specifier's query syntax.
    const mod = await import(
      `../src/backend.mjs?urlcheck=${encodeURIComponent(raw)}&n=${Math.random()}`
    );
    return await fn(mod);
  } finally {
    if (original === undefined) delete process.env.WISEREPO_OLLAMA_URL;
    else process.env.WISEREPO_OLLAMA_URL = original;
  }
}

// URL validation runs when the endpoint is USED, not when the module loads, so
// main()'s catch and the MCP tool handler can classify it as a request error
// instead of dumping a stack trace from module evaluation. The guard is still
// fail-closed: nothing may be sent, which is the zero-call assertion here.
async function rejectionFromCall(raw) {
  return withBackendBoundTo(raw, async (mod) => {
    let caught;
    const { calls } = await withStubbedFetch(
      () => {
        throw new Error("fetch must not be reached for a rejected endpoint");
      },
      async () => {
        caught = await mod.callModel({ prompt: "p" }).then(
          () => {
            throw new Error("expected callModel to reject");
          },
          (err) => err,
        );
      },
    );
    assert.equal(
      calls.length,
      0,
      `a rejected endpoint must not send anything, got ${calls.length} call(s)`,
    );
    return caught;
  });
}

test("callModel rejects credentialed remote endpoints before sending repo content", async () => {
  const err = await rejectionFromCall(
    "http://user:sup3rs3cret@ollama.internal:11434/?token=abc123",
  );
  assertRequestError(err);
  assert.match(err.message, /credential-free http URL/);
  assert.ok(!err.message.includes("sup3rs3cret"), `password leaked: ${err.message}`);
  assert.ok(!err.message.includes("abc123"), `token leaked: ${err.message}`);
});

// The trust boundary this closes is the whole point of the local backend: repo
// content must never be posted to a daemon off this machine.
test("callModel refuses a non-loopback WISEREPO_OLLAMA_URL", async () => {
  const err = await rejectionFromCall("http://192.168.1.10:11434");
  assertRequestError(err);
  assert.match(err.message, /credential-free http URL/);
});

// Loopback over https is still a loopback host, but the check is explicit about
// the scheme, so a self-signed TLS endpoint must fail loudly rather than
// surface later as an opaque fetch error.
test("callModel refuses https even on loopback", async () => {
  const err = await rejectionFromCall("https://localhost:11434");
  assertRequestError(err);
  assert.match(err.message, /credential-free http URL/);
});

test("callModel reports an unparseable WISEREPO_OLLAMA_URL as a request error", async () => {
  const err = await rejectionFromCall("not a url at all");
  assertRequestError(err);
  assert.match(err.message, /is not a valid URL/);
});

// Importing with a bad URL must now SUCCEED — that is the whole point of
// deferring validation, and it is what lets the CLI reach its own handler.
test("a bad WISEREPO_OLLAMA_URL no longer breaks importing the module", async () => {
  await withBackendBoundTo("http://192.168.1.10:11434", (mod) => {
    assert.equal(typeof mod.callModel, "function");
  });
});

// Positive control: the guards above must not reject the documented default.
test("callModel accepts a credential-free loopback endpoint", async () => {
  await withBackendBoundTo("http://127.0.0.1:11434", (mod) => {
    assert.equal(mod.ollamaBaseUrl(), "http://127.0.0.1:11434");
  });
});

test("callModel tolerates trailing slashes on WISEREPO_OLLAMA_URL", async () => {
  const original = process.env.WISEREPO_OLLAMA_URL;
  process.env.WISEREPO_OLLAMA_URL = "http://localhost:11434///";
  try {
    const mod = await import(`../src/backend.mjs?slash=${Date.now()}`);
    const { calls } = await withStubbedFetch(okResponse({ message: { content: "x" } }), () =>
      mod.callModel({ prompt: "p" }),
    );
    assert.equal(chatCalls(calls)[0].url, "http://localhost:11434/api/chat");
  } finally {
    if (original !== undefined) process.env.WISEREPO_OLLAMA_URL = original;
    else delete process.env.WISEREPO_OLLAMA_URL;
  }
});
