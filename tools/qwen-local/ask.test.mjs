// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { PolicyError } from "../agent-policy/policy.mjs";
import {
  MAX_FILE_CHARS,
  MAX_PROMPT_CHARS,
  ToolError,
  ask,
  buildPrompt,
  main,
  planAsk,
  promptBudgetFor,
  readRepoFile,
} from "./ask.mjs";

/** A backend stub that records what it was asked and returns a fixed answer. */
function stubBackend(answer = "stub answer") {
  const calls = [];
  return {
    calls,
    callModel: async (request) => {
      calls.push(request);
      return answer;
    },
  };
}

test("an allowlisted file plans as a local request", () => {
  const plan = planAsk({ question: "what is this repo?", paths: ["README.md"] });
  assert.equal(plan.tier, "local");
  assert.equal(plan.taskClass, "qa");
  assert.deepEqual(plan.files, ["README.md"]);
  assert.match(plan.model, /qwen/);
});

test("a denied path is refused and the message says not to retry", () => {
  assert.throws(
    () => planAsk({ question: "what does this do?", paths: ["crates/olympus-crypto/src/lib.rs"] }),
    (error) => {
      assert.ok(error instanceof PolicyError);
      assert.match(error.message, /crates\/olympus-crypto\/src\/lib\.rs/);
      assert.match(error.message, /do not retry/);
      assert.equal(error.denied[0].path, "crates/olympus-crypto/src/lib.rs");
      return true;
    },
  );
});

test("a question naming a protected concern is refused without any path", () => {
  assert.throws(
    () => planAsk({ question: "explain how the leaf hash is built" }),
    (error) => {
      assert.ok(error instanceof PolicyError);
      assert.equal(error.denied.length, 0);
      assert.match(error.message, /protected concern/);
      return true;
    },
  );
});

test("paths that are absolute or climb out are refused, not resolved", () => {
  for (const path of ["../secrets.env", "/etc/passwd", "C:/Windows/win.ini", "src/../../x.md"]) {
    assert.throws(
      () => planAsk({ question: "summarize this", paths: [path] }),
      (error) => {
        assert.ok(error instanceof PolicyError, `${path} must be a policy refusal`);
        // The reason, not just a refusal: an unrelated failure (a read error,
        // a typo'd class) must not be able to satisfy this test.
        assert.match(error.message, /could not be normalized/);
        assert.equal(error.denied.length, 1);
        return true;
      },
    );
  }
});

test("an unknown task class is refused and lists the known ones", () => {
  assert.throws(
    () => planAsk({ question: "summarize this", paths: ["README.md"], taskClass: "do-everything" }),
    (error) => {
      assert.ok(error instanceof PolicyError);
      assert.match(error.message, /unknown task class "do-everything"/);
      assert.match(error.message, /\bqa\b/);
      return true;
    },
  );
});

test("a file over the per-file cap is truncated with a visible note", () => {
  const big = "x".repeat(MAX_FILE_CHARS + 500);
  const built = buildPrompt("what is this?", [{ path: "docs/big.md", text: big }]);
  assert.deepEqual(built.includedPaths, ["docs/big.md"]);
  assert.deepEqual(built.droppedPaths, []);
  assert.match(built.prompt, /\[truncated: 500 of \d+ characters omitted\]/);
  assert.ok(built.prompt.length <= MAX_PROMPT_CHARS + 1000);
});

test("files past the total budget are named, not silently omitted", () => {
  const full = "y".repeat(MAX_FILE_CHARS);
  const built = buildPrompt("what is this?", [
    { path: "docs/first.md", text: full },
    { path: "docs/second.md", text: full },
    { path: "docs/third.md", text: "short" },
  ]);
  assert.deepEqual(built.includedPaths, ["docs/first.md", "docs/second.md"]);
  assert.deepEqual(built.droppedPaths, ["docs/third.md"]);
  assert.match(built.prompt, /\[not sent \(prompt budget\): docs\/third\.md\]/);
});

test("the total budget follows the window the backend will pin", async () => {
  // An 8192-token window holds (8192 - 4096) * 3 = 12288 characters. A fixed
  // 48000-character cap would send ~4x what the model can see, and Ollama drops
  // the overflow without saying so while this tool reported every file sent.
  const budget = await promptBudgetFor({ effectiveNumCtx: async () => 8_192 }, "any-model");
  assert.equal(budget, 12_288);
  const built = buildPrompt(
    "what is this?",
    [{ path: "docs/big.md", text: "z".repeat(30_000) }],
    budget,
  );
  assert.match(built.prompt, /\[truncated: \d+ of 30000 characters omitted\]/);
  assert.ok(built.prompt.length <= budget + 1_000, "prompt must fit the derived budget");
});

test("a backend reporting no window falls back to the default-window budget", async () => {
  assert.equal(await promptBudgetFor({}, "any-model"), MAX_PROMPT_CHARS);
  assert.equal(MAX_PROMPT_CHARS, 36_864);
});

test("ask sends the file body and the question to the model it planned for", async () => {
  const backend = stubBackend("the repo is Olympus");
  const result = await ask({ question: "what is this repo?", paths: ["README.md"], backend });
  assert.equal(result.answer, "the repo is Olympus");
  assert.equal(backend.calls.length, 1);
  const [request] = backend.calls;
  assert.equal(request.model, result.model);
  assert.match(request.prompt, /File: README\.md/);
  assert.match(request.prompt, /Question: what is this repo\?/);
});

test("ask refuses on the policy before reading anything", async () => {
  const backend = stubBackend();
  // The path deliberately does not exist: a read-first implementation would
  // fail with ToolError ("cannot read"), so PolicyError proves the ordering.
  await assert.rejects(
    () => ask({ question: "review this", paths: ["src-tauri/definitely-missing.rs"], backend }),
    PolicyError,
  );
  assert.equal(backend.calls.length, 0);
});

test("readRepoFile refuses a path outside the repo", async () => {
  await assert.rejects(() => readRepoFile("../../etc/passwd"), ToolError);
  await assert.rejects(() => readRepoFile("/etc/passwd"), ToolError);
});

test("--check prints the plan and never calls the model", async () => {
  const backend = stubBackend();
  const original = process.stdout.write;
  let printed = "";
  process.stdout.write = (chunk) => {
    printed += chunk;
    return true;
  };
  try {
    const code = await main(["--check", "-f", "README.md", "what is this repo?"], { backend });
    assert.equal(code, 0);
  } finally {
    process.stdout.write = original;
  }
  assert.equal(backend.calls.length, 0);
  const plan = JSON.parse(printed);
  assert.equal(plan.allowed, true);
  assert.equal(plan.tier, "local");
});

test("ask reports the token counts the backend forwarded", async () => {
  const backend = {
    callModel: async ({ onStats }) => {
      onStats({ promptTokens: 120, completionTokens: 7, doneReason: "stop" });
      return "ok";
    },
  };
  const result = await ask({ question: "what is this repo?", paths: ["README.md"], backend });
  assert.deepEqual(result.tokens, { promptTokens: 120, completionTokens: 7, doneReason: "stop" });
  assert.equal(typeof result.durationMs, "number");
});

test("a successful call appends one usage record", async () => {
  const logFile = path.join(mkdtempSync(path.join(tmpdir(), "qwen-log-")), "log.jsonl");
  const previous = process.env.OLYMPUS_ROUTE_LOG_PATH;
  process.env.OLYMPUS_ROUTE_LOG_PATH = logFile;
  const backend = {
    callModel: async ({ onStats }) => {
      onStats({ promptTokens: 10, completionTokens: 2, doneReason: "stop" });
      return "answer";
    },
  };
  const original = process.stdout.write;
  process.stdout.write = () => true;
  try {
    assert.equal(await main(["-f", "README.md", "what is this repo?"], { backend }), 0);
  } finally {
    process.stdout.write = original;
    if (previous === undefined) delete process.env.OLYMPUS_ROUTE_LOG_PATH;
    else process.env.OLYMPUS_ROUTE_LOG_PATH = previous;
  }
  const records = readFileSync(logFile, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(records.length, 1);
  assert.equal(records[0].kind, "usage");
  assert.equal(records[0].promptTokens, 10);
  assert.deepEqual(records[0].files, ["README.md"]);
});

test("a refusal exits 3 so a caller can tell it apart from a crash", async () => {
  const backend = stubBackend();
  const original = process.stderr.write;
  let printed = "";
  process.stderr.write = (chunk) => {
    printed += chunk;
    return true;
  };
  try {
    const code = await main(["explain the hash construction"], { backend });
    assert.equal(code, 3);
  } finally {
    process.stderr.write = original;
  }
  assert.equal(backend.calls.length, 0);
  assert.match(printed, /do not retry/);
});
