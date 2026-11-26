// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  gatherContext,
  budgetCharsFor,
  orderFilesForQuestion,
  runTool,
  withVerifiedCitations,
} from "../src/mcp-server.mjs";

// gatherContext is exported (rather than a module-private function) so
// these can exercise it directly instead of trusting the code by
// inspection. Importing this module does not hang on stdio — see the
// import.meta.url-guarded bootstrap at the bottom of mcp-server.mjs.

// A real, allowlisted, tens-of-KB file. The agent policy refuses AGENTS.md
// along with everything else outside the prose/UI allowlist, so the budget
// tests need a fixture the local model may actually be shown.
const BIG_ALLOWED_FILE = "docs/court-evidence.md";
const SUMMARIZE = { taskClass: "summarize" };

test("gatherContext rejects a files array over the per-request cap", async () => {
  const files = Array.from({ length: 41 }, () => BIG_ALLOWED_FILE);
  await assert.rejects(() => gatherContext({ files, ...SUMMARIZE }), /per-request cap is 40/);
});

test("gatherContext accepts a files array at the cap", async () => {
  const files = Array.from({ length: 40 }, () => BIG_ALLOWED_FILE);
  // Should not throw the cap error; the content is a real file repeated 40x,
  // so this also exercises the budget-truncation path below.
  const result = await gatherContext({ files, ...SUMMARIZE });
  assert.equal(typeof result, "string");
});

test("gatherContext notes when the combined context budget is exceeded", async () => {
  // The fixture is tens of KB; repeating it is the cheapest way to blow past
  // the combined budget without needing a synthetic huge fixture file.
  const files = Array.from({ length: 40 }, () => BIG_ALLOWED_FILE);
  const result = await gatherContext({ files, ...SUMMARIZE });
  // Asserted as a shape, not a literal: the budget is derived from the model's
  // effective window, so a hardcoded number here would encode one machine's
  // model and fail on any other.
  assert.match(result, /combined context exceeded \d+ chars/);
});

// The files that lost out used to vanish silently — the model answered from a
// partial view and the caller had no way to know which file it never saw.
test("gatherContext names the files it dropped for budget", async () => {
  const files = Array.from({ length: 40 }, () => BIG_ALLOWED_FILE);
  const result = await gatherContext({ files, ...SUMMARIZE });
  assert.match(result, /dropped \d+ file\(s\) that did not fit: /);
});

test("gatherContext with no files/grep/diffArgs returns an empty string, not an error", async () => {
  const result = await gatherContext(SUMMARIZE);
  assert.equal(result, "");
});

test("gatherContext refuses to run without a task class", async () => {
  await assert.rejects(() => gatherContext({}), /requires a taskClass/);
});

// The budget must leave room for the answer inside the same window; if it ever
// consumed the whole context the model would be asked to generate with none.
test("budgetCharsFor reserves output space inside the window", () => {
  assert.ok(budgetCharsFor(16_384) < 16_384 * 3, "budget must leave output headroom");
  assert.ok(budgetCharsFor(16_384) > 30_000, "budget should still be usable in practice");
  // Degenerate windows must not produce a negative or zero budget.
  assert.ok(budgetCharsFor(2_048) > 0);
});

// Relevance ordering exists because budget is spent in list order: with a small
// window, whichever file is named last disappears.
test("orderFilesForQuestion floats path-matching files ahead of the rest", () => {
  const files = ["docs/README.md", "src-tauri/src/smt/tree.rs", "AGENTS.md"];
  const ordered = orderFilesForQuestion(files, "what is the smt tree depth?");
  assert.equal(ordered[0], "src-tauri/src/smt/tree.rs");
});

test("orderFilesForQuestion preserves caller order when the question says nothing matchable", () => {
  const files = ["b.md", "a.md"];
  assert.deepEqual(orderFilesForQuestion(files, ""), files);
  assert.deepEqual(orderFilesForQuestion(files, "of to"), files);
});

// Arguments arrive from a model or an MCP client, so they are untrusted input:
// validation runs BEFORE gatherContext reads anything or the model is called.
// Every rejection below therefore happens without touching the network.
test("runTool rejects arguments that are not an object", async () => {
  await assert.rejects(() => runTool("repo_qa", "a string"), /arguments must be an object/);
  await assert.rejects(() => runTool("repo_qa", ["a"]), /arguments must be an object/);
});

test("runTool rejects unknown tools", async () => {
  await assert.rejects(() => runTool("rm_rf", {}), /Unknown tool "rm_rf"/);
});

test("runTool rejects argument names the tool does not accept", async () => {
  await assert.rejects(
    () => runTool("repo_qa", { question: "what is LAZY_DEPTH?", model: "something-else" }),
    /repo_qa\.model is not a supported argument/,
  );
  await assert.rejects(
    () => runTool("olympus_context", { files: ["AGENTS.md"] }),
    /olympus_context\.files is not a supported argument/,
  );
});

test("runTool requires a question for repo_qa", async () => {
  await assert.rejects(() => runTool("repo_qa", {}), /repo_qa\.question is required/);
  await assert.rejects(() => runTool("repo_qa", { question: 42 }), /must be a string/);
});

test("runTool rejects wrongly typed file lists", async () => {
  await assert.rejects(
    () => runTool("repo_qa", { question: "q", files: "AGENTS.md" }),
    /at most 40 strings/,
  );
  await assert.rejects(
    () => runTool("repo_qa", { question: "q", files: ["AGENTS.md", 7] }),
    /at most 40 strings/,
  );
});

// Caps exist so a request cannot force unbounded I/O before the budget runs,
// and so an oversized field cannot be smuggled into the prompt.
test("runTool enforces the per-argument size caps", async () => {
  const cases = [
    [
      "repo_qa",
      { question: "q".repeat(8_001) },
      /repo_qa\.question must be a string of at most 8000/,
    ],
    [
      "repo_qa",
      { question: "q", grep: "g".repeat(2_001) },
      /repo_qa\.grep must be a string of at most 2000/,
    ],
    [
      "repo_qa",
      { question: "q", files: Array.from({ length: 41 }, () => "AGENTS.md") },
      /repo_qa\.files must contain at most 40/,
    ],
    ["repo_qa", { question: "q", files: ["A".repeat(4_097) + ".md"] }, /at most 4096 characters/],
    [
      "review_diff",
      { diffArgs: Array.from({ length: 33 }, () => "HEAD") },
      /review_diff\.diffArgs must contain at most 32/,
    ],
    ["summarize", { style: "s".repeat(201) }, /summarize\.style must be a string of at most 200/],
  ];
  for (const [tool, args, pattern] of cases) {
    await assert.rejects(
      () => runTool(tool, args),
      pattern,
      `${tool} ${JSON.stringify(args).slice(0, 60)}`,
    );
  }
});

// A backend returning JSON, an array, or null is a backend bug. Passing it on
// would ship "[object Object]" into an answer that looks like prose.
test("withVerifiedCitations rejects non-text model output", async () => {
  for (const bad of [42, null, undefined, { text: "hi" }, ["hi"]]) {
    await assert.rejects(
      () => withVerifiedCitations(bad),
      /model returned a non-text response/,
      `expected rejection for ${JSON.stringify(bad)}`,
    );
  }
});

test("withVerifiedCitations truncates oversized model output and says so", async () => {
  const answer = "x".repeat(120_001);
  const result = await withVerifiedCitations(answer);
  assert.match(result, /\[truncated 1 of 120001 chars from model output\]/);
  assert.equal(
    result.length,
    120_000 + "\n...[truncated 1 of 120001 chars from model output]".length,
  );
});

test("review_diff reports omitted input even when the model does not mention it", async (t) => {
  const root = mkdtempSync(join(tmpdir(), "wiserepo-review-"));
  const previousRoot = process.env.WISEREPO_ROOT;
  process.env.WISEREPO_ROOT = root;
  // backend.mjs caches /api/show answers per model name for the process. An
  // earlier test can reach a real local Ollama and cache the default model's
  // real window (32768 for qwen2.5-coder:7b-instruct), which never truncates
  // this fixture. A model name no other test uses forces the mocked 8192.
  const previousModel = process.env.WISEREPO_MODEL_REVIEW;
  process.env.WISEREPO_MODEL_REVIEW = "wiserepo-test-review-truncation";
  t.after(() => {
    if (previousRoot === undefined) delete process.env.WISEREPO_ROOT;
    else process.env.WISEREPO_ROOT = previousRoot;
    if (previousModel === undefined) delete process.env.WISEREPO_MODEL_REVIEW;
    else process.env.WISEREPO_MODEL_REVIEW = previousModel;
    rmSync(root, { recursive: true, force: true });
  });

  execFileSync("git", ["init", "-q"], { cwd: root });
  mkdirSync(join(root, "docs"));
  const file = "docs/review.md";
  const stage = (content) => {
    writeFileSync(join(root, file), content);
    execFileSync("git", ["add", "--", file], { cwd: root });
  };
  let chats = 0;
  t.mock.method(globalThis, "fetch", async (url) => {
    if (url.endsWith("/api/show")) {
      return Response.json({ digest: "test", model_info: { "test.context_length": 8192 } });
    }
    assert.ok(url.endsWith("/api/chat"));
    chats++;
    return new Response(
      JSON.stringify({ message: { content: "Model answer" }, done: true }) + "\n",
    );
  });

  let reviewPrompt;
  const review = () =>
    runTool(
      "review_diff",
      { diffArgs: ["--cached"] },
      {
        onPrompt: ({ prompt }) => {
          reviewPrompt = prompt;
        },
      },
    );
  stage("Small change\n");
  assert.equal(await review(), "Model answer");
  assert.doesNotMatch(reviewPrompt, /partial diff/);

  stage("Start of diff\n" + "Long line for the fixture\n".repeat(1000) + "End of diff\n");
  assert.match(
    await review(),
    /^\[wiserepo: partial review .*omitted \d+ of \d+ diff chars.*\]\n\nModel answer$/,
  );

  assert.match(reviewPrompt, /partial diff; review only the supplied prefix/);
  assert.doesNotMatch(reviewPrompt, /End of diff/);

  writeFileSync(join(root, "AGENTS.md"), "Standards\n".repeat(2000));
  await assert.rejects(review, /No diff content fits in the model context/);
  assert.equal(chats, 2, "no review request should be sent when the whole diff is omitted");
});
