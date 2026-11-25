// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  buildBaselineRecord,
  buildRunRecord,
  casePassed,
  indexGoldenCases,
  parseArgs,
  promptSha256,
  provenanceDiffs,
  rescoreRecord,
  scoreCase,
  suiteScores,
} from "../bin/eval.mjs";
import { missingExpectations } from "../src/eval-match.mjs";

const fixture = (name) =>
  readFile(fileURLToPath(new URL(`../eval/fixtures/${name}`, import.meta.url)), "utf8");

const goldenReview = async () =>
  JSON.parse(
    await readFile(fileURLToPath(new URL("../eval/golden-review.json", import.meta.url)), "utf8"),
  );

test("parseArgs defaults to every suite with no limit", () => {
  assert.deepEqual(parseArgs([]), {
    limit: Infinity,
    model: undefined,
    rescore: undefined,
    showAnswers: false,
    task: "all",
    writeBaseline: false,
  });
});

// The score cannot say why a case moved, so a run has to be able to show the
// answers it scored without changing what is scored.
test("parseArgs accepts --show-answers", () => {
  const options = parseArgs(["--show-answers"]);
  assert.equal(options.showAnswers, true);
  assert.equal(options.task, "all");
});

test("parseArgs accepts --task=<suite> and --task <suite>", () => {
  assert.equal(parseArgs(["--task=review"]).task, "review");
  assert.equal(parseArgs(["--task", "summarize"]).task, "summarize");
  assert.equal(parseArgs(["--task", "all"]).task, "all");
});

test("parseArgs rejects an unknown or missing task", () => {
  assert.throws(() => parseArgs(["--task=qa2"]), /--task must be one of/);
  assert.throws(() => parseArgs(["--task"]), /--task needs a value/);
});

test("parseArgs rejects a non-positive limit", () => {
  assert.throws(() => parseArgs(["--limit", "0"]), /positive integer/);
  assert.throws(() => parseArgs(["--limit=abc"]), /positive integer/);
  assert.equal(parseArgs(["--limit=2"]).limit, 2);
});

test("parseArgs accepts --model and --write-baseline", () => {
  const options = parseArgs(["--model", "qwen2.5-coder:3b", "--write-baseline"]);
  assert.equal(options.model, "qwen2.5-coder:3b");
  assert.equal(options.writeBaseline, true);
});

// The validation moved to where the value is read, so both spellings that carry
// no tag are rejected — including `--model=`, which the old trailing
// `argv.includes("--model")` re-check let through as an empty model name.
test("parseArgs rejects --model with no value, in both spellings", () => {
  assert.throws(() => parseArgs(["--model"]), /--model needs a value/);
  assert.throws(() => parseArgs(["--model="]), /--model needs a value/);
  assert.throws(() => parseArgs(["--write-baseline", "--model"]), /--model needs a value/);
});

// The review score is only meaningful while the fixture still contains the bug
// it claims to plant, and the red herring it claims to remove. A future edit
// that "fixes" the fixture would otherwise silently turn the eval into a test
// that passes on an empty diff.
test("the review fixture still plants the bug and the removed-line red herring", async () => {
  const before = await fixture("pager.before.js");
  const after = await fixture("pager.after.js");

  // The planted bug: exactly one extra page, added by the diff.
  assert.match(after, /Math\.ceil\(totalItems \/ PAGE_SIZE\) \+ 1/);
  assert.doesNotMatch(before, /PAGE_SIZE\) \+ 1/);

  // The red herring: removed by the diff, so a deletion-blind review reports
  // it as still present instead of finding the real bug.
  assert.match(before, /lastPage - 1/);
  assert.doesNotMatch(after, /lastPage - 1/);

  // The third state is the clean one: the bug is gone too, so a case can score
  // a review that must find nothing and flag nothing.
  const fixed = await fixture("pager.fixed.js");
  assert.doesNotMatch(fixed, /PAGE_SIZE\) \+ 1/);
  assert.doesNotMatch(fixed, /lastPage - 1/);
});

// `git diff -U3` merges changes that are 6 or fewer lines apart, so the planted
// changes have to stay separated for "does the review cover each changed
// function" to be observable at all: one hunk makes the second change invisible
// as a distinct thing to report.
test("the two fixture changes land in separate diff hunks", async () => {
  const lines = (await fixture("pager.after.js")).split("\n");
  const plantedBug = lines.findIndex((line) => line.includes("PAGE_SIZE) + 1"));
  const clampFix = lines.findIndex((line) => line.includes("return lastPage;"));
  assert.ok(plantedBug > -1 && clampFix > -1, "both changes must still be in the file");
  assert.ok(
    clampFix - plantedBug > 6,
    `${clampFix - plantedBug} lines apart — -U3 merges changes within 6 into one hunk`,
  );
});

// `expect_absent` alone is satisfied by SILENCE: a review that never mentions
// the clampPage hunk passes it, so the case could not tell "read the deletion
// correctly" from "never looked at it". Every review case now also has to
// mention what the diff changed, and the phantom case specifically has to name
// the function whose removed line it is scored on.
test("every review case requires the review to address the diff", async () => {
  const cases = await goldenReview();
  assert.ok(cases.length > 0);
  for (const item of cases) {
    assert.ok(
      Array.isArray(item.expect) && item.expect.length > 0,
      `${item.id} has no positive expectation`,
    );
  }
  const phantom = cases.find((item) => item.id === "no-phantom-removed-line");
  assert.ok(phantom, "the phantom case is missing");
  assert.ok(phantom.expect.includes("clampPage"));

  // The planted bug is scored on the consequence, and the group of accepted
  // phrasings must keep the original one — otherwise a rewrite could quietly
  // drop the only wording the case was recorded against.
  const planted = cases.find((item) => item.id === "planted-off-by-one");
  const consequence = planted.expect.find(Array.isArray);
  assert.ok(consequence, "the planted-bug case has no consequence group");
  assert.ok(consequence.includes("extra page"));

  // A clean range whose only change is a correct fix: the review must not turn
  // the removed `+ 1` into a live defect. Without `expect` it would pass on a
  // review that never looked.
  // Two cases on the same range send the same prompt, so the second scores a
  // replay of the first answer (at temperature 0, verbatim) instead of an
  // independent sample.
  const ranges = cases.map((item) => item.diffArgs.join(".."));
  assert.equal(new Set(ranges).size, ranges.length, `review cases share a diff: ${ranges.join(", ")}`);

  const clean = cases.find((item) => item.id === "clean-fix-not-flagged");
  assert.ok(clean, "the clean-fix case is missing");
  assert.deepEqual(clean.diffArgs, ["HEAD~1", "HEAD"]);
  // `+ 1` alone missed a real false positive (the answer wrote "adding 1" with
  // no plus), so the consequence phrasing is scored too.
  assert.deepEqual(clean.expect_absent, ["+ 1", "extra page"]);
  assert.ok(clean.expect.length > 0);
});

// REGRESSION: a review that only discussed one hunk PASSED the phantom case
// because the other function's identifier appeared in the diff it pasted back.
// This drives scoreCase — the function runSuite actually calls — so it proves
// the composition (prose for expectations, whole answer for phantoms), not just
// that the two helpers work in isolation.
test("scoreCase scores prose for expectations and the whole answer for phantoms", async () => {
  const item = { expect: ["clampPage"], expect_absent: ["lastPage - 1"] };

  const echoOnly = [
    "### Finding: pageCount",
    "It adds an extra page.",
    "```diff",
    " export function clampPage(page, lastPage) {",
    "```",
  ].join("\n");
  const echoed = await scoreCase(echoOnly, item);
  assert.deepEqual(echoed.missing, ["clampPage"], "an identifier only in the pasted diff is not a finding");
  assert.equal(echoed.ok, false);

  const correct = [
    "### Finding: clampPage",
    "The diff removes the `lastPage - 1` return.",
    "```diff",
    "-  if (page > lastPage) return lastPage - 1;",
    "+  if (page > lastPage) return lastPage;",
    "```",
  ].join("\n");
  const scored = await scoreCase(correct, item);
  assert.deepEqual(
    [scored.missing, scored.phantom, scored.badCitations, scored.ok],
    [[], [], [], true],
  );
});

// A correct review may phrase the same finding differently; the case scores the
// finding, so any accepted phrasing passes and the diagnostic names them all.
test("an expectation group accepts equivalent phrasings", () => {
  const expect = ["pageCount", ["extra page", "one page too many"]];
  assert.deepEqual(missingExpectations("pageCount now returns one page too many", expect), []);
  assert.deepEqual(missingExpectations("pageCount adds + 1", expect), [
    "extra page | one page too many",
  ]);
});

// Citations were printed beside the verdict and never scored, so a review that
// named a file it never read could still PASS. An invented path now fails the
// case on its own, with the other conditions still load-bearing.
test("a case fails when any citation is unverified", () => {
  const clean = { missing: [], phantom: [], badCitations: [] };
  assert.equal(casePassed(clean), true);
  assert.equal(
    casePassed({ ...clean, badCitations: [{ path: "src/ghost.js", line: 12 }] }),
    false,
  );
  assert.equal(casePassed({ ...clean, missing: ["extra page"] }), false);
  assert.equal(casePassed({ ...clean, phantom: ["lastPage - 1"] }), false);
});

test("parseArgs accepts --rescore and refuses to combine it with --write-baseline", () => {
  assert.equal(parseArgs(["--rescore", "eval/runs/r.json"]).rescore, "eval/runs/r.json");
  assert.equal(parseArgs(["--rescore=eval/runs/r.json"]).rescore, "eval/runs/r.json");
  assert.throws(() => parseArgs(["--rescore"]), /--rescore needs a value/);
  assert.throws(() => parseArgs(["--rescore="]), /--rescore needs a value/);
  assert.throws(
    () => parseArgs(["--rescore", "eval/runs/r.json", "--write-baseline"]),
    /cannot also --write-baseline/,
  );
});

// A hash of the user message alone would call two materially different review
// prompts identical: the review prompt is mostly AGENTS.md plus its framing.
test("the prompt hash covers the system prompt and the user prompt separately", () => {
  const digest = promptSha256({ system: "standards", prompt: "diff" });
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.equal(promptSha256({ system: "standards", prompt: "diff" }), digest);
  assert.notEqual(promptSha256({ system: "other standards", prompt: "diff" }), digest);
  // Concatenating the two without a separator would hash these the same.
  assert.notEqual(
    promptSha256({ system: "ab", prompt: "c" }),
    promptSha256({ system: "a", prompt: "bc" }),
  );
});

// The baseline is the comparison point, so it must not quietly become a second
// copy of the transcript: scores are derived from the cases, and the answers
// live in the run file the baseline points at.
test("the run record derives suite scores from the stored cases", () => {
  const cases = [
    { suite: "qa", id: "a", seconds: 2, ok: true },
    { suite: "qa", id: "b", seconds: 3, ok: false },
    { suite: "review", id: "c", seconds: 1, ok: true },
  ];
  assert.deepEqual(suiteScores(cases), {
    qa: { passed: 1, total: 2, seconds: 5 },
    review: { passed: 1, total: 1, seconds: 1 },
  });

  const record = buildRunRecord({
    recordedAt: "2026-01-01T00:00:00.000Z",
    model: "qwen2.5-coder:7b-instruct",
    provenance: {
      git_sha: "a".repeat(40),
      git_dirty: false,
      prompt_sha256: "b".repeat(64),
      models: {},
    },
    cases,
  });
  assert.equal(record.cases.length, 3);
  assert.equal(record.suites.qa.total, 2);

  const baseline = buildBaselineRecord(record, "runs/2026-01-01.json");
  assert.deepEqual(baseline.suites, record.suites);
  assert.equal(baseline.provenance, record.provenance);
  assert.equal(baseline.answers, "runs/2026-01-01.json");
  assert.equal(
    "cases" in baseline,
    false,
    "the baseline points at the answers instead of copying them",
  );
});

// The point of recording raw answers: a scoring change can be checked against
// real answers without paying for the model call again.
test("a recorded run re-scores offline, and a changed verdict is visible", async () => {
  const item = { id: "phantom-case", expect: ["clampPage"], expect_absent: ["lastPage - 1"] };
  const goldenById = indexGoldenCases([{ suite: "review", cases: [item] }]);
  const entries = [
    {
      suite: "review",
      id: "phantom-case",
      model: "test-model:1b",
      seconds: 4,
      prompt_sha256: "a".repeat(64),
      answer: "clampPage no longer returns `lastPage - 1`; the diff removes it.",
    },
    {
      suite: "review",
      id: "phantom-case",
      model: "test-model:1b",
      seconds: 4,
      prompt_sha256: "a".repeat(64),
      answer: "clampPage still returns `lastPage - 1`.",
    },
  ];

  const scored = await rescoreRecord(entries, goldenById);
  assert.deepEqual(scored.map((entry) => entry.ok), [true, false]);
  // Re-scoring explains the recorded run; it does not replace it.
  assert.equal(scored[0].answer, entries[0].answer);
  assert.equal(scored[0].prompt_sha256, entries[0].prompt_sha256);
});

// A re-score that only re-ran the stored verdict would pass a review citing a
// file it invented. Citation checking is still part of the score.
test("re-scoring verifies citations against the tree", async () => {
  const goldenById = indexGoldenCases([{ suite: "qa", cases: [{ id: "ghost", expect: ["clampPage"] }] }]);
  const [scored] = await rescoreRecord(
    [{ suite: "qa", id: "ghost", seconds: 1, answer: "clampPage is defined in src/ghost-rescore.js:9." }],
    goldenById,
  );
  assert.equal(scored.ok, false);
  assert.equal(scored.verdict.badCitations.length, 1);
});

// A record outliving the case it names must say so, not score it as a pass.
test("a run record naming a case the golden files no longer have is a hard error", async () => {
  await assert.rejects(
    rescoreRecord([{ suite: "qa", id: "gone", answer: "x" }], new Map()),
    /not a golden case/,
  );
});

// Without this, a prompt edit plus a re-pulled model reads exactly like a prompt
// regression and gets blamed on whichever changed last.
test("provenance diffs name every change that makes a comparison unlike-for-like", () => {
  const before = {
    git_sha: "a".repeat(40),
    git_dirty: false,
    prompt_sha256: "b".repeat(64),
    models: { "m:1": { digest: "sha256:1111", num_ctx: 16384 } },
  };
  assert.deepEqual(provenanceDiffs(before, structuredClone(before)), []);

  const after = {
    git_sha: "c".repeat(40),
    git_dirty: true,
    prompt_sha256: "d".repeat(64),
    models: { "m:1": { digest: "sha256:2222", num_ctx: 8192 } },
  };
  assert.deepEqual(provenanceDiffs(before, after), [
    `git ${"a".repeat(12)} -> ${"c".repeat(12)}`,
    "worktree clean -> dirty",
    `prompt ${"b".repeat(12)} -> ${"d".repeat(12)}`,
    "m:1 weights sha256:1111 -> sha256:2222",
    "m:1 num_ctx 16384 -> 8192",
  ]);

  // A baseline recorded before provenance existed is "unknown", not "equal".
  assert.equal(provenanceDiffs({}, before).length, 5);
});
