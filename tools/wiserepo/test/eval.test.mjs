// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { casePassed, parseArgs, scoreCase } from "../bin/eval.mjs";
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
