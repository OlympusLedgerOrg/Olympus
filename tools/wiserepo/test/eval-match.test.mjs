// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { missingExpectations, normaliseForExpect, unexpectedMentions } from "../src/eval-match.mjs";

// The false negative that made a correct 6/6 run report 5/6: the model wrote
// "SHA-256 …" for the expectation "sha256". Case and separator punctuation
// are the same token.
test("case and separator punctuation do not fail a correct answer", () => {
  assert.deepEqual(missingExpectations("a SHA-256 hash of the source", ["sha256"]), []);
  assert.deepEqual(missingExpectations("uses node_prefix for SMT nodes", ["NODE_PREFIX"]), []);
  assert.deepEqual(missingExpectations("NODE PREFIX", ["NODE_PREFIX"]), []);
  assert.deepEqual(
    missingExpectations("the variable is `olympus-ceremony-coordinator-key`", [
      "OLYMPUS_CEREMONY_COORDINATOR_KEY",
    ]),
    [],
  );
});

// ...but normalisation must not become fuzziness, or the golden set would stop
// being able to report a regression at all.
test("a genuinely absent expectation still fails", () => {
  assert.deepEqual(missingExpectations("it compares a stored hash", ["sha256"]), ["sha256"]);
});

test("matching is not stemmed or synonym-aware", () => {
  assert.deepEqual(missingExpectations("authorization of writes to a shard", ["authorize_write"]), [
    "authorize_write",
  ]);
});

// A review can name every real bug and still invent a phantom one from a line
// the diff deleted; stating the stale value as CURRENT is the thing to score.
test("unexpectedMentions flags removed text stated as current", () => {
  assert.deepEqual(unexpectedMentions("clampPage returns lastPage - 1", ["lastPage - 1"]), [
    "lastPage - 1",
  ]);
  assert.deepEqual(unexpectedMentions("clampPage returns lastPage", ["lastPage - 1"]), []);
  // Same folding as the positive matcher, or the two would disagree on a token.
  assert.deepEqual(unexpectedMentions("LASTPAGE-1", ["lastPage - 1"]), ["lastPage - 1"]);
});

// The golden case exists to reward reading a deletion correctly. Calling the
// value removed is the right answer, so attributing it must not fail the case.
test("unexpectedMentions accepts removed text called removed", () => {
  assert.deepEqual(
    unexpectedMentions("The diff removes `lastPage - 1` from clampPage; that is a fix.", [
      "lastPage - 1",
    ]),
    [],
  );
  assert.deepEqual(
    unexpectedMentions("clampPage previously returned lastPage - 1, dropping the final page.", [
      "lastPage - 1",
    ]),
    [],
  );
  assert.deepEqual(
    unexpectedMentions("clampPage now returns lastPage instead of lastPage - 1.", ["lastPage - 1"]),
    [],
  );
  assert.deepEqual(
    unexpectedMentions("The lastPage - 1 off-by-one was removed by this diff.", ["lastPage - 1"]),
    [],
  );
});

// ...but a removal word in the same sentence must not launder a claim that the
// value is still live, and the attribution has to sit near the mention.
test("unexpectedMentions still flags a live claim beside a removal word", () => {
  assert.deepEqual(
    unexpectedMentions("The diff removes a guard, so clampPage still returns lastPage - 1.", [
      "lastPage - 1",
    ]),
    ["lastPage - 1"],
  );
  assert.deepEqual(
    unexpectedMentions(
      "The diff removes a guard and renames a helper. clampPage returns lastPage - 1.",
      ["lastPage - 1"],
    ),
    ["lastPage - 1"],
  );
  // A review's own "Fix:" heading is a bug claim, not an attribution.
  assert.deepEqual(
    unexpectedMentions("**Fix**: change `return lastPage - 1;` to `return lastPage;`.", [
      "lastPage - 1",
    ]),
    ["lastPage - 1"],
  );
});

// A review's own example diff quotes the removed line with git's `-` marker; that
// is the removal stated, not a claim that the line is live. A Markdown bullet
// with a single space is still a claim, and a `+` line is code the diff ADDS, so
// repeating the forbidden value there is asserting it as the new behaviour.
test("unexpectedMentions reads a diff removal line as attribution", () => {
  assert.deepEqual(unexpectedMentions("-  return lastPage - 1;", ["lastPage - 1"]), []);
  // A `+` line is the post-diff code, so it never counts as attribution.
  assert.deepEqual(unexpectedMentions("+\treturn lastPage - 1;", ["lastPage - 1"]), [
    "lastPage - 1",
  ]);
  assert.deepEqual(unexpectedMentions("- clampPage returns lastPage - 1", ["lastPage - 1"]), [
    "lastPage - 1",
  ]);
});

test("normaliseForExpect folds case, spaces, hyphens and underscores only", () => {
  assert.equal(normaliseForExpect(" Qwen2.5-Coder:7b-Instruct "), "qwen2.5coder:7binstruct");
  assert.equal(normaliseForExpect(null), "");
});
