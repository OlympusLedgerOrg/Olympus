// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { missingExpectations, normaliseForExpect } from "../src/eval-match.mjs";

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

test("normaliseForExpect folds case, spaces, hyphens and underscores only", () => {
  assert.equal(normaliseForExpect(" Qwen2.5-Coder:7b-Instruct "), "qwen2.5coder:7binstruct");
  assert.equal(normaliseForExpect(null), "");
});
