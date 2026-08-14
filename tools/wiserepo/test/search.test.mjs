// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { searchIndex } from "../src/search.mjs";

const entries = {
  a: { file: "a.rs", startLine: 1, endLine: 5, text: "exact match", vector: [1, 0, 0] },
  b: { file: "b.rs", startLine: 1, endLine: 5, text: "orthogonal", vector: [0, 1, 0] },
  c: { file: "c.rs", startLine: 1, endLine: 5, text: "close match", vector: [0.9, 0.1, 0] },
  d: { file: "d.rs", startLine: 1, endLine: 5, text: "opposite", vector: [-1, 0, 0] },
};

test("searchIndex ranks by cosine similarity, highest first", () => {
  const results = searchIndex([1, 0, 0], entries, 4);
  assert.deepEqual(
    results.map((r) => r.file),
    ["a.rs", "c.rs", "b.rs", "d.rs"],
  );
});

test("searchIndex respects topK", () => {
  const results = searchIndex([1, 0, 0], entries, 2);
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.file),
    ["a.rs", "c.rs"],
  );
});

test("searchIndex returns file/line metadata alongside the score", () => {
  const results = searchIndex([1, 0, 0], entries, 1);
  assert.equal(results[0].file, "a.rs");
  assert.equal(results[0].startLine, 1);
  assert.equal(results[0].endLine, 5);
  assert.equal(results[0].text, "exact match");
  assert.equal(results[0].score, 1);
});

test("searchIndex on an empty index returns an empty array", () => {
  assert.deepEqual(searchIndex([1, 0, 0], {}, 5), []);
});

test("searchIndex topK larger than entry count returns all entries", () => {
  const results = searchIndex([1, 0, 0], entries, 100);
  assert.equal(results.length, 4);
});
