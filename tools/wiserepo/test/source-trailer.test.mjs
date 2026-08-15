// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  computeSourceHash,
  extractSourceTrailer,
  stripSourceTrailer,
  embedSourceTrailer,
} from "../src/source-trailer.mjs";

test("computeSourceHash is deterministic and content-sensitive", () => {
  assert.equal(computeSourceHash("hello"), computeSourceHash("hello"));
  assert.notEqual(computeSourceHash("hello"), computeSourceHash("Hello"));
  assert.match(computeSourceHash("x"), /^[0-9a-f]{64}$/);
});

test("extractSourceTrailer returns null when absent", () => {
  assert.equal(extractSourceTrailer("# Doc\n\nsome content\n"), null);
});

test("embedSourceTrailer then extractSourceTrailer round-trips the hash", () => {
  const hash = computeSourceHash("source content");
  const doc = embedSourceTrailer("# Doc\n\nbody text\n", hash);
  assert.equal(extractSourceTrailer(doc), hash);
});

test("embedSourceTrailer replaces an existing trailer rather than appending a second one", () => {
  const oldHash = computeSourceHash("old");
  const newHash = computeSourceHash("new");
  const withOld = embedSourceTrailer("# Doc\n\nbody\n", oldHash);
  const withNew = embedSourceTrailer(withOld, newHash);
  assert.equal(extractSourceTrailer(withNew), newHash);
  assert.equal(
    (withNew.match(/wiserepo:source-sha256/g) || []).length,
    1,
    "must not accumulate trailers",
  );
});

test("stripSourceTrailer removes the trailer and leaves body content untouched", () => {
  const hash = computeSourceHash("x");
  const withTrailer = embedSourceTrailer("# Doc\n\nbody text\n", hash);
  const stripped = stripSourceTrailer(withTrailer);
  assert.ok(stripped.includes("body text"));
  assert.equal(extractSourceTrailer(stripped), null);
});

// This is the actual invariant the whole sync-detection mechanism rests on:
// changing the SOURCE's content — even in a way that leaves Markdown
// structure (headings/bullets/tables) completely unchanged, like rewording
// a sentence — must change the recorded hash. This is what structural
// parity alone could not detect, which was the real finding.
test("REGRESSION: a prose-only content change (same structure) changes the hash", () => {
  const before = "# T\n\n## Critical Invariants\n\n- shard creation is operator-controlled\n";
  const after = "# T\n\n## Critical Invariants\n\n- shard creation is open to any caller\n";
  assert.notEqual(computeSourceHash(before), computeSourceHash(after));
});

test("embedSourceTrailer output ends with exactly one trailing newline", () => {
  const doc = embedSourceTrailer("# Doc\n\nbody\n\n\n", computeSourceHash("x"));
  assert.ok(doc.endsWith("-->\n"));
  assert.ok(!doc.endsWith("-->\n\n"));
});
