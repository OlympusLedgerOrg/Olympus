// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { extractCitations, verifyCitations, formatMissingCitations } from "../src/citations.mjs";

test("extractCitations finds repo paths with and without line numbers", () => {
  const found = extractCitations(
    "The leaf hash lives in `crates/olympus-crypto/src/lib.rs:42` and the tree in src-tauri/src/smt/tree.rs.",
  );
  assert.deepEqual(found, [
    { path: "crates/olympus-crypto/src/lib.rs", line: 42 },
    { path: "src-tauri/src/smt/tree.rs", line: null },
  ]);
});

test("extractCitations de-duplicates repeats", () => {
  const text = "src-tauri/src/smt/tree.rs then src-tauri/src/smt/tree.rs again";
  assert.equal(extractCitations(text).length, 1);
});

// The narrow extension list is deliberate: flagging prose tokens would train
// people to ignore the warning, which is worse than not warning.
test("extractCitations ignores prose and bare words", () => {
  const found = extractCitations(
    "use and/or instead of either bos/chat or the CLI; also see CLAUDE.md and README",
  );
  assert.deepEqual(found, [], `unexpected citations: ${JSON.stringify(found)}`);
});

test("verifyCitations accepts real files and flags invented ones", async () => {
  const { checked, missing } = await verifyCitations(
    "Real: CLAUDE.md via crates/olympus-crypto/src/lib.rs. Invented: src-tauri/src/does/not/exist.rs.",
  );
  // CLAUDE.md has no slash so it is not a citation candidate; the two repo
  // paths are.
  assert.equal(checked, 2);
  assert.deepEqual(
    missing.map((c) => c.path),
    ["src-tauri/src/does/not/exist.rs"],
  );
});

test("verifyCitations refuses paths that escape the repo without reading them", async () => {
  const { missing } = await verifyCitations("see ../../../../etc/passwd.rs");
  assert.equal(missing.length, 1, "an escaping path must never count as verified");
});

test("formatMissingCitations renders path:line when a line was cited", () => {
  assert.equal(
    formatMissingCitations([
      { path: "a/b.rs", line: 12 },
      { path: "c/d.md", line: null },
    ]),
    "a/b.rs:12, c/d.md",
  );
});
