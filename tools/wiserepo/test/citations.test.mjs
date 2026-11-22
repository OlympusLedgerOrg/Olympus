// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  extractCitations,
  verifyCitations,
  formatMissingCitations,
  hasLine,
} from "../src/citations.mjs";

test("extractCitations finds repo paths with and without line numbers", () => {
  const found = extractCitations(
    "The leaf hash lives in `crates/olympus-crypto/src/lib.rs:42` and the tree in src-tauri/src/smt/tree.rs.",
  );
  assert.deepEqual(found, [
    { path: "crates/olympus-crypto/src/lib.rs", line: 42 },
    { path: "src-tauri/src/smt/tree.rs", line: null },
  ]);
});

// REGRESSION: alternation order made `js` swallow `json` (and `ts` swallow
// `tsx`), so a .json citation parsed as a .js path with no line attached and
// skipped the line check entirely.
test("extractCitations keeps multi-character extensions and their line numbers", () => {
  const found = extractCitations(
    "see tools/wiserepo/package.json:12 and src/ui/App.tsx:34 and a/b/notes.md",
  );
  assert.deepEqual(found, [
    { path: "tools/wiserepo/package.json", line: 12 },
    { path: "src/ui/App.tsx", line: 34 },
    { path: "a/b/notes.md", line: null },
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

// `exists` returning true isolates containment from the filesystem: the
// citation has to be rejected because it left the repo, not because the target
// happened to be missing. Otherwise this test would still pass if the
// containment check were deleted.
test("verifyCitations refuses a traversal citation even when the file exists", async () => {
  const { missing } = await verifyCitations("see ../../package.json:1", {
    exists: async () => true,
  });
  assert.equal(missing.length, 1, "a traversal citation must never count as verified");
});

const PKG = "tools/wiserepo/package.json";
// Counted independently of citations.mjs, so an off-by-one there cannot make
// this fixture agree with the bug.
const PKG_LAST_LINE = readFileSync(new URL("../package.json", import.meta.url), "utf8")
  .replace(/\n$/, "")
  .split("\n").length;

const alwaysExists = { exists: async () => true };

test("verifyCitations accepts line 1 and the true last line of a real file", async () => {
  const first = await verifyCitations(`${PKG}:1`, alwaysExists);
  assert.deepEqual(first.missing, []);
  const last = await verifyCitations(`${PKG}:${PKG_LAST_LINE}`, alwaysExists);
  assert.deepEqual(last.missing, []);
});

// REGRESSION: counting `split("\n").length` makes a trailing newline look like
// an extra empty line, so every newline-terminated file in the repo accepts a
// citation one line past its end.
test("verifyCitations rejects the line just past the end of the file", async () => {
  const { missing } = await verifyCitations(`${PKG}:${PKG_LAST_LINE + 1}`, alwaysExists);
  assert.equal(missing.length, 1, "a line past EOF must be reported, not accepted");
});

test("verifyCitations rejects line 0 and an absurdly large line number", async () => {
  for (const line of [0, 999_999_999]) {
    const { missing } = await verifyCitations(`${PKG}:${line}`, alwaysExists);
    assert.equal(missing.length, 1, `line ${line} must be reported`);
  }
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

// hasLine streams instead of buffering the file, so exercise it on a fixture far
// larger than anything tracked here. Correctness at scale is the point: the
// bounds are what a buffered reader got wrong, and streaming them must not
// change the answers.
test("hasLine bounds a large file correctly without buffering it", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "wiserepo-cite-"));
  try {
    const lines = 200_000;
    const file = path.join(dir, "big.txt");
    await writeFile(
      file,
      Array.from({ length: lines }, (_, i) => `line ${i + 1}`).join("\n") + "\n",
    );
    assert.equal(await hasLine(file, 1), true, "first line");
    assert.equal(await hasLine(file, lines), true, "last line of a newline-terminated file");
    assert.equal(await hasLine(file, lines + 1), false, "one past the end");
    assert.equal(await hasLine(file, 0), false, "line 0 is never addressable");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("hasLine counts an unterminated final line, and an empty file has none", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "wiserepo-cite-"));
  try {
    const file = path.join(dir, "small.txt");
    await writeFile(file, "one\ntwo");
    assert.equal(await hasLine(file, 2), true, "final line without a trailing newline");
    assert.equal(await hasLine(file, 3), false);
    await writeFile(file, "");
    assert.equal(await hasLine(file, 1), false, "an empty file has no line 1");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// The confinement check must still run before any bytes are read, so a
// traversal citation fails even though the target is readable.
test("verifyCitations still refuses traversal now that it streams", async () => {
  const { missing } = await verifyCitations("see ../../package.json:1", {
    exists: async () => true,
  });
  assert.equal(missing.length, 1);
});
