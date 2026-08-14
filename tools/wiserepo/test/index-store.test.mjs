// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { chunkHash, loadIndex, saveIndex, indexExists } from "../src/index-store.mjs";

// Each test gets its own throwaway WISEREPO_ROOT so index files never touch
// the real repo's .wiserepo-index/ directory.
function withTempRoot(fn) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "wiserepo-index-test-"));
  const originalRoot = process.env.WISEREPO_ROOT;
  process.env.WISEREPO_ROOT = dir;
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      if (originalRoot !== undefined) process.env.WISEREPO_ROOT = originalRoot;
      else delete process.env.WISEREPO_ROOT;
      rmSync(dir, { recursive: true, force: true });
    });
}

test("chunkHash is deterministic and content-sensitive", () => {
  assert.equal(chunkHash("abc"), chunkHash("abc"));
  assert.notEqual(chunkHash("abc"), chunkHash("abd"));
  assert.match(chunkHash("x"), /^[0-9a-f]{64}$/);
});

test("loadIndex returns an empty index when no file exists yet", async () => {
  await withTempRoot(async () => {
    const index = await loadIndex();
    assert.equal(indexExists(index), false);
    assert.deepEqual(index.entries, {});
  });
});

test("saveIndex then loadIndex round-trips entries", async () => {
  await withTempRoot(async () => {
    const index = await loadIndex();
    index.entries["abc123"] = {
      file: "x.rs",
      startLine: 1,
      endLine: 5,
      text: "fn x() {}",
      vector: [0.1, 0.2],
    };
    index.model = "text-embedding-3-small";
    await saveIndex(index);

    const reloaded = await loadIndex();
    assert.equal(indexExists(reloaded), true);
    assert.equal(reloaded.model, "text-embedding-3-small");
    assert.deepEqual(reloaded.entries["abc123"].vector, [0.1, 0.2]);
  });
});

test("loadIndex treats an incompatible version as absent rather than crashing", async () => {
  await withTempRoot(async () => {
    const { writeFile, mkdir } = await import("node:fs/promises");
    const dir = path.join(process.env.WISEREPO_ROOT, ".wiserepo-index");
    await mkdir(dir, { recursive: true });
    await writeFile(
      path.join(dir, "index.json"),
      JSON.stringify({ version: 999, entries: { x: {} } }),
      "utf8",
    );
    const index = await loadIndex();
    assert.equal(indexExists(index), false);
  });
});
