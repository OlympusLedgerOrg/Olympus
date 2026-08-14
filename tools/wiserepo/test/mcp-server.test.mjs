// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { gatherContext, formatSemanticResults } from "../src/mcp-server.mjs";
import { semanticSearch } from "../src/search.mjs";

// gatherContext is exported (rather than a module-private function) so
// these can exercise it directly instead of trusting the code by
// inspection. Importing this module does not hang on stdio — see the
// import.meta.url-guarded bootstrap at the bottom of mcp-server.mjs.

test("gatherContext rejects a files array over the per-request cap", async () => {
  const files = Array.from({ length: 41 }, () => "CLAUDE.md");
  await assert.rejects(() => gatherContext({ files }), /per-request cap is 40/);
});

test("gatherContext accepts a files array at the cap", async () => {
  const files = Array.from({ length: 40 }, () => "CLAUDE.md");
  // Should not throw the cap error; content is real CLAUDE.md repeated 40x,
  // so this also exercises the budget-truncation path below.
  const result = await gatherContext({ files });
  assert.equal(typeof result, "string");
});

test("gatherContext notes when the combined context budget is exceeded", async () => {
  // CLAUDE.md is tens of KB; repeating it is the cheapest way to blow past
  // the 300k combined budget without needing a synthetic huge fixture file.
  const files = Array.from({ length: 40 }, () => "CLAUDE.md");
  const result = await gatherContext({ files });
  assert.match(result, /total context exceeded 300000 chars/);
});

test("gatherContext with no files/grep/diffArgs returns an empty string, not an error", async () => {
  const result = await gatherContext({});
  assert.equal(result, "");
});

// ── semantic search integration ─────────────────────────────────────────────

test("formatSemanticResults renders file, line range, similarity score, and text", () => {
  const rendered = formatSemanticResults([
    { file: "a.rs", startLine: 1, endLine: 5, text: "fn a() {}", score: 0.876543 },
  ]);
  assert.match(rendered, /## Semantic search results/);
  assert.match(rendered, /a\.rs:1-5/);
  assert.match(rendered, /similarity 0\.877/);
  assert.match(rendered, /fn a\(\) \{\}/);
});

test("formatSemanticResults on an empty result list returns an empty string", () => {
  assert.equal(formatSemanticResults([]), "");
});

test("semanticSearch returns null (not an error, not a network call) when no index has been built", async () => {
  // repo_qa's whole point in falling back gracefully depends on this: no
  // index built yet must be indistinguishable, cost-wise, from the feature
  // not existing -- no embeddings API call, no OPENAI_API_KEY required.
  // Uses WISEREPO_ROOT pointed at a directory with no .wiserepo-index/ to
  // guarantee this, independent of whether this checkout happens to have
  // a real index sitting around from local testing.
  const { mkdtempSync, rmSync } = await import("node:fs");
  const os = await import("node:os");
  const path = await import("node:path");
  const dir = mkdtempSync(path.join(os.tmpdir(), "wiserepo-no-index-"));
  const originalRoot = process.env.WISEREPO_ROOT;
  const originalKey = process.env.OPENAI_API_KEY;
  process.env.WISEREPO_ROOT = dir;
  delete process.env.OPENAI_API_KEY;
  try {
    const result = await semanticSearch("does anything match");
    assert.equal(result, null);
  } finally {
    if (originalRoot !== undefined) process.env.WISEREPO_ROOT = originalRoot;
    else delete process.env.WISEREPO_ROOT;
    if (originalKey !== undefined) process.env.OPENAI_API_KEY = originalKey;
    rmSync(dir, { recursive: true, force: true });
  }
});
