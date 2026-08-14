// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import {
  extractHeadings,
  extractCodeBlocks,
  stripFencedCode,
  checkStructuralParity,
} from "../src/sections.mjs";
import { repoRoot } from "../src/repo.mjs";

test("extractHeadings pulls every heading verbatim, ignores non-headings", () => {
  const md = [
    "# Title",
    "",
    "Some prose, not a heading.",
    "## Section A",
    "text",
    "### Subsection",
    "not # a heading because no leading #",
    "#NoSpaceNotAHeading",
  ].join("\n");
  assert.deepEqual(extractHeadings(md), ["# Title", "## Section A", "### Subsection"]);
});

// ── code-fence awareness ───────────────────────────────────────────────────
// The bug that made the first version of this checker reject the repo's own
// docs 100% of the time: `# shell comment` inside a ```bash block was counted
// as a Markdown heading.

test("extractHeadings ignores shell comments inside fenced code blocks", () => {
  const md = [
    "# Real Heading",
    "",
    "```bash",
    "# this is a shell comment, NOT a heading",
    "cargo test",
    "```",
    "",
    "## Another Real Heading",
  ].join("\n");
  assert.deepEqual(extractHeadings(md), ["# Real Heading", "## Another Real Heading"]);
});

test("extractHeadings handles tilde fences and longer backtick fences", () => {
  const md = [
    "# H",
    "~~~",
    "# not a heading",
    "~~~",
    "````",
    "# also not a heading",
    "````",
    "## H2",
  ].join("\n");
  assert.deepEqual(extractHeadings(md), ["# H", "## H2"]);
});

test("stripFencedCode leaves an unterminated fence closed rather than leaking its body", () => {
  const md = ["# H", "```", "# swallowed", "still swallowed"].join("\n");
  assert.deepEqual(extractHeadings(md), ["# H"]);
  assert.ok(!stripFencedCode(md).includes("swallowed"));
});

test("extractCodeBlocks returns block bodies in order", () => {
  const md = ["```bash", "one", "```", "text", "```js", "two", "```"].join("\n");
  assert.deepEqual(extractCodeBlocks(md), ["one", "two"]);
});

// ── REGRESSION: the real documents must pass ───────────────────────────────
// The original checker reported "source has 33 headings, regenerated has 30"
// on these exact files, blocking every commit that staged CLAUDE.md. If this
// test ever fails again, the checker is rejecting reality, not catching drift.

test("REGRESSION: real CLAUDE.md yields no phantom headings from code fences", async () => {
  const claudeMd = await readFile(path.join(repoRoot(), "CLAUDE.md"), "utf8");
  const headings = extractHeadings(claudeMd);
  const phantom = headings.filter((h) =>
    /^#\s*(Regenerate SSMF|Keep the embedded-Postgres|Desktop app|Rust$|Frontend$)/.test(h),
  );
  assert.deepEqual(phantom, [], `shell comments leaked in as headings: ${JSON.stringify(phantom)}`);
  assert.ok(headings.every((h) => /^#{1,6}\s/.test(h)));
});

test("REGRESSION: CLAUDE.md is structurally self-consistent (a doc always matches itself)", async () => {
  const claudeMd = await readFile(path.join(repoRoot(), "CLAUDE.md"), "utf8");
  assert.deepEqual(checkStructuralParity(claudeMd, claudeMd), { ok: true });
});

// ── parity semantics ───────────────────────────────────────────────────────

test("checkStructuralParity accepts identical heading structure", () => {
  const md = "# Title\n\ntext\n\n## A\n\n## B\n";
  assert.deepEqual(checkStructuralParity(md, md), { ok: true });
});

test("checkStructuralParity accepts a title override", () => {
  const source = "# CLAUDE.md\n\n## A\n";
  const regenerated = "# AGENTS.md\n\n## A\n";
  assert.deepEqual(checkStructuralParity(source, regenerated, { titleOverride: "# AGENTS.md" }), {
    ok: true,
  });
});

test("checkStructuralParity rejects a dropped section (truncated response)", () => {
  const result = checkStructuralParity("# T\n\n## A\n\n## B\n\n## C\n", "# T\n\n## A\n\n## B\n");
  assert.equal(result.ok, false);
  assert.match(result.reason, /heading count mismatch/);
});

test("checkStructuralParity rejects reordered sections", () => {
  const result = checkStructuralParity("# T\n\n## A\n\n## B\n", "# T\n\n## B\n\n## A\n");
  assert.equal(result.ok, false);
  assert.match(result.reason, /differs/);
});

test("checkStructuralParity rejects a wrong heading depth (## vs ###)", () => {
  assert.equal(checkStructuralParity("# T\n\n## A\n", "# T\n\n### A\n").ok, false);
});

// These are the failure modes heading-only comparison could not see. Most of
// CLAUDE.md's load-bearing content (Critical Invariants, the gates table) is
// bullets and rows under a single heading each.

test("checkStructuralParity rejects a dropped invariant bullet", () => {
  const source = "# T\n\n## Critical Invariants\n\n- one\n- two\n- three\n";
  const dropped = "# T\n\n## Critical Invariants\n\n- one\n- two\n";
  const result = checkStructuralParity(source, dropped);
  assert.equal(result.ok, false);
  assert.match(result.reason, /bullet count mismatch under "## Critical Invariants"/);
});

test("checkStructuralParity rejects a gutted table", () => {
  const source = "# T\n\n## Gates\n\n| a | b |\n| --- | --- |\n| 1 | 2 |\n| 3 | 4 |\n";
  const gutted = "# T\n\n## Gates\n\n| a | b |\n| --- | --- |\n| 1 | 2 |\n";
  const result = checkStructuralParity(source, gutted);
  assert.equal(result.ok, false);
  assert.match(result.reason, /table-row count mismatch/);
});

test("checkStructuralParity rejects a deleted code block", () => {
  const source = "# T\n\n## A\n\n```bash\ncargo test\n```\n\n```bash\ncargo build\n```\n";
  const deleted = "# T\n\n## A\n\n```bash\ncargo test\n```\n";
  const result = checkStructuralParity(source, deleted);
  assert.equal(result.ok, false);
  assert.match(result.reason, /code-block count mismatch/);
});

test("checkStructuralParity allows a legitimately different command inside a code block", () => {
  // AGENTS.md exists precisely so some commands can differ for Codex; block
  // COUNT is asserted, block CONTENT deliberately is not.
  const source = "# CLAUDE.md\n\n## Commands\n\n```bash\ncargo test --workspace\n```\n";
  const variant = "# AGENTS.md\n\n## Commands\n\n```bash\ncargo nextest run --workspace\n```\n";
  assert.deepEqual(checkStructuralParity(source, variant, { titleOverride: "# AGENTS.md" }), {
    ok: true,
  });
});
