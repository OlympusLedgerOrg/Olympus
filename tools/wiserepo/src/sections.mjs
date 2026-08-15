// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Structural-parity checks used to verify a regenerated doc didn't silently
// drop or alter content.
//
// This exists because the regenerated file is a *security-relevant document*:
// AGENTS.md carries the same critical invariants and upstream-boundary policy
// as CLAUDE.md, so a model that quietly drops a bullet or deletes a table
// produces a file that reads as authoritative while being incomplete. Heading
// comparison alone is nowhere near sufficient for that — most of CLAUDE.md's
// load-bearing content lives in flat bullet lists and one table under a
// single heading each. So we compare four independent structural signals,
// and every one of them must hold.
//
// What this deliberately does NOT catch: a bullet whose CONTENT is reworded
// or inverted while the count stays the same — "shard creation is operator-
// controlled" silently becoming "shard creation is open" would pass every
// signal here, because nothing here reads prose. That is a real, known gap,
// not an oversight: these are STRUCTURAL signals (counts and headings), and
// a regenerated AGENTS.md should be read, not blindly trusted. See the
// caveat in the repo README.

/**
 * Strip fenced code blocks, replacing each with a placeholder line so line
 * structure is preserved.
 *
 * This is load-bearing, not cosmetic: CLAUDE.md's ```bash blocks are full of
 * `# shell comments`, and a naive line-wise heading regex counts every one of
 * them as a Markdown heading. That made the original version of this checker
 * reject the repo's own correct docs 100% of the time (33 "headings" in
 * CLAUDE.md vs 30 in AGENTS.md, the difference being comment text).
 */
export function stripFencedCode(markdown) {
  const lines = markdown.split("\n");
  const out = [];
  let fence = null; // the exact opening fence marker (``` or ~~~, possibly longer)
  for (const line of lines) {
    const m = /^\s*(`{3,}|~{3,})/.exec(line);
    if (fence === null && m) {
      fence = m[1][0].repeat(m[1].length);
      out.push("<<CODE_FENCE>>");
      continue;
    }
    if (fence !== null) {
      // A closing fence must be the same char and at least as long.
      const close = /^\s*(`{3,}|~{3,})\s*$/.exec(line);
      if (close && close[1][0] === fence[0] && close[1].length >= fence.length) {
        fence = null;
      }
      continue;
    }
    out.push(line);
  }
  return out.join("\n");
}

/** Every fenced code block's raw content, in document order. */
export function extractCodeBlocks(markdown) {
  const lines = markdown.split("\n");
  const blocks = [];
  let fence = null;
  let current = [];
  for (const line of lines) {
    const m = /^\s*(`{3,}|~{3,})/.exec(line);
    if (fence === null && m) {
      fence = m[1][0].repeat(m[1].length);
      current = [];
      continue;
    }
    if (fence !== null) {
      const close = /^\s*(`{3,}|~{3,})\s*$/.exec(line);
      if (close && close[1][0] === fence[0] && close[1].length >= fence.length) {
        blocks.push(current.join("\n").trim());
        fence = null;
        continue;
      }
      current.push(line);
    }
  }
  return blocks;
}

/** @returns {string[]} heading lines, verbatim, with fenced code excluded. */
export function extractHeadings(markdown) {
  return stripFencedCode(markdown)
    .split("\n")
    .filter((line) => /^#{1,6}\s+\S/.test(line))
    .map((line) => line.trim());
}

/**
 * Per-section counts of the content that lives *under* each heading.
 *
 * CLAUDE.md's `## Critical Invariants` is a flat bullet list with no
 * subheadings; its `## Before every git push` carries a table. Heading
 * comparison sees both as a single unit, so dropping an invariant or gutting
 * the table is invisible without this.
 *
 * @returns {Array<{heading: string, bullets: number, tableRows: number}>}
 */
export function sectionContentCounts(markdown) {
  const lines = stripFencedCode(markdown).split("\n");
  const sections = [];
  let current = { heading: "(preamble)", bullets: 0, tableRows: 0 };
  for (const line of lines) {
    if (/^#{1,6}\s+\S/.test(line)) {
      sections.push(current);
      current = { heading: line.trim(), bullets: 0, tableRows: 0 };
      continue;
    }
    if (/^\s*([-*+]|\d+\.)\s+\S/.test(line)) current.bullets++;
    // A table row: starts and ends with | and isn't the --- separator.
    else if (/^\s*\|.*\|\s*$/.test(line) && !/^\s*\|[\s|:-]*\|\s*$/.test(line)) current.tableRows++;
  }
  sections.push(current);
  return sections;
}

/**
 * Compares structure between a source doc and its regenerated counterpart.
 * The counterpart may substitute an expected title line but must otherwise
 * preserve headings, per-section bullet/table counts, and code-block count.
 *
 * Code-block *content* is deliberately NOT required to match verbatim: the
 * whole point of AGENTS.md is that a few commands legitimately differ for
 * Codex. We assert the count instead, so a wholesale deletion is caught while
 * an intentional command variant is allowed. Callers wanting stricter
 * treatment should diff the blocks themselves.
 *
 * @param {string} sourceMarkdown
 * @param {string} regeneratedMarkdown
 * @param {{ titleOverride?: string }} [opts]
 * @returns {{ ok: true } | { ok: false, reason: string }}
 */
export function checkStructuralParity(sourceMarkdown, regeneratedMarkdown, opts = {}) {
  const sourceHeadings = extractHeadings(sourceMarkdown);
  const newHeadings = extractHeadings(regeneratedMarkdown);

  const expected = opts.titleOverride
    ? [opts.titleOverride, ...sourceHeadings.slice(1)]
    : sourceHeadings;

  if (newHeadings.length !== expected.length) {
    return {
      ok: false,
      reason: `heading count mismatch: source has ${expected.length} headings, regenerated has ${newHeadings.length}`,
    };
  }

  for (let i = 0; i < expected.length; i++) {
    if (expected[i] !== newHeadings[i]) {
      return {
        ok: false,
        reason: `heading #${i + 1} differs:\n  source:      ${expected[i]}\n  regenerated: ${newHeadings[i]}`,
      };
    }
  }

  const srcBlocks = extractCodeBlocks(sourceMarkdown);
  const newBlocks = extractCodeBlocks(regeneratedMarkdown);
  if (srcBlocks.length !== newBlocks.length) {
    return {
      ok: false,
      reason: `code-block count mismatch: source has ${srcBlocks.length}, regenerated has ${newBlocks.length}`,
    };
  }

  const srcSections = sectionContentCounts(sourceMarkdown);
  const newSections = sectionContentCounts(regeneratedMarkdown);
  if (srcSections.length !== newSections.length) {
    return {
      ok: false,
      reason: `section count mismatch: source has ${srcSections.length}, regenerated has ${newSections.length}`,
    };
  }
  for (let i = 0; i < srcSections.length; i++) {
    const a = srcSections[i];
    const b = newSections[i];
    if (a.bullets !== b.bullets) {
      return {
        ok: false,
        reason:
          `bullet count mismatch under "${a.heading}": source has ${a.bullets}, regenerated has ${b.bullets}. ` +
          `This is how an added or dropped invariant shows up — compare that section by hand. ` +
          `(A reworded bullet at the same count would NOT trigger this — count comparison doesn't read prose.)`,
      };
    }
    if (a.tableRows !== b.tableRows) {
      return {
        ok: false,
        reason: `table-row count mismatch under "${a.heading}": source has ${a.tableRows}, regenerated has ${b.tableRows}`,
      };
    }
  }

  return { ok: true };
}
