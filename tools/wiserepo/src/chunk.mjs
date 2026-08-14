// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Splits file content into chunks for embedding. Boundary-aware, not
// fixed-size windows: a fixed-size split cuts a function in half as often
// as not, which both wastes embedding budget (two half-functions embed
// worse than one whole one) and produces search results that land you
// mid-function with no idea what it's part of.
//
// Deliberately simple regex-based boundary detection, not a real parser --
// this only needs to be right often enough that search results are useful,
// not perfectly correct. A chunk that's slightly mis-bounded still embeds
// and searches fine; it just isn't as tidy to read.

const MAX_CHUNK_CHARS = 4000; // keeps a single embedding call's input small and each result readable
const MIN_CHUNK_CHARS = 40; // below this, MERGE into a neighbor rather than drop -- see mergeSmallChunks

// Rust: split before top-level `fn`/`impl`/`struct`/`enum`/`trait`/`mod`.
// Deliberately anchored at column 0 (no leading whitespace) so nested items
// inside an impl block don't each become their own chunk -- the outer impl
// block is the more useful unit to search and read.
const RUST_BOUNDARY_RE =
  /^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(fn|impl|struct|enum|trait|mod)\s/;

// JS/TS: split before top-level function/class/export declarations.
const JS_BOUNDARY_RE =
  /^(?:export\s+)?(?:default\s+)?(?:async\s+)?(function|class)\s|^export\s+(?:const|let)\s+\w+\s*=\s*(?:async\s*)?\(/;

// Markdown: split at any heading.
const MD_BOUNDARY_RE = /^#{1,6}\s+\S/;

function boundaryRegexFor(relPath) {
  if (/\.rs$/.test(relPath)) return RUST_BOUNDARY_RE;
  if (/\.(mjs|cjs|js|jsx|ts|tsx)$/.test(relPath)) return JS_BOUNDARY_RE;
  if (/\.md$/.test(relPath)) return MD_BOUNDARY_RE;
  return null;
}

/**
 * @param {string} relPath repo-relative path, used only to pick a boundary heuristic
 * @param {string} text file content
 * @returns {Array<{startLine: number, endLine: number, text: string}>}
 */
export function chunkFile(relPath, text) {
  const lines = text.split("\n");
  const boundaryRe = boundaryRegexFor(relPath);

  if (!boundaryRe) {
    return mergeSmallChunks(fixedSizeChunks(lines));
  }

  const boundaries = [0];
  for (let i = 1; i < lines.length; i++) {
    if (boundaryRe.test(lines[i])) boundaries.push(i);
  }
  boundaries.push(lines.length);

  const rawChunks = [];
  for (let i = 0; i < boundaries.length - 1; i++) {
    const start = boundaries[i];
    const end = boundaries[i + 1];
    const body = lines.slice(start, end).join("\n");
    // A boundary-delimited section can still be huge (a long impl block) or
    // tiny (a one-line re-export between two boundaries) -- re-chunk the
    // oversized case by size; the tiny case is handled by mergeSmallChunks
    // below, not dropped.
    if (body.length > MAX_CHUNK_CHARS) {
      for (const sub of fixedSizeChunks(lines.slice(start, end), start)) rawChunks.push(sub);
    } else if (body.trim().length > 0) {
      // Whitespace-only sections (a run of blank lines between two
      // boundaries) ARE genuine noise -- nothing to merge, nothing lost by
      // dropping them.
      rawChunks.push({ startLine: start + 1, endLine: end, text: body });
    }
  }
  return mergeSmallChunks(rawChunks);
}

// Merges a chunk under MIN_CHUNK_CHARS into a neighbor instead of dropping
// it. This exists because dropping outright was the actual bug in an
// earlier version: a short function, a short heading section, or any other
// real-but-brief unit of content was silently excluded from the index --
// which for a search index means "this code doesn't exist" from the
// caller's perspective. Merging into the previous chunk (or, for a small
// leading chunk with nothing before it, the next one) keeps every real
// character searchable; only whitespace-only sections are ever discarded,
// and that happens before this function is called.
function mergeSmallChunks(chunks) {
  if (chunks.length === 0) return [];
  const merged = [];
  for (const chunk of chunks) {
    const prev = merged[merged.length - 1];
    if (prev && chunk.text.trim().length < MIN_CHUNK_CHARS) {
      prev.text += "\n" + chunk.text;
      prev.endLine = chunk.endLine;
    } else {
      merged.push({ ...chunk });
    }
  }
  if (merged.length > 1 && merged[0].text.trim().length < MIN_CHUNK_CHARS) {
    merged[1].text = merged[0].text + "\n" + merged[1].text;
    merged[1].startLine = merged[0].startLine;
    merged.shift();
  }
  return merged;
}

function fixedSizeChunks(lines, lineOffset = 0) {
  const chunks = [];
  let start = 0;
  let charCount = 0;
  for (let i = 0; i < lines.length; i++) {
    charCount += lines[i].length + 1;
    if (charCount >= MAX_CHUNK_CHARS) {
      chunks.push({
        startLine: lineOffset + start + 1,
        endLine: lineOffset + i + 1,
        text: lines.slice(start, i + 1).join("\n"),
      });
      start = i + 1;
      charCount = 0;
    }
  }
  if (start < lines.length) {
    chunks.push({
      startLine: lineOffset + start + 1,
      endLine: lineOffset + lines.length,
      text: lines.slice(start).join("\n"),
    });
  }
  return chunks.filter((c) => c.text.trim().length > 0);
}
