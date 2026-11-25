// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Verify the file paths a model cites actually exist.
//
// The system prompt asks for file paths and line numbers, and a small local
// model produces them confidently whether or not it saw the file. In a repo
// whose entire thesis is verifiable claims, a fabricated citation in a review
// is the worst failure mode available: it reads as evidence and is not.
// A path that does not resolve is reported, not rewritten — the answer is still
// returned, with the unverified citations named so a human knows what to check.

import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import path from "node:path";
import { repoRoot, resolveInRepoFollowingSymlinks } from "./repo.mjs";

// Extensions worth checking. Kept narrow on purpose: matching arbitrary
// "a/b" tokens would flag prose like "and/or" and train people to ignore the
// warning, which is worse than not warning at all.
// Sorted longest-first, and that is load-bearing, not cosmetic: JavaScript
// regex alternation takes the FIRST branch that matches, so listing `js` before
// `json` makes "a/b/package.json:12" parse as the path "a/b/package.js" with no
// line at all — silently dropping the line check for every .json citation, and
// doing the same to .tsx via `ts`. The trailing (?!\w) in CITATION_RE close the
// remaining gap where a shorter extension could still prefix a longer one.
const CITE_EXTENSIONS = "rs|ts|tsx|js|mjs|cjs|json|md|toml|ya?ml|sql|sh|ps1|py|circom|css|html|lock"
  .split("|")
  .sort((a, b) => b.length - a.length)
  .join("|");

// A path is one or more `dir/` segments followed by `name.ext`, optionally
// followed by `:line`. Requires the slash and a known extension so bare words
// never match.
const CITATION_RE = new RegExp(
  `((?:[\\w.-]+/)+[\\w.-]+\\.(?:${CITE_EXTENSIONS}))(?!\\w)(?::(\\d+))?`,
  "gi",
);

/**
 * Extract the file citations from a block of model output.
 * @returns {{ path: string, line: number | null }[]} de-duplicated, in order
 */
export function extractCitations(text) {
  if (typeof text !== "string") return [];
  const seen = new Set();
  const found = [];
  for (const match of text.matchAll(CITATION_RE)) {
    const cited = match[1].replace(/^\.\//, "");
    const line = match[2] ? Number(match[2]) : null;
    const key = `${cited}:${line ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    found.push({ path: cited, line });
  }
  return found;
}

// git writes every unified diff header as `a/<path>` and `b/<path>`, so a review
// that quotes a header is naming the file on disk, not a directory called `a`.
// Tried only after the literal path fails, so a repo with a real `a/` still wins.
const DIFF_HEADER_PREFIX = /^[ab]\//;

// A review that says "add a regression test in `src/pager.test.js`" is proposing
// a file, not citing evidence of one: the path is meant NOT to exist, so scoring
// it as invented punishes the recommendation. Decided per SENTENCE — a sentence
// that asserts a file exists carries no proposal language — rather than by
// distance to a marker, which needed two windows and still broke at a clause.
const PROPOSAL_RE =
  /\b(add|adds|adding|needs?|missing|lacks?|untested|creates?|creating|propos\w*|suggest\w*|consider\w*|should|would|could)\b|no tests?\b|no coverage\b|does\s?not\s?exist|doesn'?t\s?exist|not\s?present/i;

const sentencesOf = (text) => String(text ?? "").split(/(?<=[.!?])\s+|\n+/);

function isProposedCitation(text, citation) {
  const needle = citation.path.toLowerCase();
  return sentencesOf(text).some(
    (sentence) => sentence.toLowerCase().includes(needle) && PROPOSAL_RE.test(sentence),
  );
}

async function existsInRepo(relPath) {
  const root = repoRoot();
  const resolved = path.resolve(root, relPath);
  // A cited path that escapes the repo is not a repo file, full stop — no
  // realpath needed because we never read it, only report on it.
  if (resolved !== root && !resolved.startsWith(root + path.sep)) return false;
  try {
    const info = await stat(resolved);
    return info.isFile();
  } catch {
    return false;
  }
}

/**
 * Check every citation in `text` against the working tree.
 * @returns {Promise<{ checked: number, missing: { path: string, line: number | null }[] }>}
 */
export async function verifyCitations(text, { exists = existsInRepo } = {}) {
  const citations = extractCitations(text);
  const missing = [];
  for (const citation of citations) {
    let target = null;
    if (await exists(citation.path)) target = citation.path;
    else {
      const stripped = DIFF_HEADER_PREFIX.test(citation.path)
        ? citation.path.replace(DIFF_HEADER_PREFIX, "")
        : null;
      if (stripped && (await exists(stripped))) target = stripped;
    }
    if (target === null) {
      // Two honest ways a path can legitimately not exist: it was quoted from a
      // diff header (handled above), or the review is proposing it. Everything
      // else is a fabricated citation and is reported.
      if (isProposedCitation(text, citation)) continue;
      missing.push(citation);
      continue;
    }
    if (citation.line === null) continue;
    try {
      // existsInRepo above is LEXICAL, and it never reads. This branch does
      // read, so it must re-confine after resolving symlinks (see
      // resolveInRepo's comment in repo.mjs): a repo-tracked symlink can sit
      // lexically inside the tree while pointing at a file outside it, and
      // following it here would pull bytes we never meant to touch just to
      // count their lines. It also rejects a path that escapes the root.
      const resolved = await resolveInRepoFollowingSymlinks(target);
      if (!(await hasLine(resolved, citation.line))) missing.push(citation);
    } catch {
      // Unreadable (dangling symlink, permissions, a directory, invalid UTF-8
      // path) means the cited line cannot be confirmed, so the citation is
      // reported rather than quietly accepted.
      missing.push(citation);
    }
  }
  return { checked: citations.length, missing };
}

/**
 * Whether the file at `absPath` has an addressable line `line`.
 *
 * Streamed, not buffered: the previous version read the whole file to count
 * lines, so a citation naming a very large tracked file (a lockfile, a fixture)
 * allocated it in full just to answer a question about one line number. This
 * counts 0x0A bytes — never part of a multi-byte UTF-8 sequence, so no decoding
 * is needed — and returns the moment the cited line starts, so memory stays
 * constant and the usual case costs only the prefix up to that line. Worst case
 * still scans the file once, at the same order as the old stat+read.
 *
 * Line semantics: a trailing newline TERMINATES the last line rather than
 * opening an empty one, so "a\n" has one line, not two. Counting newlines and
 * treating a final unterminated segment as a line is what keeps a citation one
 * past the end of a newline-terminated file from being accepted.
 *
 * Exported for the bounded-read test; callers should go through
 * verifyCitations, which also enforces repo confinement.
 */
export async function hasLine(absPath, line) {
  if (line < 1) return false;
  let newlines = 0;
  let bytes = 0;
  let lastByte = -1;
  const stream = createReadStream(absPath);
  try {
    for await (const chunk of stream) {
      bytes += chunk.length;
      for (let i = 0; i < chunk.length; i++) {
        if (chunk[i] !== 0x0a) continue;
        newlines += 1;
        // `line` newlines seen means line `line` has begun; the rest of the
        // file cannot change that answer.
        if (newlines >= line) return true;
      }
      lastByte = chunk[chunk.length - 1];
    }
  } finally {
    stream.destroy();
  }
  // An empty file has no addressable line, matching a zero-line count rather
  // than reporting its single empty segment as line 1.
  if (bytes === 0) return false;
  return lastByte !== 0x0a && line === newlines + 1;
}

export function formatMissingCitations(missing) {
  return missing
    .map((citation) => (citation.line ? `${citation.path}:${citation.line}` : citation.path))
    .join(", ");
}
