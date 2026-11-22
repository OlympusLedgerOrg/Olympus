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

import { readFile, stat } from "node:fs/promises";
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
    if (!(await exists(citation.path))) {
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
      const content = await readFile(await resolveInRepoFollowingSymlinks(citation.path), "utf8");
      if (citation.line < 1 || citation.line > countLines(content)) missing.push(citation);
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
 * Number of addressable lines in `content`.
 *
 * A trailing newline TERMINATES the last line rather than opening an empty
 * one: "a\n" is one line, not two. Counting `split("\n").length` gets this
 * wrong for every newline-terminated file in the repo — which is nearly all of
 * them — and accepts a citation exactly one line past the end.
 */
function countLines(content) {
  if (content === "") return 0;
  const lines = content.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  return lines.length;
}

export function formatMissingCitations(missing) {
  return missing
    .map((citation) => (citation.line ? `${citation.path}:${citation.line}` : citation.path))
    .join(", ");
}
