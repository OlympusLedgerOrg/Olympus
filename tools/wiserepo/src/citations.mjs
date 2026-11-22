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

import { stat } from "node:fs/promises";
import path from "node:path";
import { repoRoot } from "./repo.mjs";

// Extensions worth checking. Kept narrow on purpose: matching arbitrary
// "a/b" tokens would flag prose like "and/or" and train people to ignore the
// warning, which is worse than not warning at all.
const CITE_EXTENSIONS =
  "rs|ts|tsx|js|mjs|cjs|json|md|toml|ya?ml|sql|sh|ps1|py|circom|css|html|lock";

// A path is one or more `dir/` segments followed by `name.ext`, optionally
// followed by `:line`. Requires the slash and a known extension so bare words
// never match.
const CITATION_RE = new RegExp(
  `((?:[\\w.-]+/)+[\\w.-]+\\.(?:${CITE_EXTENSIONS}))(?::(\\d+))?`,
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
    if (!(await exists(citation.path))) missing.push(citation);
  }
  return { checked: citations.length, missing };
}

export function formatMissingCitations(missing) {
  return missing
    .map((citation) => (citation.line ? `${citation.path}:${citation.line}` : citation.path))
    .join(", ");
}
