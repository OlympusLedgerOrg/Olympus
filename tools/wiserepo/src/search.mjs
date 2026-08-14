// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { cosineSimilarity, embedTexts } from "./embed.mjs";
import { loadIndex, indexExists } from "./index-store.mjs";

/**
 * Ranks index entries by cosine similarity to a query vector.
 * @param {number[]} queryVector
 * @param {Record<string, {file: string, startLine: number, endLine: number, text: string, vector: number[]}>} entries
 * @param {number} topK
 * @returns {Array<{file: string, startLine: number, endLine: number, text: string, score: number}>}
 */
export function searchIndex(queryVector, entries, topK = 8) {
  const scored = [];
  for (const entry of Object.values(entries)) {
    scored.push({
      file: entry.file,
      startLine: entry.startLine,
      endLine: entry.endLine,
      text: entry.text,
      score: cosineSimilarity(queryVector, entry.vector),
    });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, topK);
}

/**
 * Full semantic-search flow for a natural-language query: load the on-disk
 * index, embed the query, rank chunks by similarity. Returns `null` (not a
 * thrown error) when there's no index to search yet -- callers treat "no
 * index built" as "fall back to grep/explicit files", not as a failure.
 * A missing OPENAI_API_KEY or a network error while embedding the query
 * DOES throw (from embedTexts) -- that's a real failure the caller should
 * decide how to handle, distinct from "you haven't run build-index.mjs yet".
 *
 * @param {string} query
 * @param {{ topK?: number }} [opts]
 * @returns {Promise<null | Array<{file: string, startLine: number, endLine: number, text: string, score: number}>>}
 */
export async function semanticSearch(query, opts = {}) {
  const index = await loadIndex();
  if (!indexExists(index)) return null;
  const [queryVector] = await embedTexts([query]);
  return searchIndex(queryVector, index.entries, opts.topK ?? 8);
}
