#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// wiserepo: build/refresh the semantic index used for repo_qa's search.
//
// Manual only, by design -- this makes a real, metered API call (OpenAI
// embeddings) for every NEW or CHANGED chunk, so it runs only when you
// choose to run it: `node bin/build-index.mjs`. It is not wired into the
// pre-commit hook, CI, or any schedule. Re-run it whenever you want
// repo_qa's search to reflect recent changes.
//
// Incremental: chunks are keyed by a hash of their own text
// (src/index-store.mjs), so an unchanged function costs nothing on a
// re-run -- only chunks whose content actually changed get re-embedded.
//
// Usage: node bin/build-index.mjs [--dry-run]

import { readFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { repoRoot } from "../src/repo.mjs";
import { chunkFile } from "../src/chunk.mjs";
import { embedTexts } from "../src/embed.mjs";
import { loadIndex, saveIndex, chunkHash } from "../src/index-store.mjs";

const execFileAsync = promisify(execFile);

const dryRun = process.argv.includes("--dry-run");

// Same source-code extensions the chunker has boundary heuristics for, plus
// a couple of plain-text config/doc formats worth being searchable. Not an
// exhaustive "index everything tracked" -- generated artifacts, binary
// files, and lockfiles would just waste embedding budget on content nobody
// asks wiserepo questions about.
const INDEXABLE_EXT = /\.(rs|mjs|cjs|js|jsx|ts|tsx|md|toml|yml|yaml)$/;

// Vendored/patched upstream trees this repo already excludes from its own
// formatting and review tooling (see .prettierignore's "Vendored or patched
// upstream trees" section) -- third-party code nobody is asking wiserepo
// questions about, and indexing it would burn a large share of the
// embedding budget on text this repo doesn't own.
const EXCLUDE_DIR_RE =
  /^(crates\/glib-[^/]+-patched|crates\/ppv-lite86-patched|pg-embed-local|proofs\/vendor)\//;

async function listTrackedFiles() {
  const { stdout } = await execFileAsync("git", ["ls-files"], {
    cwd: repoRoot(),
    maxBuffer: 20 * 1024 * 1024,
  });
  return stdout
    .split("\n")
    .filter(Boolean)
    .filter((f) => INDEXABLE_EXT.test(f))
    .filter((f) => !EXCLUDE_DIR_RE.test(f));
}

async function main() {
  const index = await loadIndex();
  const files = await listTrackedFiles();

  const seenFile = new Map(); // relPath -> [chunkHash, ...] to prune stale entries after the loop
  const toEmbed = []; // [{ key, file, startLine, endLine, text }]
  // Chunks are keyed by content hash, and identical content genuinely
  // recurs (a shared boilerplate block, two files that happen to share a
  // one-line re-export). index.entries only gains a key once that chunk is
  // actually embedded, which hasn't happened yet mid-scan -- so checking
  // `!index.entries[key]` alone let the SAME new chunk get queued twice
  // (once per file it appeared in), double-embedding it and inflating the
  // "new/changed" count past the actual total chunk count. This set tracks
  // what's already been queued THIS run, independent of index.entries.
  const queuedThisRun = new Set();

  for (const relPath of files) {
    let content;
    try {
      content = await readFile(path.join(repoRoot(), relPath), "utf8");
    } catch {
      continue; // binary/unreadable-as-utf8 file that slipped through the extension filter
    }
    const chunks = chunkFile(relPath, content);
    const hashes = [];
    for (const chunk of chunks) {
      const key = chunkHash(chunk.text);
      hashes.push(key);
      if (!index.entries[key] && !queuedThisRun.has(key)) {
        queuedThisRun.add(key);
        toEmbed.push({
          key,
          file: relPath,
          startLine: chunk.startLine,
          endLine: chunk.endLine,
          text: chunk.text,
        });
      }
    }
    seenFile.set(relPath, hashes);
  }

  // Prune entries for chunks that no longer exist -- a deleted file, a
  // renamed one, or a function that was edited enough to change its hash.
  // Without this the index only ever grows and eventually returns search
  // results pointing at code that isn't there anymore.
  const liveKeys = new Set();
  for (const hashes of seenFile.values()) for (const h of hashes) liveKeys.add(h);
  let prunedCount = 0;
  for (const key of Object.keys(index.entries)) {
    if (!liveKeys.has(key)) {
      delete index.entries[key];
      prunedCount++;
    }
  }

  console.log(
    `[wiserepo] ${files.length} files scanned, ${liveKeys.size} chunks total, ` +
      `${toEmbed.length} new/changed, ${prunedCount} stale entries pruned.`,
  );

  if (dryRun) {
    console.log("[wiserepo] --dry-run: not calling the embeddings API or writing the index.");
    return;
  }

  if (toEmbed.length > 0) {
    let done = 0;
    const vectors = await embedTexts(
      toEmbed.map((c) => c.text),
      {
        onProgress: (d, total) => {
          if (d !== done) {
            done = d;
            process.stdout.write(`\r[wiserepo] embedding ${d}/${total}...`);
          }
        },
      },
    );
    process.stdout.write("\n");
    for (let i = 0; i < toEmbed.length; i++) {
      const c = toEmbed[i];
      index.entries[c.key] = {
        file: c.file,
        startLine: c.startLine,
        endLine: c.endLine,
        text: c.text,
        vector: vectors[i],
      };
    }
    index.model = process.env.WISEREPO_EMBEDDING_MODEL || "text-embedding-3-small";
  }

  await saveIndex(index);
  console.log(`[wiserepo] index saved: ${Object.keys(index.entries).length} chunks.`);
}

main().catch((err) => {
  console.error(`[wiserepo] build-index failed: ${err.stack || err.message}`);
  process.exit(1);
});
