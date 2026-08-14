// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Storage for wiserepo's semantic index: a single JSON file under
// .wiserepo-index/ (gitignored -- regenerable, and not something to commit).
//
// Each entry is keyed by a hash of its own chunk text (not file+line),
// which is what makes re-indexing incremental and cheap: build-index.mjs
// re-chunks every tracked file on each run, but only calls the embeddings
// API for chunks whose hash isn't already in the stored index. Editing one
// function in a large file re-embeds one chunk, not the whole repo.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { repoRoot } from "./repo.mjs";

const INDEX_DIR = ".wiserepo-index";
const INDEX_FILE = "index.json";
const INDEX_VERSION = 1;

export function chunkHash(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function indexPath() {
  return path.join(repoRoot(), INDEX_DIR, INDEX_FILE);
}

/**
 * @returns {Promise<{ version: number, model: string, entries: Record<string, {file: string, startLine: number, endLine: number, text: string, vector: number[]}> }>}
 */
export async function loadIndex() {
  try {
    const raw = await readFile(indexPath(), "utf8");
    const parsed = JSON.parse(raw);
    if (parsed.version !== INDEX_VERSION) {
      // A version bump means the storage shape changed incompatibly --
      // treat as absent rather than guess at a migration, so the next
      // build starts clean instead of crashing on a shape it doesn't
      // understand.
      return { version: INDEX_VERSION, model: null, entries: {} };
    }
    return parsed;
  } catch (err) {
    if (err.code === "ENOENT") {
      return { version: INDEX_VERSION, model: null, entries: {} };
    }
    throw err;
  }
}

export async function saveIndex(index) {
  const dir = path.join(repoRoot(), INDEX_DIR);
  await mkdir(dir, { recursive: true });
  await writeFile(indexPath(), JSON.stringify(index), "utf8");
}

export function indexExists(index) {
  return index.entries && Object.keys(index.entries).length > 0;
}
