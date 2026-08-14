// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Embeddings for wiserepo's semantic index. Anthropic has no embeddings API
// (they partner with Voyage AI for it, per their own docs); OpenAI's
// text-embedding-3-small is the practical default here since wiserepo
// already reads OPENAI_API_KEY for the chat backend -- no new credential to
// configure. Swap in Voyage AI later if that's ever worth the extra
// integration; nothing else in wiserepo depends on which provider this is.
//
// This is the one part of wiserepo that sends repo content to a third party
// UNCONDITIONALLY on every index build, not just when you explicitly name a
// file to a tool call -- see the README's trust-boundary section, which
// this module's existence changes materially.

import { ModelUnavailableError, ModelRequestError } from "./backend.mjs";

const OPENAI_EMBEDDINGS_URL = "https://api.openai.com/v1/embeddings";
const EMBEDDING_MODEL = process.env.WISEREPO_EMBEDDING_MODEL || "text-embedding-3-small";
const TIMEOUT_MS = process.env.WISEREPO_TIMEOUT_MS
  ? Number(process.env.WISEREPO_TIMEOUT_MS)
  : 45_000;

// The API accepts a batch of inputs per request; batching cuts round-trips
// but a batch that's too large risks the request itself timing out or
// hitting a token-count limit. 64 is conservative for chunks capped at
// ~4000 chars each.
const BATCH_SIZE = 64;

async function embedBatch(texts, apiKey) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let res;
  try {
    res = await fetch(OPENAI_EMBEDDINGS_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({ model: EMBEDDING_MODEL, input: texts }),
      signal: controller.signal,
    });
  } catch (err) {
    if (err.name === "AbortError") {
      throw new ModelUnavailableError(`embeddings request timed out after ${TIMEOUT_MS}ms`, {
        cause: err,
      });
    }
    throw new ModelUnavailableError(`embeddings request failed: ${err.message}`, { cause: err });
  } finally {
    clearTimeout(timer);
  }

  const body = await res.text();
  if (!res.ok) {
    const redacted = body.split(apiKey).join("[REDACTED]");
    const msg = `OpenAI embeddings API error ${res.status}: ${redacted}`;
    if (res.status === 401 || res.status === 403 || res.status === 429 || res.status >= 500) {
      throw new ModelUnavailableError(
        `${msg}${res.status === 401 || res.status === 403 ? " (check your API key)" : ""}`,
      );
    }
    throw new ModelRequestError(msg);
  }

  let data;
  try {
    data = JSON.parse(body);
  } catch (err) {
    throw new ModelUnavailableError("OpenAI embeddings returned a non-JSON body", { cause: err });
  }

  // The API returns results possibly out of input order but with an
  // `index` field -- sort back into input order so callers can zip the
  // returned vectors against their original texts by position.
  const items = data.data;
  if (!Array.isArray(items) || items.length !== texts.length) {
    throw new ModelUnavailableError(
      `OpenAI embeddings returned ${Array.isArray(items) ? items.length : "no"} vectors for ${texts.length} inputs`,
    );
  }
  const ordered = new Array(texts.length);
  for (const item of items) ordered[item.index] = item.embedding;
  return ordered;
}

/**
 * Embeds an array of texts, batching internally, and returns vectors in the
 * same order as the input.
 * @param {string[]} texts
 * @param {{ apiKey?: string, onProgress?: (done: number, total: number) => void }} [opts]
 * @returns {Promise<number[][]>}
 */
export async function embedTexts(texts, opts = {}) {
  const apiKey = opts.apiKey ?? process.env.OPENAI_API_KEY;
  if (!apiKey) {
    throw new ModelUnavailableError(
      "OPENAI_API_KEY is not set -- required to build or query the semantic index",
    );
  }
  const out = [];
  for (let i = 0; i < texts.length; i += BATCH_SIZE) {
    const batch = texts.slice(i, i + BATCH_SIZE);
    const vectors = await embedBatch(batch, apiKey);
    out.push(...vectors);
    opts.onProgress?.(Math.min(i + BATCH_SIZE, texts.length), texts.length);
  }
  return out;
}

/** Cosine similarity between two equal-length vectors. */
export function cosineSimilarity(a, b) {
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}
