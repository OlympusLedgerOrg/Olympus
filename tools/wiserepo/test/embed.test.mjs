// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { embedTexts, cosineSimilarity } from "../src/embed.mjs";
import { ModelUnavailableError, ModelRequestError } from "../src/backend.mjs";

// embed.mjs's HTTP-calling logic (embedBatch, internal to embedTexts) is
// tested here via a stubbed global.fetch -- the same approach backend.mjs's
// error-classification tests use, and for the same reason: it exercises the
// real request/response/error-handling code path without needing a live
// OPENAI_API_KEY or a real network call, which this environment does not
// have available to test against.

test("cosineSimilarity: identical, orthogonal, opposite, zero-vector cases", () => {
  assert.equal(cosineSimilarity([1, 0, 0], [1, 0, 0]), 1);
  assert.equal(cosineSimilarity([1, 0, 0], [0, 1, 0]), 0);
  assert.equal(cosineSimilarity([1, 0, 0], [-1, 0, 0]), -1);
  assert.equal(cosineSimilarity([0, 0, 0], [1, 1, 1]), 0);
});

test("embedTexts throws ModelUnavailableError when no API key is available", async () => {
  const originalKey = process.env.OPENAI_API_KEY;
  delete process.env.OPENAI_API_KEY;
  try {
    await assert.rejects(() => embedTexts(["hello"]), ModelUnavailableError);
  } finally {
    if (originalKey !== undefined) process.env.OPENAI_API_KEY = originalKey;
  }
});

test("embedTexts returns vectors in input order, using a stubbed fetch", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () =>
    new Response(
      JSON.stringify({
        data: [
          { index: 1, embedding: [0, 1] },
          { index: 0, embedding: [1, 0] },
        ],
      }),
      { status: 200 },
    );
  try {
    const vectors = await embedTexts(["first", "second"], { apiKey: "test-key" });
    assert.deepEqual(vectors, [
      [1, 0],
      [0, 1],
    ]);
  } finally {
    global.fetch = originalFetch;
  }
});

test("embedTexts classifies a 401 as ModelUnavailableError (non-blocking)", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => new Response("invalid api key", { status: 401 });
  try {
    await assert.rejects(() => embedTexts(["x"], { apiKey: "test-key" }), ModelUnavailableError);
  } finally {
    global.fetch = originalFetch;
  }
});

test("embedTexts classifies a 400 as ModelRequestError (blocking)", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => new Response("bad request", { status: 400 });
  try {
    await assert.rejects(() => embedTexts(["x"], { apiKey: "test-key" }), ModelRequestError);
  } finally {
    global.fetch = originalFetch;
  }
});

test("embedTexts redacts the API key from an error message", async () => {
  const secretKey = "sk-test-secret-value";
  const originalFetch = global.fetch;
  global.fetch = async () => new Response(`auth failed for key ${secretKey}`, { status: 401 });
  try {
    await assert.rejects(
      () => embedTexts(["x"], { apiKey: secretKey }),
      (err) => !err.message.includes(secretKey),
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test("embedTexts rejects when the API returns a mismatched result count", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () =>
    new Response(JSON.stringify({ data: [{ index: 0, embedding: [1] }] }), { status: 200 });
  try {
    await assert.rejects(
      () => embedTexts(["a", "b"], { apiKey: "test-key" }),
      ModelUnavailableError,
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test("embedTexts batches large inputs and reports progress", async () => {
  const originalFetch = global.fetch;
  let callCount = 0;
  global.fetch = async (url, options) => {
    callCount++;
    const body = JSON.parse(options.body);
    return new Response(
      JSON.stringify({ data: body.input.map((_, i) => ({ index: i, embedding: [i] })) }),
      { status: 200 },
    );
  };
  try {
    const texts = Array.from({ length: 130 }, (_, i) => `text ${i}`);
    const progressCalls = [];
    const vectors = await embedTexts(texts, {
      apiKey: "test-key",
      onProgress: (done, total) => progressCalls.push([done, total]),
    });
    assert.equal(vectors.length, 130);
    // 130 inputs at batch size 64 -> 3 requests (64, 64, 2).
    assert.equal(callCount, 3);
    assert.deepEqual(progressCalls, [
      [64, 130],
      [128, 130],
      [130, 130],
    ]);
  } finally {
    global.fetch = originalFetch;
  }
});
