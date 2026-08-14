// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ModelUnavailableError,
  ModelRequestError,
  classifyHttpFailure,
  isRestrictedOpenAiModel,
  resolveBackend,
} from "../src/backend.mjs";

// The exit-code contract in bin/sync-agent-docs.mjs rests entirely on this
// classification: "unavailable" must never block a commit, "request error"
// always must. Getting it backwards either hides a broken config behind a
// green build, or blocks commits on a transient network blip.

test("auth failures classify as unavailable (non-blocking)", () => {
  for (const status of [401, 403]) {
    assert.ok(classifyHttpFailure(status, "nope", "Anthropic") instanceof ModelUnavailableError);
  }
});

test("rate limiting classifies as unavailable (non-blocking)", () => {
  assert.ok(classifyHttpFailure(429, "slow down", "OpenAI") instanceof ModelUnavailableError);
});

test("server errors classify as unavailable (non-blocking)", () => {
  for (const status of [500, 502, 503]) {
    assert.ok(classifyHttpFailure(status, "boom", "Anthropic") instanceof ModelUnavailableError);
  }
});

test("client request errors classify as blocking bugs", () => {
  for (const status of [400, 404, 422]) {
    assert.ok(classifyHttpFailure(status, "bad request", "OpenAI") instanceof ModelRequestError);
  }
});

test("classified errors carry the provider, status and body for debugging", () => {
  const err = classifyHttpFailure(400, "unknown_parameter: max_tokens", "OpenAI");
  assert.match(err.message, /OpenAI API error 400/);
  assert.match(err.message, /unknown_parameter/);
});

test("classified errors never contain an API key", () => {
  // Guard against a future refactor interpolating credentials into messages.
  const err = classifyHttpFailure(401, "invalid x-api-key", "Anthropic");
  assert.ok(!/sk-[a-zA-Z0-9-]{8,}/.test(err.message));
});

// gpt-5 / o-series reject `max_tokens` and any non-default temperature; older
// chat models reject `max_completion_tokens`. Sending the wrong pair yields a
// 400 that would otherwise surface only at runtime.
test("isRestrictedOpenAiModel identifies reasoning/gpt-5 model families", () => {
  for (const m of ["gpt-5-codex", "gpt-5", "o1-preview", "o3-mini"]) {
    assert.equal(isRestrictedOpenAiModel(m), true, m);
  }
  for (const m of ["gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"]) {
    assert.equal(isRestrictedOpenAiModel(m), false, m);
  }
});

test("resolveBackend accepts the two supported backends, case-insensitively", () => {
  assert.equal(resolveBackend("claude"), "claude");
  assert.equal(resolveBackend("OpenAI"), "openai");
});

test("resolveBackend rejects an unknown backend as a request error", () => {
  assert.throws(() => resolveBackend("gemini"), ModelRequestError);
});
