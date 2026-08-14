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
  redactSecrets,
  numericEnv,
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

// 402 (quota exhausted -- a billing state, not a malformed request) and 408
// (timeout -- transient by definition) were originally missing from the
// non-blocking branch and fell through to ModelRequestError instead. That
// meant an exhausted OpenAI quota blocked every developer with a key
// exported from committing at all, contradicting the documented contract
// that environmental failures never block a commit.
test("quota-exhausted (402) and request-timeout (408) classify as unavailable (non-blocking)", () => {
  for (const status of [402, 408]) {
    assert.ok(
      classifyHttpFailure(status, "quota exceeded", "OpenAI") instanceof ModelUnavailableError,
      `status ${status}`,
    );
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

// The original version of this test passed a body with no key-shaped token
// in it ("invalid x-api-key" — the literal header NAME, not a value), so
// the regex it asserted against could never match regardless of whether
// redaction existed. It was a vacuous guard: a refactor that started
// leaking real keys into messages would pass it unchanged. This version
// puts an actual key-shaped token in the input and proves it does not
// survive into the constructed message.
test("classifyHttpFailure redacts a caller-supplied secret echoed in the response body", () => {
  const leaked = "sk-ant-api03-AAAABBBBCCCCDDDD";
  const err = classifyHttpFailure(401, `authentication_error: ${leaked} is invalid`, "Anthropic", [
    leaked,
  ]);
  assert.ok(!err.message.includes(leaked), `credential survived into: ${err.message}`);
  assert.match(err.message, /\[REDACTED\]/);
});

test("redactSecrets replaces every occurrence, ignores empty/falsy secrets", () => {
  assert.equal(redactSecrets("a-KEY-b-KEY-c", ["KEY"]), "a-[REDACTED]-b-[REDACTED]-c");
  assert.equal(redactSecrets("unchanged", ["", undefined, null]), "unchanged");
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

// numericEnv guards WISEREPO_TIMEOUT_MS / WISEREPO_TEMPERATURE. Before this,
// Number("45s") silently produced NaN with no throw; setTimeout(fn, NaN)
// coerces to 1ms, so the very next model call would abort almost instantly,
// get classified as ModelUnavailableError, and the pre-commit hook would
// report "backend unavailable, skipping AGENTS.md sync" forever — a typo'd
// env var indistinguishable from an actual network problem, with no
// diagnostic pointing at the real cause. numericEnv must reject that at
// load time instead, loudly, as a blocking ModelRequestError.
test("numericEnv returns the fallback when unset or empty", () => {
  assert.equal(numericEnv("WISEREPO_TEST_UNSET_VAR", 42, { min: 0, max: 100 }), 42);
});

test("numericEnv accepts a valid value in range", () => {
  process.env.WISEREPO_TEST_VAR = "50";
  try {
    assert.equal(numericEnv("WISEREPO_TEST_VAR", 42, { min: 0, max: 100 }), 50);
  } finally {
    delete process.env.WISEREPO_TEST_VAR;
  }
});

test("numericEnv rejects a non-numeric value loudly instead of silently becoming NaN", () => {
  process.env.WISEREPO_TEST_VAR = "45s";
  try {
    assert.throws(
      () => numericEnv("WISEREPO_TEST_VAR", 42, { min: 0, max: 100 }),
      (err) => err instanceof ModelRequestError && /45s.*not a finite number/.test(err.message),
    );
  } finally {
    delete process.env.WISEREPO_TEST_VAR;
  }
});

test("numericEnv rejects an out-of-range value", () => {
  process.env.WISEREPO_TEST_VAR = "-5";
  try {
    assert.throws(
      () => numericEnv("WISEREPO_TEST_VAR", 42, { min: 0, max: 100 }),
      ModelRequestError,
    );
  } finally {
    delete process.env.WISEREPO_TEST_VAR;
  }
});
