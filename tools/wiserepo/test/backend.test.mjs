// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ModelUnavailableError,
  ModelRequestError,
  classifyHttpFailure,
  numericEnv,
  DEFAULT_OLLAMA_MODEL,
} from "../src/backend.mjs";

// The exit-code contract in bin/sync-agent-docs.mjs rests entirely on this
// classification: "unavailable" must never block a commit, "request error"
// always must. Getting it backwards either hides a broken config behind a
// green build, or blocks commits on a transient local blip.

test("server errors classify as unavailable (non-blocking)", () => {
  for (const status of [500, 502, 503]) {
    assert.ok(classifyHttpFailure(status, "boom") instanceof ModelUnavailableError, `${status}`);
  }
});

test("request-timeout (408) classifies as unavailable (non-blocking)", () => {
  assert.ok(classifyHttpFailure(408, "timed out") instanceof ModelUnavailableError);
});

// A 404 from Ollama means the model tag isn't pulled. Retrying never fixes
// that, so it must block AND say what to actually run -- a bare "API error
// 404" would send someone hunting a network problem that doesn't exist.
test("404 classifies as blocking and names the pull command", () => {
  const err = classifyHttpFailure(404, 'model "x" not found');
  assert.ok(err instanceof ModelRequestError);
  assert.match(err.message, /ollama pull/);
  assert.ok(
    err.message.includes(DEFAULT_OLLAMA_MODEL),
    `expected the configured model name in: ${err.message}`,
  );
});

test("client request errors classify as blocking bugs", () => {
  for (const status of [400, 422]) {
    assert.ok(classifyHttpFailure(status, "bad request") instanceof ModelRequestError, `${status}`);
  }
});

test("classified errors carry the status and body for debugging", () => {
  const err = classifyHttpFailure(400, "invalid options.num_predict");
  assert.match(err.message, /Ollama API error 400/);
  assert.match(err.message, /num_predict/);
});

// numericEnv guards WISEREPO_TIMEOUT_MS / WISEREPO_TEMPERATURE. Before this,
// Number("45s") silently produced NaN with no throw; setTimeout(fn, NaN)
// coerces to 1ms, so the very next model call would abort almost instantly,
// get classified as ModelUnavailableError, and the pre-commit hook would
// report "backend unavailable, skipping AGENTS.md sync" forever — a typo'd
// env var indistinguishable from an actual daemon-down condition, with no
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
