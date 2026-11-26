// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  appendRecord,
  buildRouteRecord,
  buildUsageRecord,
  logPath,
  logRoute,
  logUsage,
  loggingEnabled,
} from "./log.mjs";

const tempLog = () =>
  path.join(mkdtempSync(path.join(tmpdir(), "route-log-")), "nested", "log.jsonl");

const readLines = (file) =>
  readFileSync(file, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));

const ROUTE = {
  task: "summarize the docs",
  tier: "local",
  agent: "local",
  model: "qwen2.5-coder:7b-instruct",
  taskClass: "summarize",
  allowed: true,
  escalated: false,
  policyReason: "allowlisted task class and paths",
  deniedPaths: [],
};

test("a route record keeps the fields a report needs", () => {
  const record = buildRouteRecord(
    {
      ...ROUTE,
      deniedPaths: [
        "src-tauri/src/main.rs",
        { path: "crates/x/Cargo.toml", reason: "denied path" },
      ],
    },
    { now: () => new Date("2026-11-26T10:00:00.000Z") },
  );
  assert.equal(record.ts, "2026-11-26T10:00:00.000Z");
  assert.equal(record.kind, "route");
  assert.equal(record.tier, "local");
  assert.equal(record.model, "qwen2.5-coder:7b-instruct");
  assert.equal(record.allowed, true);
  assert.deepEqual(record.deniedPaths, ["src-tauri/src/main.rs", "crates/x/Cargo.toml"]);
});

test("a usage record carries the local token counts", () => {
  const record = buildUsageRecord({
    model: "qwen2.5-coder:7b-instruct",
    taskClass: "qa",
    files: ["README.md"],
    promptTokens: 1200,
    completionTokens: 80,
    durationMs: 4200,
  });
  assert.equal(record.kind, "usage");
  assert.equal(record.tier, "local");
  assert.equal(record.promptTokens, 1200);
  assert.equal(record.completionTokens, 80);
  assert.equal(record.durationMs, 4200);
});

test("records append as one JSON object per line, creating the directory", () => {
  const file = tempLog();
  logRoute(ROUTE, { path: file });
  logUsage({ model: "m", files: [], promptTokens: 1, completionTokens: 2 }, { path: file });
  const lines = readLines(file);
  assert.equal(lines.length, 2);
  assert.deepEqual(
    lines.map((line) => line.kind),
    ["route", "usage"],
  );
});

test("appendRecord adds to existing content instead of replacing it", () => {
  const file = tempLog();
  appendRecord({ kind: "route", n: 1 }, { path: file });
  appendRecord({ kind: "route", n: 2 }, { path: file });
  assert.deepEqual(
    readLines(file).map((line) => line.n),
    [1, 2],
  );
});

test("OLYMPUS_ROUTE_LOG=0 disables writing", () => {
  const file = tempLog();
  assert.equal(loggingEnabled({ OLYMPUS_ROUTE_LOG: "0" }), false);
  assert.equal(logRoute(ROUTE, { env: { OLYMPUS_ROUTE_LOG: "false" }, path: file }), null);
  assert.throws(() => readFileSync(file, "utf8"));
});

test("an explicit path wins over the default, and the default is gitignored state", () => {
  const file = tempLog();
  assert.equal(logPath({ OLYMPUS_ROUTE_LOG_PATH: file }), file);
  assert.match(logPath({}), /\.olympus-logs[\\/]route-report\.jsonl$/);
});
