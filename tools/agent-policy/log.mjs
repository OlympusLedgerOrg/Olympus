#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Append-only JSONL record of which tier ran what, and what the local model
 * cost in tokens.
 *
 * The budget this repo is trying to protect is paid-model tokens, and the one
 * number that is measurable from here is the local side: Ollama reports
 * `prompt_eval_count` and `eval_count` on the final stream event. A hosted
 * model bills in its own dashboard, so the log records the *tier chosen* for
 * those and does not invent a token count it cannot see.
 *
 * Two record kinds, one file:
 *
 *   {"kind":"route", ...}  one per routing decision (tier, agent, model, why)
 *   {"kind":"usage", ...}  one per local call (tokens, duration, files)
 *
 * Append-only because it is a log: a crash mid-write can leave one partial
 * line, and the reader skips it rather than refusing the whole file. Nothing
 * here throws into a caller's happy path — a failed log write is a warning, not
 * a failed task.
 */

import { appendFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));

/** Gitignored (`.olympus-logs/`), so a run never appears in a diff. */
export const DEFAULT_LOG_PATH = path.join(REPO_ROOT, ".olympus-logs", "route-report.jsonl");

export function logPath(env = process.env) {
  const override = env.OLYMPUS_ROUTE_LOG_PATH;
  return override && override.trim() ? override.trim() : DEFAULT_LOG_PATH;
}

/** `OLYMPUS_ROUTE_LOG=0` (or false/off/no) turns logging off entirely. */
export function loggingEnabled(env = process.env) {
  const value = String(env.OLYMPUS_ROUTE_LOG ?? "")
    .trim()
    .toLowerCase();
  return !["0", "false", "off", "no"].includes(value);
}

export function appendRecord(record, { path: logFile = DEFAULT_LOG_PATH } = {}) {
  mkdirSync(path.dirname(logFile), { recursive: true });
  appendFileSync(logFile, `${JSON.stringify(record)}\n`, "utf8");
  return logFile;
}

const deniedPath = (entry) => (typeof entry === "string" ? entry : entry?.path);

export function buildRouteRecord(result, { now = () => new Date() } = {}) {
  return {
    ts: now().toISOString(),
    kind: "route",
    task: String(result?.task ?? ""),
    tier: result?.tier ?? null,
    agent: result?.agent ?? null,
    model: result?.model ?? null,
    taskClass: result?.taskClass ?? null,
    allowed: Boolean(result?.allowed),
    escalated: Boolean(result?.escalated),
    policyReason: result?.policyReason ?? null,
    deniedPaths: (result?.deniedPaths ?? []).map(deniedPath).filter(Boolean),
  };
}

export function buildUsageRecord(
  {
    model,
    taskClass = null,
    files = [],
    promptTokens = null,
    completionTokens = null,
    durationMs = null,
  },
  { now = () => new Date() } = {},
) {
  return {
    ts: now().toISOString(),
    kind: "usage",
    tier: "local",
    agent: "local",
    model: model ?? null,
    taskClass,
    files: [...files],
    promptTokens,
    completionTokens,
    durationMs,
  };
}

export function logRoute(result, { env = process.env, path: logFile } = {}) {
  if (!loggingEnabled(env)) return null;
  return appendRecord(buildRouteRecord(result), { path: logFile ?? logPath(env) });
}

export function logUsage(record, { env = process.env, path: logFile } = {}) {
  if (!loggingEnabled(env)) return null;
  return appendRecord(buildUsageRecord(record), { path: logFile ?? logPath(env) });
}
