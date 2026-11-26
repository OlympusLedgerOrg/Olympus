#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Gate-integrity check: a PR must not be able to weaken the gate that evaluates
// it.
//
// The scope-drift workflow runs this file from the *base* branch, so replacing
// this copy inside a PR changes nothing about the decision. Any change under
// GATE_PATHS is allowed only with an explicit `gate-change-approved` label: a
// reviewable, greppable signal rather than an invisible edit to the same file
// the gate reads. The label is intentionally distinct from `scope-override`,
// which excuses an out-of-scope path, not a change to the gate itself.
//
// Like `check-pr-scope.mjs`, this imports only `node:` builtins so the workflow
// needs no install step.

import { appendFileSync, readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

export const GATE_PATHS = [
  ".github/CODEOWNERS",
  ".github/workflows/pr-scope-drift.yml",
  "scripts/check-gate-integrity.mjs",
  "scripts/check-gate-integrity.test.mjs",
  "scripts/check-pr-scope.mjs",
  "scripts/check-pr-scope.test.mjs",
  "tools/agent-policy/policy.json",
];

export const REQUIRED_LABEL = "gate-change-approved";

/** Files in `changedFiles` that are part of the gate itself. */
export function changedGatePaths(changedFiles, gatePaths = GATE_PATHS) {
  return changedFiles.filter((file) =>
    gatePaths.some((gate) => (gate.endsWith("/") ? file.startsWith(gate) : file === gate)),
  );
}

/**
 * Decide whether a diff may proceed.
 *
 * @param {{changedFiles: string[], labels: string[], requiredLabel?: string, gatePaths?: string[]}} input
 * @returns {{ok: boolean, touched: string[], reason: string}}
 */
export function evaluateGateIntegrity({
  changedFiles,
  labels,
  requiredLabel = REQUIRED_LABEL,
  gatePaths = GATE_PATHS,
}) {
  const touched = changedGatePaths(changedFiles, gatePaths);
  if (touched.length === 0) {
    return { ok: true, touched, reason: "no gate files changed" };
  }
  if (labels.includes(requiredLabel)) {
    return {
      ok: true,
      touched,
      reason: `gate change approved by the ${requiredLabel} label`,
    };
  }
  return {
    ok: false,
    touched,
    reason:
      `the scope gate's own files changed without the ${requiredLabel} label: ` +
      touched.join(", "),
  };
}

function parseArgs(argv) {
  const options = {
    changedFilesFile: null,
    labelsJson: "[]",
    requiredLabel: REQUIRED_LABEL,
    summaryFile: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`${arg} needs a value`);
      return argv[i];
    };
    switch (arg) {
      case "--changed-files-file":
        options.changedFilesFile = next();
        break;
      case "--labels-json":
        options.labelsJson = next();
        break;
      case "--required-label":
        options.requiredLabel = next();
        break;
      case "--summary-file":
        options.summaryFile = next();
        break;
      case "--help":
      case "-h":
        options.help = true;
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }
  return options;
}

function readLabels(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("--labels-json is not valid JSON");
  }
  if (!Array.isArray(parsed) || parsed.some((label) => typeof label !== "string")) {
    throw new Error("--labels-json must be a JSON array of strings");
  }
  return parsed;
}

export function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(
      "usage: check-gate-integrity.mjs --changed-files-file <path> " +
        "[--labels-json <json>] [--required-label <label>] [--summary-file <path>]\n",
    );
    return 0;
  }
  if (!options.changedFilesFile) {
    process.stderr.write("error: --changed-files-file is required\n");
    return 2;
  }

  const changedFiles = readFileSync(options.changedFilesFile, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const labels = readLabels(options.labelsJson);
  const result = evaluateGateIntegrity({
    changedFiles,
    labels,
    requiredLabel: options.requiredLabel,
  });

  const record = JSON.stringify({
    ok: result.ok,
    touched: result.touched,
    required_label: options.requiredLabel,
  });
  process.stdout.write(`gate-integrity-record ${record}\n`);
  process.stdout.write(`${result.ok ? "PASS" : "FAIL"}: ${result.reason}\n`);

  if (options.summaryFile) {
    appendFileSync(
      options.summaryFile,
      `### Gate integrity\n\n${result.ok ? "PASS" : "FAIL"}: ${result.reason}\n\n`,
    );
  }

  return result.ok ? 0 : 1;
}

const invokedDirectly =
  process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (invokedDirectly) {
  try {
    process.exitCode = main();
  } catch (error) {
    process.stderr.write(`error: ${error.message}\n`);
    process.exitCode = 2;
  }
}
