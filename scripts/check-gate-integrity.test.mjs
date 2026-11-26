// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  GATE_PATHS,
  REQUIRED_LABEL,
  changedGatePaths,
  evaluateGateIntegrity,
} from "./check-gate-integrity.mjs";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "check-gate-integrity.mjs");

function runCli({ changedFiles, labels = [] }) {
  const dir = mkdtempSync(path.join(tmpdir(), "gate-integrity-"));
  const changed = path.join(dir, "changed.txt");
  writeFileSync(changed, changedFiles.join("\n"));
  return spawnSync(
    process.execPath,
    [SCRIPT, "--changed-files-file", changed, "--labels-json", JSON.stringify(labels)],
    { encoding: "utf8" },
  );
}

test("an unrelated diff passes", () => {
  const result = evaluateGateIntegrity({
    changedFiles: ["app/public-ui/src/App.tsx", "README.md"],
    labels: [],
  });
  assert.equal(result.ok, true);
  assert.deepEqual(result.touched, []);
  assert.equal(runCli({ changedFiles: ["README.md"] }).status, 0);
});

test("editing the scope checker without the label fails", () => {
  const result = evaluateGateIntegrity({
    changedFiles: ["scripts/check-pr-scope.mjs"],
    labels: ["scope-override"],
  });
  assert.equal(result.ok, false);
  assert.deepEqual(result.touched, ["scripts/check-pr-scope.mjs"]);

  const cli = runCli({
    changedFiles: ["scripts/check-pr-scope.mjs"],
    labels: ["scope-override"],
  });
  assert.equal(cli.status, 1);
  assert.match(cli.stdout, /FAIL/);
  assert.match(cli.stdout, new RegExp(REQUIRED_LABEL));
});

test("the gate-change label allows an intentional gate edit", () => {
  const result = evaluateGateIntegrity({
    changedFiles: ["scripts/check-pr-scope.mjs", "scripts/check-pr-scope.test.mjs"],
    labels: [REQUIRED_LABEL],
  });
  assert.equal(result.ok, true);
  assert.equal(result.touched.length, 2);
  assert.equal(
    runCli({
      changedFiles: ["scripts/check-pr-scope.mjs"],
      labels: [REQUIRED_LABEL],
    }).status,
    0,
  );
});

test("every protected gate file is actually protected", () => {
  for (const gatePath of GATE_PATHS) {
    assert.deepEqual(changedGatePaths([gatePath]), [gatePath]);
    assert.equal(
      evaluateGateIntegrity({ changedFiles: [gatePath], labels: [] }).ok,
      false,
      `${gatePath} must require the label`,
    );
  }
});

test("path prefixes do not fool exact matching", () => {
  assert.deepEqual(changedGatePaths(["scripts/check-pr-scope.mjs.bak"]), []);
  assert.deepEqual(changedGatePaths(["nested/.github/CODEOWNERS"]), []);
});

test("a malformed label list is an invocation error, not a pass", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "gate-integrity-"));
  const changed = path.join(dir, "changed.txt");
  writeFileSync(changed, "scripts/check-pr-scope.mjs");
  const cli = spawnSync(
    process.execPath,
    [SCRIPT, "--changed-files-file", changed, "--labels-json", "{}"],
    { encoding: "utf8" },
  );
  assert.equal(cli.status, 2);
  assert.match(cli.stderr, /array of strings/);
});
