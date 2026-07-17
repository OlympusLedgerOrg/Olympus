#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import {
  checkPrivilegedWorkflows,
  mutableExternalActions,
  workflowHasElevatedAuthority,
} from "./check-privileged-action-pins.mjs";

test("detects write authority and both GitHub secrets expression forms", () => {
  assert.equal(workflowHasElevatedAuthority("permissions: { contents: write }"), true);
  assert.equal(workflowHasElevatedAuthority("permissions:\n  id-token: write"), true);
  assert.equal(workflowHasElevatedAuthority("token: ${{ secrets.RELEASE_TOKEN }}"), true);
  assert.equal(workflowHasElevatedAuthority("token: ${{ secrets['RELEASE_TOKEN'] }}"), true);
  assert.equal(workflowHasElevatedAuthority("permissions:\n  contents: read"), false);
});

test("accepts full action commit pins and local actions", () => {
  const workflow = `
steps:
  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v1
  - uses : "vendor/quoted-action@0123456789abcdef0123456789abcdef01234567"
  - uses: ./.github/actions/local
  - uses: docker://ghcr.io/vendor/action@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
`;
  assert.deepEqual(mutableExternalActions(workflow), []);
});

test("rejects mutable action tags and branches", () => {
  const workflow = `
steps:
  - uses: actions/checkout@v7
  - uses: vendor/action@main
  - uses: docker://ghcr.io/vendor/action:latest
`;
  assert.deepEqual(mutableExternalActions(workflow), [
    { line: 3, action: "actions/checkout@v7" },
    { line: 4, action: "vendor/action@main" },
    { line: 5, action: "docker://ghcr.io/vendor/action:latest" },
  ]);
});

test("checks external dependencies hidden inside local composite actions", () => {
  const root = mkdtempSync(path.join(tmpdir(), "olympus-action-pins-"));
  try {
    mkdirSync(path.join(root, ".github/workflows"), { recursive: true });
    mkdirSync(path.join(root, ".github/actions/example"), { recursive: true });
    writeFileSync(
      path.join(root, ".github/workflows/read-only.yml"),
      "permissions:\n  contents: read\n",
    );
    writeFileSync(
      path.join(root, ".github/actions/example/action.yml"),
      "runs:\n  using: composite\n  steps:\n    - uses: vendor/action@main\n",
    );

    assert.deepEqual(checkPrivilegedWorkflows(root), [
      ".github/actions/example/action.yml:4: vendor/action@main",
    ]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
