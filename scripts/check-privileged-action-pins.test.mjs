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
  mutableToolchainInputs,
  workflowHasElevatedAuthority,
} from "./check-privileged-action-pins.mjs";

test("detects write authority and both GitHub secrets expression forms", () => {
  assert.equal(workflowHasElevatedAuthority("permissions: { contents: write }"), true);
  assert.equal(workflowHasElevatedAuthority("permissions:\n  id-token: write"), true);
  assert.equal(workflowHasElevatedAuthority("token: ${{ secrets.RELEASE_TOKEN }}"), true);
  assert.equal(workflowHasElevatedAuthority("token: ${{ secrets['RELEASE_TOKEN'] }}"), true);
  assert.equal(workflowHasElevatedAuthority("permissions:\n  contents: read"), false);
  assert.equal(workflowHasElevatedAuthority("name: permissions omitted\n"), true);
  assert.equal(
    workflowHasElevatedAuthority(
      "jobs:\n  read-only:\n    permissions:\n      contents: read\n    steps: []\n",
    ),
    false,
  );
  assert.equal(workflowHasElevatedAuthority('permissions: "write-all"\n'), true);
  assert.equal(
    workflowHasElevatedAuthority(
      "permissions: { contents: read }\njobs:\n  release:\n    permissions: { packages: 'write' }\n",
    ),
    true,
  );
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

test("rejects floating workflow toolchains", () => {
  const pinned = `
steps:
  - uses: actions/setup-node@0123456789abcdef0123456789abcdef01234567
    with:
      node-version: "22.14.0"
  - uses: dtolnay/rust-toolchain@0123456789abcdef0123456789abcdef01234567
    with:
      toolchain: 1.95.0
  - uses: taiki-e/install-action@0123456789abcdef0123456789abcdef01234567
    with:
      tool: nextest@0.9.140
  - run: cargo install cargo-audit --version 0.22.2 --locked
  - run: cargo +nightly-2026-07-20 install cargo-fuzz --version 0.13.2 --locked
`;
  assert.deepEqual(mutableToolchainInputs(pinned), []);

  const floating = `
steps:
  - uses: actions/setup-node@0123456789abcdef0123456789abcdef01234567
    with:
      node-version: "22"
  - uses: dtolnay/rust-toolchain@0123456789abcdef0123456789abcdef01234567
    with:
      toolchain: stable
  - uses: taiki-e/install-action@0123456789abcdef0123456789abcdef01234567
    with:
      tool: cargo-llvm-cov
  - run: cargo install cargo-audit --locked
  - run: cargo +nightly install cargo-fuzz --locked
  - run: rustup toolchain install nightly
`;
  assert.deepEqual(mutableToolchainInputs(floating), [
    "actions/setup-node must select exact reviewed Node.js 22.14.0",
    "dtolnay/rust-toolchain must select exact reviewed Rust 1.95.0",
    "taiki-e tool must include an exact version: cargo-llvm-cov",
    "cargo install must include --version: cargo install cargo-audit --locked",
    "cargo install must include --version: cargo +nightly install cargo-fuzz --locked",
    "nightly toolchain alias must be date-pinned: cargo +nightly install cargo-fuzz --locked",
    "rustup nightly install must be date-pinned: rustup toolchain install nightly",
  ]);
});

test("parses quoted and folded workflow uses values", () => {
  const workflow = `
permissions: { contents: read }
steps:
  - "uses": "actions/checkout@v7"
  - uses: >-
      vendor/action@main
`;
  assert.deepEqual(mutableExternalActions(workflow), [
    { line: 4, action: "actions/checkout@v7" },
    { line: 5, action: "vendor/action@main" },
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

test("checks mutable actions even in explicitly read-only workflows", () => {
  const root = mkdtempSync(path.join(tmpdir(), "olympus-action-pins-"));
  try {
    mkdirSync(path.join(root, ".github/workflows"), { recursive: true });
    writeFileSync(
      path.join(root, ".github/workflows/read-only.yml"),
      [
        "permissions:",
        "  contents: read",
        "jobs:",
        "  test:",
        "    permissions:",
        "      contents: read",
        "    steps:",
        "      - uses: vendor/action@main",
        "",
      ].join("\n"),
    );

    assert.deepEqual(checkPrivilegedWorkflows(root), [
      ".github/workflows/read-only.yml:8: vendor/action@main",
    ]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("recursively resolves local actions outside .github/actions with cycle protection", () => {
  const root = mkdtempSync(path.join(tmpdir(), "olympus-action-pins-"));
  try {
    mkdirSync(path.join(root, ".github/workflows"), { recursive: true });
    mkdirSync(path.join(root, "ci/action-a"), { recursive: true });
    mkdirSync(path.join(root, "ci/action-b"), { recursive: true });
    writeFileSync(
      path.join(root, ".github/workflows/release.yml"),
      "permissions:\n  contents: write\njobs:\n  release:\n    steps:\n      - uses: ./ci/action-a\n",
    );
    writeFileSync(
      path.join(root, "ci/action-a/action.yml"),
      "runs:\n  using: composite\n  steps:\n    - uses: ./ci/action-b\n",
    );
    writeFileSync(
      path.join(root, "ci/action-b/action.yaml"),
      "runs:\n  using: composite\n  steps:\n    - uses: vendor/action@main\n    - uses: ./ci/action-a\n",
    );

    assert.deepEqual(checkPrivilegedWorkflows(root), [
      "ci/action-b/action.yaml:4: vendor/action@main",
    ]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
