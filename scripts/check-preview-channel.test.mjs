#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  checkActionMetadataExpressions,
  checkContainment,
  checkPinAgreement,
  checkPreviewChannel,
  collectActionPins,
  collectToolVersions,
} from "./check-preview-channel.mjs";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));

const PREVIEW_WORKFLOW = ".github/workflows/tauri-preview.yml";
const RELEASE_WORKFLOW = ".github/workflows/tauri-release.yml";
const SHARED_ACTION = ".github/actions/setup-build-toolchain/action.yml";

const write = (root, relative, contents) => {
  const absolute = path.join(root, relative);
  mkdirSync(path.dirname(absolute), { recursive: true });
  writeFileSync(absolute, contents);
};

/** A minimal repo that satisfies both checks, for mutation in each test. */
const fixture = () => {
  const root = mkdtempSync(path.join(tmpdir(), "olympus-preview-channel-"));
  write(
    root,
    RELEASE_WORKFLOW,
    [
      "jobs:",
      "  build:",
      "    steps:",
      "      - uses: actions/checkout@aaaaaaa",
      "      - uses: pnpm/action-setup@bbbbbbb",
      "        with:",
      "          toolchain: 1.95.0",
      '          node-version: "22.14.0"',
      "      - run: cargo install tauri-cli --version 2.11.4 --locked",
      "",
    ].join("\n"),
  );
  write(
    root,
    SHARED_ACTION,
    [
      "inputs:",
      "  rust-toolchain:",
      "    description: Rust toolchain version.",
      '    default: "1.95.0"',
      "  node-version:",
      "    description: Node.js version.",
      '    default: "22.14.0"',
      "runs:",
      "  using: composite",
      "  steps:",
      "    - uses: pnpm/action-setup@bbbbbbb",
      "",
    ].join("\n"),
  );
  write(
    root,
    PREVIEW_WORKFLOW,
    [
      "env:",
      "  OLYMPUS_RELEASE_CHANNEL: preview",
      "jobs:",
      "  build:",
      "    steps:",
      "      - uses: actions/checkout@aaaaaaa",
      "      - uses: ./.github/actions/setup-build-toolchain",
      "      - run: cargo install tauri-cli --version 2.11.4 --locked",
      "",
    ].join("\n"),
  );
  write(root, "src-tauri/build.rs", 'env::var("OLYMPUS_RELEASE_CHANNEL")\n');
  write(root, "src-tauri/src/env.rs", 'env!("OLYMPUS_RELEASE_CHANNEL")\n');
  return root;
};

const withFixture = (body) => {
  const root = fixture();
  try {
    body(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
};

test("the real repository passes both preview-channel tripwires", () => {
  assert.deepEqual(checkPreviewChannel(REPO_ROOT), []);
});

test("a clean fixture passes containment and pin agreement", () => {
  withFixture((root) => {
    assert.deepEqual(checkContainment(root), []);
    assert.deepEqual(checkPinAgreement(root), []);
  });
});

test("containment rejects the channel variable escaping into another workflow", () => {
  withFixture((root) => {
    write(root, ".github/workflows/ci.yml", "env:\n  OLYMPUS_RELEASE_CHANNEL: preview\n");
    const errors = checkContainment(root);
    assert.equal(errors.length, 1);
    assert.match(errors[0], /ci\.yml mentions OLYMPUS_RELEASE_CHANNEL/);
    // The message must explain the consequence, not just name the file.
    assert.match(errors[0], /production secret gates/);
  });
});

test("containment rejects the preview workflow losing the channel stamp", () => {
  withFixture((root) => {
    write(root, PREVIEW_WORKFLOW, "jobs:\n  build:\n    steps: []\n");
    const errors = checkContainment(root);
    assert.equal(errors.length, 1);
    assert.match(errors[0], /no longer sets OLYMPUS_RELEASE_CHANNEL/);
  });
});

test("containment allows markdown to discuss the channel", () => {
  withFixture((root) => {
    write(
      root,
      "docs/plans/preview-release-channel.md",
      "Set `OLYMPUS_RELEASE_CHANNEL=preview`.\n",
    );
    assert.deepEqual(checkContainment(root), []);
  });
});

test("pin agreement rejects a third-party action SHA that drifted", () => {
  withFixture((root) => {
    write(
      root,
      SHARED_ACTION,
      ["runs:", "  steps:", "    - uses: pnpm/action-setup@ccccccc", ""].join("\n"),
    );
    const errors = checkPinAgreement(root);
    assert.ok(
      errors.some((error) => /pnpm\/action-setup is pinned to bbbbbbb .* but ccccccc/.test(error)),
      `expected a SHA drift error, got: ${JSON.stringify(errors)}`,
    );
  });
});

test("pin agreement rejects a toolchain version that drifted", () => {
  withFixture((root) => {
    write(
      root,
      SHARED_ACTION,
      [
        "inputs:",
        "  rust-toolchain:",
        '    default: "1.90.0"',
        "  node-version:",
        '    default: "22.14.0"',
        "runs:",
        "  steps:",
        "    - uses: pnpm/action-setup@bbbbbbb",
        "",
      ].join("\n"),
    );
    const errors = checkPinAgreement(root);
    assert.ok(
      errors.some((error) => /rust is 1\.95\.0 .* but 1\.90\.0/.test(error)),
      `expected a Rust version drift error, got: ${JSON.stringify(errors)}`,
    );
  });
});

test("pin agreement rejects the preview path dropping a pin entirely", () => {
  withFixture((root) => {
    write(root, SHARED_ACTION, "runs:\n  steps:\n    - uses: pnpm/action-setup@bbbbbbb\n");
    const errors = checkPinAgreement(root);
    assert.ok(
      errors.some((error) => /does not pin rust/.test(error)),
      `expected a missing-pin error, got: ${JSON.stringify(errors)}`,
    );
  });
});

// Regression: this is verbatim what killed the first preview tag
// (preview-v0.10.0-rc.1). A comment in the composite action's `description`
// explained that the toolchain versions were literals "rather than a
// ${{ inputs.* }} indirection" — and the runner evaluated that prose as a real
// expression, failing the manifest with "Unrecognized named-value: 'inputs'"
// before a single step ran. The YAML was valid, so js-yaml and prettier both
// passed it.
test("action metadata rejects GitHub expression syntax in a description", () => {
  withFixture((root) => {
    write(
      root,
      ".github/actions/setup-build-toolchain/action.yml",
      [
        "name: Setup build toolchain",
        "description: |",
        "  Versions are literals, not a ${{ inputs.rust-toolchain }} indirection.",
        "runs:",
        "  using: composite",
        "  steps: []",
        "",
      ].join("\n"),
    );
    const errors = checkActionMetadataExpressions(root);
    assert.equal(errors.length, 1);
    assert.match(errors[0], /description contains GitHub expression syntax/);
    // The message must say why it is fatal, not merely that it is disallowed.
    assert.match(errors[0], /before any step runs/);
  });
});

test("action metadata rejects expressions in an input description too", () => {
  withFixture((root) => {
    write(
      root,
      ".github/actions/setup-build-toolchain/action.yml",
      [
        "name: Setup build toolchain",
        "description: Fine.",
        "inputs:",
        "  cache-key:",
        "    description: Defaults to ${{ github.job }} when empty.",
        "    default: ''",
        "runs:",
        "  using: composite",
        "  steps: []",
        "",
      ].join("\n"),
    );
    const errors = checkActionMetadataExpressions(root);
    assert.equal(errors.length, 1);
    assert.match(errors[0], /inputs\.cache-key\.description/);
  });
});

test("action metadata allows expressions in steps, where they are legal", () => {
  withFixture((root) => {
    write(
      root,
      ".github/actions/setup-build-toolchain/action.yml",
      [
        "name: Setup build toolchain",
        "description: Prose with no expressions.",
        "inputs:",
        "  rust-targets:",
        "    description: Extra target triples.",
        "    default: ''",
        "runs:",
        "  using: composite",
        "  steps:",
        "    - uses: dtolnay/rust-toolchain@aaaaaaa",
        "      with:",
        "        targets: ${{ inputs.rust-targets }}",
        "",
      ].join("\n"),
    );
    assert.deepEqual(checkActionMetadataExpressions(root), []);
  });
});

test("collectActionPins skips local composite actions and reads SHAs", () => {
  const pins = collectActionPins(
    ["      - uses: actions/checkout@abc123", "      - uses: ./.github/actions/local", ""].join(
      "\n",
    ),
  );
  assert.deepEqual([...pins.entries()], [["actions/checkout", "abc123"]]);
});

test("collectToolVersions reads inline keys and composite input defaults", () => {
  assert.equal(collectToolVersions("        toolchain: 1.95.0\n").rust, "1.95.0");
  assert.equal(
    collectToolVersions('inputs:\n  rust-toolchain:\n    default: "1.95.0"\n').rust,
    "1.95.0",
  );
  assert.equal(collectToolVersions("nothing here\n").rust, null);
});
