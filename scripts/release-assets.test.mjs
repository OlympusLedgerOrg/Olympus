#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { stageReleaseAssets, verifyReleaseAssets } from "./release-assets.mjs";

const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const TAG = "v1.2.3";
const VERIFY_RELEASE = fileURLToPath(new URL("./verify-release.sh", import.meta.url));

const TARGET_FILES = new Map([
  ["x86_64-pc-windows-msvc", ["Olympus Ledger.msi", "Olympus-setup.exe"]],
  ["x86_64-apple-darwin", ["Olympus-x64.dmg"]],
  ["aarch64-apple-darwin", ["Olympus-arm64.dmg"]],
  ["x86_64-unknown-linux-gnu", ["olympus.deb", "olympus.AppImage", "olympus.rpm"]],
]);

const fixture = () => {
  const root = mkdtempSync(path.join(tmpdir(), "olympus-release-assets-"));
  const input = path.join(root, "input");
  const sbom = path.join(root, "sbom");
  const output = path.join(root, "publish");
  mkdirSync(input);
  mkdirSync(sbom);

  for (const [target, files] of TARGET_FILES) {
    const targetDirectory = path.join(input, `olympus-${target}`);
    const bundleDirectory = path.join(targetDirectory, "bundle-output");
    mkdirSync(bundleDirectory, { recursive: true });
    for (const file of files) {
      writeFileSync(path.join(bundleDirectory, file), `${target}/${file}\n`);
    }
  }
  writeFileSync(path.join(sbom, "olympus-desktop.cdx.json"), '{"bomFormat":"CycloneDX"}\n');
  writeFileSync(path.join(sbom, "public-ui.cdx.json"), '{"bomFormat":"CycloneDX"}\n');

  return { root, input, sbom, output };
};

const stageFixture = (dirs) =>
  stageReleaseAssets({
    input: dirs.input,
    sbom: dirs.sbom,
    output: dirs.output,
    tag: TAG,
    commit: COMMIT,
    installerChecksums: path.join(dirs.root, "INSTALLER_SHA256SUMS"),
  });

test("stages and verifies a complete deterministic release asset set", () => {
  const dirs = fixture();
  try {
    const staged = stageFixture(dirs);
    const verified = path.join(dirs.root, "verified");
    const result = verifyReleaseAssets({
      input: dirs.output,
      output: verified,
      tag: TAG,
      commit: COMMIT,
    });

    assert.equal(result.releaseTag, TAG);
    assert.deepEqual(result, staged);
    assert.match(
      readFileSync(path.join(dirs.output, "SHA256SUMS"), "utf8"),
      /RELEASE_ASSETS\.json/,
    );
    assert.equal(readFileSync(path.join(verified, "RELEASE_ASSETS.json"), "utf8").length > 0, true);
    execFileSync(VERIFY_RELEASE, ["--dir", dirs.output, "--level", "1"], {
      stdio: "pipe",
    });
  } finally {
    rmSync(dirs.root, { recursive: true, force: true });
  }
});

test("rejects a partial target matrix", () => {
  const dirs = fixture();
  try {
    rmSync(
      path.join(
        dirs.input,
        "olympus-x86_64-unknown-linux-gnu",
        "bundle-output",
        "olympus.AppImage",
      ),
    );
    assert.throws(() => stageFixture(dirs), /exactly one appimage installer/);
  } finally {
    rmSync(dirs.root, { recursive: true, force: true });
  }
});

test("rejects tampered and stale release assets", () => {
  const dirs = fixture();
  try {
    stageFixture(dirs);
    const installer = path.join(dirs.output, "x86_64-pc-windows-msvc--Olympus-setup.exe");
    writeFileSync(installer, "tampered\n");
    assert.throws(
      () => verifyReleaseAssets({ input: dirs.output, tag: TAG }),
      /size mismatch|digest mismatch/,
    );

    // Restore a fresh fixture, then add an installer left over from an older run.
    rmSync(dirs.root, { recursive: true, force: true });
    const fresh = fixture();
    try {
      stageFixture(fresh);
      writeFileSync(path.join(fresh.output, "old-portable-build.zip"), "stale\n");
      assert.throws(
        () => verifyReleaseAssets({ input: fresh.output, tag: TAG }),
        /stale or unmanifested release asset/,
      );
    } finally {
      rmSync(fresh.root, { recursive: true, force: true });
    }
  } finally {
    rmSync(dirs.root, { recursive: true, force: true });
  }
});

test("rejects empty installers before publishing", () => {
  const dirs = fixture();
  try {
    writeFileSync(
      path.join(
        dirs.input,
        "olympus-x86_64-pc-windows-msvc",
        "bundle-output",
        "Olympus Ledger.msi",
      ),
      "",
    );
    assert.throws(() => stageFixture(dirs), /release assets must not be empty/);
  } finally {
    rmSync(dirs.root, { recursive: true, force: true });
  }
});

test("binds the release asset manifest to its tag", () => {
  const dirs = fixture();
  try {
    stageFixture(dirs);
    assert.throws(() => verifyReleaseAssets({ input: dirs.output, tag: "v9.9.9" }), /tag mismatch/);
  } finally {
    rmSync(dirs.root, { recursive: true, force: true });
  }
});

test("binds the release asset manifest to its source commit", () => {
  const dirs = fixture();
  try {
    stageFixture(dirs);
    assert.throws(
      () =>
        verifyReleaseAssets({
          input: dirs.output,
          tag: TAG,
          commit: "ffffffffffffffffffffffffffffffffffffffff",
        }),
      /commit mismatch/,
    );
  } finally {
    rmSync(dirs.root, { recursive: true, force: true });
  }
});
