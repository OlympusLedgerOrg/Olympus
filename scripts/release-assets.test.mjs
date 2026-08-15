#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
    execFileSync("bash", [VERIFY_RELEASE, "--dir", dirs.output, "--level", "1"], {
      stdio: "pipe",
    });
  } finally {
    rmSync(dirs.root, { recursive: true, force: true });
  }
});

test("level 2 verifies provenance for the release manifest", () => {
  const dirs = fixture();
  try {
    stageFixture(dirs);
    const bin = path.join(dirs.root, "bin");
    const log = path.join(dirs.root, "gh.log");
    mkdirSync(bin);
    const fakeGh = path.join(bin, "gh");
    writeFileSync(fakeGh, '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$GH_LOG"\n');
    chmodSync(fakeGh, 0o755);

    execFileSync("bash", [VERIFY_RELEASE, "--dir", dirs.output, "--level", "2"], {
      env: {
        ...process.env,
        GH_LOG: log,
        // `path.delimiter`, not a literal ":" — the separator is ";" on Windows,
        // where a ":"-joined value makes the whole PATH unresolvable and the
        // stub `gh` below is never found.
        PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      },
      stdio: "pipe",
    });

    const calls = readFileSync(log, "utf8");
    assert.match(calls, /attestation verify RELEASE_ASSETS\.json /);
    assert.doesNotMatch(calls, /SHA256SUMS|\.cdx\.json/);
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

// GitHub rewrites release asset filenames on upload — spaces become periods —
// so a staged name containing a space can never match what `gh release
// download` returns, and both `verify` and every downloader's `sha256sum -c`
// fail on names while the bytes are intact. preview-v0.10.0-rc.3 shipped
// exactly this. Staging must therefore emit GitHub-stable names.
test("stages Tauri's spaced bundle names as the dotted names GitHub will serve", () => {
  const dirs = fixture();
  try {
    const staged = stageFixture(dirs);
    const names = staged.assets.map((asset) => asset.name);
    // The fixture's Windows source file is "Olympus Ledger.msi" (real Tauri
    // bundles carry the space, derived from productName).
    assert.ok(
      names.includes("x86_64-pc-windows-msvc--Olympus.Ledger.msi"),
      `expected the dotted name, got: ${JSON.stringify(names)}`,
    );
    for (const name of names) {
      assert.ok(!name.includes(" "), `staged asset name contains a space: ${name}`);
    }
    // The verifier must accept the whole staged set under the new names.
    verifyReleaseAssets({ input: dirs.output, tag: TAG, commit: COMMIT });
  } finally {
    rmSync(dirs.root, { recursive: true, force: true });
  }
});

test("rejects asset names GitHub would rewrite beyond the space transform", () => {
  const dirs = fixture();
  try {
    writeFileSync(
      path.join(dirs.input, "olympus-x86_64-pc-windows-msvc", "bundle-output", "Olympus#1.msi"),
      "installer\n",
    );
    assert.throws(
      () => stageFixture(dirs),
      /characters GitHub rewrites on upload/,
      "an unmappable character must fail at stage time, before anything is hashed",
    );
  } finally {
    rmSync(dirs.root, { recursive: true, force: true });
  }
});

test("verify refuses a pre-fix manifest whose asset names contain spaces", () => {
  const dirs = fixture();
  try {
    stageFixture(dirs);
    const manifestPath = path.join(dirs.output, "RELEASE_ASSETS.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    const victim = manifest.assets.find((asset) => asset.name.endsWith(".msi"));
    victim.name = victim.name.replace(/\./g, " "); // simulate a pre-fix spaced manifest
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    assert.throws(
      () => verifyReleaseAssets({ input: dirs.output, tag: TAG, commit: COMMIT }),
      /not GitHub-stable/,
      "a spaced manifest must be named as the cause, not surface as N per-file mismatches",
    );
  } finally {
    rmSync(dirs.root, { recursive: true, force: true });
  }
});

// docs/plans/preview-release-channel.md §4 claims the asset contract needs no
// channel parameter — the tag is opaque data, and preview bundles are unsigned
// but otherwise identical in shape. Assert that rather than assuming it, so the
// claim cannot quietly stop being true.
test("stages and verifies a preview-channel tag with no contract changes", () => {
  const previewTag = "preview-v0.10.0-rc.1";
  const dirs = fixture();
  try {
    const staged = stageReleaseAssets({
      input: dirs.input,
      sbom: dirs.sbom,
      output: dirs.output,
      tag: previewTag,
      commit: COMMIT,
      installerChecksums: path.join(dirs.root, "INSTALLER_SHA256SUMS"),
    });
    assert.equal(staged.releaseTag, previewTag);

    const verified = verifyReleaseAssets({
      input: dirs.output,
      tag: previewTag,
      commit: COMMIT,
    });
    assert.deepEqual(verified, staged);

    // A preview manifest must not verify against a production tag, and vice
    // versa — the same binding that protects the `v*` path protects this one.
    assert.throws(
      () => verifyReleaseAssets({ input: dirs.output, tag: "v0.10.0" }),
      /tag mismatch/,
    );
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
