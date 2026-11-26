#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Runs the native taplo binary, fetching it once per machine.
 *
 * Why not `@taplo/cli`: that npm package stops at 0.7.0 and bundles a WASM
 * taplo whose file collection is broken on Windows. There `taplo format
 * --check` collects zero files and exits 0 — even when handed an explicit
 * filename — so `format:toml:check` was a silent no-op on Windows while CI
 * (Linux) enforced it. Its glob walker also skips dot-directories everywhere,
 * so `.cargo/*.toml`, `.config/*.toml` and `.gitleaks.toml` were never checked
 * on any platform.
 *
 * The native release is current (0.10.0), is the same binary on every OS, and
 * collects both. Downloads are pinned by version and per-platform SHA-256 of
 * the `.gz` archive; `TAPLO_BIN` overrides it with a system install.
 *
 * WSL caveat: reading the repository through the `/mnt/c` 9p mount makes the
 * walk into `node_modules` take minutes, because pnpm's Windows junctions are
 * traversed one stat at a time. Run the gate from an ext4 checkout there.
 * Native Windows and native Linux both finish in about a second.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { gunzipSync } from "node:zlib";

const VERSION = "0.10.0";
const BASE = `https://github.com/tamasfe/taplo/releases/download/${VERSION}`;

/** Release assets are single-file `.gz` streams on every platform. */
const TARGETS = {
  "win32-x64": {
    asset: "taplo-windows-x86_64.gz",
    sha256: "550fdc955343f8a196447a05346ecf8827e391726e4ded577bb00a0a36cf220c",
  },
  "linux-x64": {
    asset: "taplo-linux-x86_64.gz",
    sha256: "8fe196b894ccf9072f98d4e1013a180306e17d244830b03986ee5e8eabeb6156",
  },
  "darwin-arm64": {
    asset: "taplo-darwin-aarch64.gz",
    sha256: "713734314c3e71894b9e77513c5349835eefbd52908445a0d73b0c7dc469347d",
  },
  "darwin-x64": {
    asset: "taplo-darwin-x86_64.gz",
    sha256: "898122cde3a0b1cd1cbc2d52d3624f23338218c91b5ddb71518236a4c2c10ef2",
  },
};

const REPO_ROOT = path.resolve(import.meta.dirname, "..");
const BIN_NAME = process.platform === "win32" ? "taplo.exe" : "taplo";

function fail(message) {
  console.error(`taplo: ${message}`);
  process.exit(1);
}

function cachePath() {
  const modules = path.join(REPO_ROOT, "node_modules");
  if (existsSync(modules)) {
    return path.join(modules, ".cache", "taplo", VERSION, BIN_NAME);
  }
  return path.join(tmpdir(), `olympus-taplo-${VERSION}`, BIN_NAME);
}

function runsPinnedVersion(bin) {
  const probe = spawnSync(bin, ["--version"], { encoding: "utf8" });
  return probe.status === 0 && probe.stdout.trim() === `taplo ${VERSION}`;
}

async function download(target, dest) {
  const url = `${BASE}/${target.asset}`;
  console.error(`taplo: downloading ${target.asset} (${VERSION})`);
  const response = await fetch(url);
  if (!response.ok) {
    fail(`download failed: ${response.status} ${response.statusText} from ${url}`);
  }
  const archive = Buffer.from(await response.arrayBuffer());
  const digest = createHash("sha256").update(archive).digest("hex");
  if (digest !== target.sha256) {
    fail(
      `checksum mismatch for ${target.asset}\n` +
        `  expected ${target.sha256}\n` +
        `  got      ${digest}`,
    );
  }
  mkdirSync(path.dirname(dest), { recursive: true });
  writeFileSync(dest, gunzipSync(archive));
  if (process.platform !== "win32") {
    chmodSync(dest, 0o755);
  }
}

async function resolveBinary() {
  const override = process.env.TAPLO_BIN;
  if (override) {
    if (!existsSync(override)) {
      fail(`TAPLO_BIN points at a missing file: ${override}`);
    }
    return override;
  }

  const dest = cachePath();
  if (existsSync(dest) && runsPinnedVersion(dest)) {
    return dest;
  }

  const target = TARGETS[`${process.platform}-${process.arch}`];
  if (!target) {
    fail(
      `no prebuilt taplo ${VERSION} for ${process.platform}-${process.arch}; ` +
        `set TAPLO_BIN to a taplo ${VERSION} binary`,
    );
  }

  await download(target, dest);
  if (!runsPinnedVersion(dest)) {
    fail(`downloaded binary did not run: ${dest}`);
  }
  return dest;
}

const binary = await resolveBinary();
const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  fail(result.error.message);
}
process.exit(result.status ?? 1);
