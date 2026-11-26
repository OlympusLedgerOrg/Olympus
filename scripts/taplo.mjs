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
 * Repo-wide runs enumerate their files through git instead of letting taplo
 * walk the tree. Walking is pathologically slow on WSL's `/mnt/c` mount, where
 * the 9p layer descends `node_modules` one stat at a time because pnpm's
 * Windows junctions look like ordinary directories; the git view skips it
 * entirely. If git cannot answer, the walk is used and the timeout below turns
 * what would be a six-minute hang into an actionable error.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { gunzipSync } from "node:zlib";

const VERSION = "0.10.0";
const TIMEOUT_MS = Number(process.env.TAPLO_TIMEOUT_MS ?? 120_000);
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

/**
 * TOML files as git sees them: tracked plus untracked-but-not-ignored. git
 * answers from the index and from `.gitignore`, so it never enters
 * `node_modules`, which is what makes this fast on a slow filesystem.
 *
 * Returns null when git cannot answer, so the caller falls back to the walk.
 * `taplo.toml`'s `exclude` list still applies to the paths we pass through.
 */
function gitTomlFiles(cwd) {
  const inside = spawnSync("git", ["rev-parse", "--is-inside-work-tree"], {
    cwd,
    encoding: "utf8",
  });
  if (inside.status !== 0 || inside.stdout.trim() !== "true") {
    return null;
  }
  const listed = spawnSync(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.toml"],
    { cwd, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  if (listed.status !== 0) {
    return null;
  }
  return listed.stdout
    .split("\0")
    .filter((file) => file.length > 0)
    .filter((file) => existsSync(path.resolve(cwd, file)));
}

/**
 * True for `format` / `format --check` with no file arguments. Explicit paths
 * and stdin (`-`) are passed through untouched.
 */
function isRepoWideFormat(args) {
  if (args[0] !== "format" || args.includes("-")) {
    return false;
  }
  return args.slice(1).every((arg) => arg.startsWith("-"));
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

const args = process.argv.slice(2);
const files = isRepoWideFormat(args) ? gitTomlFiles(process.cwd()) : null;
const argv = files && files.length > 0 ? [...args, ...files] : args;

const binary = await resolveBinary();
const result = spawnSync(binary, argv, { stdio: "inherit", timeout: TIMEOUT_MS });

if (result.error?.code === "ETIMEDOUT") {
  fail(
    `gave up after ${Math.round(TIMEOUT_MS / 1000)}s — the tree walk is ` +
      `pathologically slow on this filesystem.\n` +
      `  WSL's /mnt/c mount (9p) descends node_modules one stat at a time.\n` +
      `  Run the gate from an ext4 checkout, or pass files explicitly:\n` +
      `    node scripts/taplo.mjs format --check $(git ls-files '*.toml')\n` +
      `  On Windows the gate runs natively in about a second.`,
  );
}
if (result.error) {
  fail(result.error.message);
}
process.exit(result.status ?? 1);
