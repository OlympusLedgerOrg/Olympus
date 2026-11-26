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
 * collects both.
 *
 * Downloads are pinned twice: the SHA-256 of the `.gz` archive and the SHA-256
 * of the binary it contains. The archive digest is checked on download; the
 * binary digest is checked on every use, so a file planted in the cache (or in
 * the temp fallback) is replaced rather than executed. `TAPLO_BIN` overrides
 * all of this with a binary the caller vouches for.
 *
 * Both digests were computed from the artifacts themselves (trust-on-first-use),
 * so they pin what this repo first fetched: they catch a later tampered or
 * replaced asset, not a compromise at the first download. Upstream publishes no
 * checksum file for 0.10.0, but the archive digests and the linux binary digest
 * agree with independently published copies (mise lockfiles using the aqua
 * backend, and the SourceForge mirror).
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
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";

export const VERSION = "0.10.0";
const TIMEOUT_MS = Number(process.env.TAPLO_TIMEOUT_MS ?? 120_000);
const BASE = `https://github.com/tamasfe/taplo/releases/download/${VERSION}`;

/**
 * Release assets are single-file `.gz` streams on every platform. `binarySha256`
 * is the digest of the decompressed executable, which is what the cache holds.
 */
export const TARGETS = {
  "win32-x64": {
    asset: "taplo-windows-x86_64.gz",
    archiveSha256: "550fdc955343f8a196447a05346ecf8827e391726e4ded577bb00a0a36cf220c",
    binarySha256: "12660d24becf05a78b39133112e91d1bd319b22b8e49660448c222a6858a6827",
  },
  "linux-x64": {
    asset: "taplo-linux-x86_64.gz",
    archiveSha256: "8fe196b894ccf9072f98d4e1013a180306e17d244830b03986ee5e8eabeb6156",
    binarySha256: "dad2faf6377d2daa4f4fabf459fe7ccfb98a5448f0d4bca8270ca9acb0409bfe",
  },
  "darwin-arm64": {
    asset: "taplo-darwin-aarch64.gz",
    archiveSha256: "713734314c3e71894b9e77513c5349835eefbd52908445a0d73b0c7dc469347d",
    binarySha256: "13cd257c1cadb003b40daf82b3fb1451e012e2463b760bdd33df07a07970c604",
  },
  "darwin-x64": {
    asset: "taplo-darwin-x86_64.gz",
    archiveSha256: "898122cde3a0b1cd1cbc2d52d3624f23338218c91b5ddb71518236a4c2c10ef2",
    binarySha256: "9fd7a2872ea154df61a2c7e9ca69fc19ac08e29f2e2dc2f866e299bdc789c1a1",
  },
};

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export function sha256OfBuffer(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

export function sha256OfFile(file) {
  return sha256OfBuffer(readFileSync(file));
}

export function binaryName(platform = process.platform) {
  return platform.startsWith("win32") ? "taplo.exe" : "taplo";
}

export function defaultCacheDir() {
  const modules = path.join(REPO_ROOT, "node_modules");
  if (existsSync(modules)) {
    return path.join(modules, ".cache", "taplo");
  }
  return path.join(tmpdir(), `olympus-taplo-${VERSION}`);
}

export function cachedBinaryPath(cacheDir, platform = process.platform) {
  return path.join(cacheDir, VERSION, binaryName(platform));
}

async function download(target, dest, platform, fetchImpl, log) {
  const url = `${BASE}/${target.asset}`;
  log(`taplo: downloading ${target.asset} (${VERSION})`);
  const response = await fetchImpl(url);
  if (!response.ok) {
    throw new Error(`download failed: ${response.status} ${response.statusText} from ${url}`);
  }

  const archive = Buffer.from(await response.arrayBuffer());
  const archiveDigest = sha256OfBuffer(archive);
  if (archiveDigest !== target.archiveSha256) {
    throw new Error(
      `checksum mismatch for ${target.asset}\n` +
        `  expected ${target.archiveSha256}\n` +
        `  got      ${archiveDigest}`,
    );
  }

  const binary = gunzipSync(archive);
  const binaryDigest = sha256OfBuffer(binary);
  if (binaryDigest !== target.binarySha256) {
    throw new Error(
      `extracted ${target.asset} does not match the pinned binary digest\n` +
        `  expected ${target.binarySha256}\n` +
        `  got      ${binaryDigest}`,
    );
  }

  mkdirSync(path.dirname(dest), { recursive: true });
  writeFileSync(dest, binary);
  if (!platform.startsWith("win32")) {
    chmodSync(dest, 0o755);
  }
}

/**
 * Returns a path to a taplo binary, downloading one when the cache is empty or
 * does not match `binarySha256`. A cached file is never trusted on its
 * behaviour alone — only on its digest — so a planted executable is replaced.
 */
export async function resolveBinary({
  cacheDir = process.env.TAPLO_CACHE_DIR ?? defaultCacheDir(),
  platform = `${process.platform}-${process.arch}`,
  targets = TARGETS,
  fetchImpl = fetch,
  log = (message) => console.error(message),
} = {}) {
  const override = process.env.TAPLO_BIN;
  if (override) {
    if (!existsSync(override)) {
      throw new Error(`TAPLO_BIN points at a missing file: ${override}`);
    }
    return override;
  }

  const target = targets[platform];
  if (!target) {
    throw new Error(
      `no prebuilt taplo ${VERSION} for ${platform}; ` +
        `set TAPLO_BIN to a taplo ${VERSION} binary`,
    );
  }

  const dest = cachedBinaryPath(cacheDir, platform);
  if (existsSync(dest)) {
    if (sha256OfFile(dest) === target.binarySha256) {
      return dest;
    }
    log(`taplo: cached binary at ${dest} does not match the pinned digest; replacing it`);
  }

  await download(target, dest, platform, fetchImpl, log);
  return dest;
}

/**
 * TOML files as git sees them: tracked plus untracked-but-not-ignored. git
 * answers from the index and from `.gitignore`, so it never enters
 * `node_modules`, which is what makes this fast on a slow filesystem.
 *
 * Returns null when git cannot answer, so the caller falls back to the walk.
 * `taplo.toml`'s `exclude` list still applies to the paths we pass through.
 */
export function gitTomlFiles(cwd) {
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
export function isRepoWideFormat(args) {
  if (args[0] !== "format" || args.includes("-")) {
    return false;
  }
  return args.slice(1).every((arg) => arg.startsWith("-"));
}

export async function main(argv = process.argv.slice(2)) {
  const files = isRepoWideFormat(argv) ? gitTomlFiles(process.cwd()) : null;
  const args = files && files.length > 0 ? [...argv, ...files] : argv;

  const binary = await resolveBinary();
  const result = spawnSync(binary, args, { stdio: "inherit", timeout: TIMEOUT_MS });

  if (result.error?.code === "ETIMEDOUT") {
    throw new Error(
      `gave up after ${Math.round(TIMEOUT_MS / 1000)}s — the tree walk is ` +
        `pathologically slow on this filesystem.\n` +
        `  WSL's /mnt/c mount (9p) descends node_modules one stat at a time.\n` +
        `  Run the gate from an ext4 checkout, or pass files explicitly:\n` +
        `    node scripts/taplo.mjs format --check $(git ls-files '*.toml')\n` +
        `  On Windows the gate runs natively in about a second.`,
    );
  }
  if (result.error) {
    throw new Error(result.error.message);
  }
  return result.status ?? 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().then(
    (code) => process.exit(code),
    (error) => {
      console.error(`taplo: ${error.message}`);
      process.exit(1);
    },
  );
}
