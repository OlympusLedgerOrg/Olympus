#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The cache is the weak point of a checksum-pinned downloader: a file already
 * on disk is never fetched, so a launcher that trusts it on behaviour alone
 * executes whatever answers `taplo 0.10.0`. These tests plant exactly that file
 * — wrong bytes, right version string — and assert it is replaced.
 */

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { cachedBinaryPath, isRepoWideFormat, resolveBinary, sha256OfBuffer } from "./taplo.mjs";

// The launcher honours TAPLO_BIN before any cache lookup; clear it so the tests
// exercise the cache and download paths regardless of the caller's environment.
delete process.env.TAPLO_BIN;

/** Wrong bytes that still print the pinned version — the old trust model. */
const PLANTED = Buffer.from("#!/bin/sh\n# planted\necho 'taplo 0.10.0'\n");

const FAKE_BINARY = Buffer.from("#!/bin/sh\necho 'taplo 0.10.0'\n");
const FAKE_ARCHIVE = gzipSync(FAKE_BINARY);
const TARGET = {
  asset: "taplo-test.gz",
  archiveSha256: sha256OfBuffer(FAKE_ARCHIVE),
  binarySha256: sha256OfBuffer(FAKE_BINARY),
};

const quiet = () => {};

function tempCache() {
  return mkdtempSync(path.join(tmpdir(), "taplo-cache-"));
}

function countingFetch(archive = FAKE_ARCHIVE) {
  const calls = [];
  const impl = async (url) => {
    calls.push(url);
    return { ok: true, status: 200, statusText: "OK", arrayBuffer: async () => archive };
  };
  impl.calls = calls;
  return impl;
}

function resolveWith(cache, fetcher) {
  return resolveBinary({
    cacheDir: cache,
    platform: "linux-x64",
    targets: { "linux-x64": TARGET },
    fetchImpl: fetcher,
    log: quiet,
  });
}

test("a planted cached binary is replaced instead of executed", async (t) => {
  const cache = tempCache();
  t.after(() => rmSync(cache, { recursive: true, force: true }));

  const dest = cachedBinaryPath(cache, "linux-x64");
  mkdirSync(path.dirname(dest), { recursive: true });
  writeFileSync(dest, PLANTED);
  assert.notEqual(sha256OfBuffer(PLANTED), TARGET.binarySha256);

  const fetcher = countingFetch();
  const resolved = await resolveWith(cache, fetcher);

  assert.equal(resolved, dest);
  assert.equal(fetcher.calls.length, 1, "the planted file must be re-downloaded");
  assert.deepEqual(readFileSync(dest), FAKE_BINARY);
});

test("a cached binary with the pinned digest is reused without downloading", async (t) => {
  const cache = tempCache();
  t.after(() => rmSync(cache, { recursive: true, force: true }));

  const dest = cachedBinaryPath(cache, "linux-x64");
  mkdirSync(path.dirname(dest), { recursive: true });
  writeFileSync(dest, FAKE_BINARY);

  const fetcher = countingFetch();
  const resolved = await resolveWith(cache, fetcher);

  assert.equal(resolved, dest);
  assert.equal(fetcher.calls.length, 0, "a matching cache entry must not hit the network");
});

test("an archive that does not match its pinned digest is rejected", async (t) => {
  const cache = tempCache();
  t.after(() => rmSync(cache, { recursive: true, force: true }));

  const fetcher = countingFetch(gzipSync(Buffer.from("some other build\n")));
  await assert.rejects(resolveWith(cache, fetcher), /checksum mismatch/);
});

test("a rebuilt archive whose binary digest differs is rejected", async (t) => {
  const cache = tempCache();
  t.after(() => rmSync(cache, { recursive: true, force: true }));

  const archive = gzipSync(PLANTED);
  const target = {
    asset: "taplo-test.gz",
    archiveSha256: sha256OfBuffer(archive),
    binarySha256: TARGET.binarySha256,
  };
  await assert.rejects(
    resolveBinary({
      cacheDir: cache,
      platform: "linux-x64",
      targets: { "linux-x64": target },
      fetchImpl: countingFetch(archive),
      log: quiet,
    }),
    /pinned binary digest/,
  );
});

test("an unsupported platform names TAPLO_BIN in the failure", async (t) => {
  const cache = tempCache();
  t.after(() => rmSync(cache, { recursive: true, force: true }));

  await assert.rejects(
    resolveBinary({ cacheDir: cache, platform: "aix-ppc64", targets: {}, log: quiet }),
    /set TAPLO_BIN/,
  );
});

test("only path-free format invocations are repo-wide", () => {
  assert.equal(isRepoWideFormat(["format"]), true);
  assert.equal(isRepoWideFormat(["format", "--check"]), true);
  assert.equal(isRepoWideFormat(["format", "--check", "Cargo.toml"]), false);
  assert.equal(isRepoWideFormat(["format", "-"]), false);
  assert.equal(isRepoWideFormat(["--version"]), false);
});

test("the Windows target caches an .exe", () => {
  assert.match(cachedBinaryPath("/cache", "win32-x64"), /taplo\.exe$/);
  assert.match(cachedBinaryPath("/cache", "linux-x64"), /[/\\]taplo$/);
});
