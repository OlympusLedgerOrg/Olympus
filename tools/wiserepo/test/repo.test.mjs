// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { existsSync, rmSync, mkdtempSync, writeFileSync, symlinkSync } from "node:fs";
import os from "node:os";
import {
  resolveInRepo,
  resolveInRepoFollowingSymlinks,
  readRepoFile,
  truncateText,
  wouldTruncate,
  sanitizeDiffArgs,
  gitDiff,
  gitGrep,
  repoRoot,
} from "../src/repo.mjs";

test("resolveInRepo allows a plain relative path inside the repo", () => {
  const resolved = resolveInRepo("CLAUDE.md");
  assert.ok(resolved.endsWith("CLAUDE.md"));
});

test("resolveInRepo allows the repo root itself", () => {
  // Asserts the actual contract (equals repoRoot()), not a hardcoded
  // basename — the old assertion broke in any checkout not named "Olympus"
  // (a fork, a differently named CI workspace, WISEREPO_ROOT set).
  const resolved = resolveInRepo(".");
  assert.equal(resolved, path.resolve(repoRoot()));
});

test("resolveInRepo rejects a simple parent-directory escape", () => {
  assert.throws(() => resolveInRepo("../outside.txt"), /escapes the repo root/);
});

test("resolveInRepo rejects a deep parent-directory escape", () => {
  assert.throws(() => resolveInRepo("../../../etc/passwd"), /escapes the repo root/);
});

test("resolveInRepo rejects an absolute path outside the repo", () => {
  const outside = process.platform === "win32" ? "C:\\Windows\\System32\\config" : "/etc/passwd";
  assert.throws(() => resolveInRepo(outside), /escapes the repo root/);
});

test("resolveInRepo rejects a sibling directory whose name merely starts with the repo dir name", () => {
  // Regression guard for the classic `startsWith(root)` bug: a sibling like
  // `Olympus-evil` must NOT be treated as inside `Olympus` just because the
  // string "Olympus" is a prefix.
  const root = resolveInRepo(".");
  const siblingLookalike = root + "-evil" + path.sep + "file.txt";
  assert.throws(() => resolveInRepo(siblingLookalike), /escapes the repo root/);
});

test("truncateText leaves short text untouched", () => {
  assert.equal(truncateText("hello", 100, "test"), "hello");
});

test("truncateText cuts long text and notes how much was dropped", () => {
  const long = "x".repeat(1000);
  const result = truncateText(long, 100, "test-label");
  assert.equal(result.slice(0, 100), "x".repeat(100));
  assert.match(result, /truncated 900 of 1000 chars from test-label/);
});

// ── diffArgs option-injection guard ────────────────────────────────────────
// These exist because an unguarded `git diff` splat let `--output=PATH` write
// an arbitrary file outside the repo. That was reproduced live before the fix.

test("sanitizeDiffArgs rejects --output (the arbitrary-write vector)", () => {
  assert.throws(() => sanitizeDiffArgs(["--output=/tmp/pwn.txt", "HEAD"]), /not permitted/);
});

test("sanitizeDiffArgs rejects any --flag=value form", () => {
  assert.throws(() => sanitizeDiffArgs(["--src-prefix=/tmp/x"]), /not permitted/);
});

test("sanitizeDiffArgs rejects a flag that is not on the allowlist", () => {
  assert.throws(() => sanitizeDiffArgs(["--ext-diff"]), /not in wiserepo's allowlist/);
});

test("sanitizeDiffArgs rejects an orderfile short flag", () => {
  assert.throws(() => sanitizeDiffArgs(["-O/etc/passwd"]), /allowlist|not permitted/);
});

test("sanitizeDiffArgs permits ordinary revisions and ranges", () => {
  assert.deepEqual(sanitizeDiffArgs(["HEAD"]), ["HEAD", "--"]);
  assert.deepEqual(sanitizeDiffArgs(["main...HEAD"]), ["main...HEAD", "--"]);
  assert.deepEqual(sanitizeDiffArgs(["v1.0..v2.0"]), ["v1.0..v2.0", "--"]);
});

test("sanitizeDiffArgs permits allowlisted flags and orders them before revisions", () => {
  assert.deepEqual(sanitizeDiffArgs(["HEAD", "--cached", "--stat"]), [
    "--cached",
    "--stat",
    "HEAD",
    "--",
  ]);
});

test("sanitizeDiffArgs always terminates with -- so a revision cannot be read as a path", () => {
  assert.equal(sanitizeDiffArgs(["HEAD"]).at(-1), "--");
});

test("sanitizeDiffArgs confines post-dash-dash pathspecs to the repo", () => {
  assert.throws(
    () => sanitizeDiffArgs(["HEAD", "--", "../../etc/passwd"]),
    /escapes the repo root/,
  );
  assert.deepEqual(sanitizeDiffArgs(["HEAD", "--", "CLAUDE.md"]), ["HEAD", "--", "CLAUDE.md"]);
});

test("sanitizeDiffArgs rejects a non-string argument", () => {
  assert.throws(() => sanitizeDiffArgs([{ evil: true }]), /must be strings/);
});

test("gitDiff does NOT write a file outside the repo when handed --output", async () => {
  // End-to-end proof the guard holds at the call site, not just in the
  // sanitizer: this exact call previously wrote 7748 bytes to disk.
  const target = path.join(process.env.TEMP || "/tmp", "wiserepo-guard-check.txt");
  rmSync(target, { force: true });
  await assert.rejects(() => gitDiff([`--output=${target}`, "HEAD"]), /not permitted/);
  assert.equal(existsSync(target), false, "guard failed: a file was written outside the repo");
});

// ── symlink escape (read-side exfiltration) ────────────────────────────────
// resolveInRepo is a lexical string check; it does not follow symlinks. A
// repo-tracked symlink pointing outside the repo passes that check, and
// unguarded stat()/readFile() would follow it and return the TARGET's
// content — which readRepoFile puts straight into a prompt sent to a third
// -party model API. This is worse than the diffArgs write bug above: it
// exfiltrates arbitrary readable files, not just writes one inside a temp
// dir. Skipped where symlink creation requires elevated privilege (some
// Windows configurations) rather than failing the suite on an environment
// limitation unrelated to the code under test.

const canSymlink = (() => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "wiserepo-symlink-check-"));
  try {
    const target = path.join(dir, "target.txt");
    const link = path.join(dir, "link.txt");
    writeFileSync(target, "x");
    symlinkSync(target, link);
    return true;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
})();

test(
  "resolveInRepoFollowingSymlinks rejects a symlink that escapes the repo root",
  { skip: !canSymlink && "symlink creation not permitted in this environment" },
  async () => {
    const outsideDir = mkdtempSync(path.join(os.tmpdir(), "wiserepo-outside-"));
    const secret = path.join(outsideDir, "secret.txt");
    writeFileSync(secret, "outside-repo-content-that-must-not-leak");

    const linkPath = path.join(repoRoot(), "wiserepo-test-symlink-escape.txt");
    rmSync(linkPath, { force: true });
    try {
      symlinkSync(secret, linkPath);
      // Lexically inside the repo, so resolveInRepo alone would pass this.
      assert.doesNotThrow(() => resolveInRepo("wiserepo-test-symlink-escape.txt"));
      // The symlink-aware check must catch what the lexical one misses.
      await assert.rejects(
        () => resolveInRepoFollowingSymlinks("wiserepo-test-symlink-escape.txt"),
        /outside the repo root|resolves outside/,
      );
      // readRepoFile is the actual exfiltration path — prove it refuses too.
      await assert.rejects(() => readRepoFile("wiserepo-test-symlink-escape.txt"));
    } finally {
      rmSync(linkPath, { force: true });
      rmSync(outsideDir, { recursive: true, force: true });
    }
  },
);

test(
  "resolveInRepoFollowingSymlinks allows a symlink that stays inside the repo",
  { skip: !canSymlink && "symlink creation not permitted in this environment" },
  async () => {
    const linkPath = path.join(repoRoot(), "wiserepo-test-symlink-internal.txt");
    rmSync(linkPath, { force: true });
    try {
      symlinkSync(path.join(repoRoot(), "CLAUDE.md"), linkPath);
      const real = await resolveInRepoFollowingSymlinks("wiserepo-test-symlink-internal.txt");
      assert.equal(real, path.resolve(repoRoot(), "CLAUDE.md"));
    } finally {
      rmSync(linkPath, { force: true });
    }
  },
);

// ── wouldTruncate ───────────────────────────────────────────────────────────

test("wouldTruncate matches truncateText's actual cut decision, including near the boundary", () => {
  // truncateText's own output can be LONGER than input for a small overflow
  // (the appended note adds ~55 chars), so a naive length comparison at a
  // call site can miss a real truncation. wouldTruncate must not have that
  // blind spot.
  const text = "x".repeat(101);
  assert.equal(wouldTruncate(text, 100), true);
  assert.ok(
    truncateText(text, 100, "t").length > text.length,
    "sanity: note pushed output longer than input",
  );
  assert.equal(wouldTruncate("x".repeat(100), 100), false);
});

// ── gitGrep globs ────────────────────────────────────────────────────────────
// Regression for the double `--` bug: git only treats the FIRST `--` as the
// options/pathspec separator. Inserting another `--` before each glob turned
// every glob after the first into a literal pathspec named `--`, so a
// caller passing globs got "no matches" even for a pattern that matches.
// Not reachable via gatherContext today (it never passes globs), but the
// function is part of the public module surface.

test("gitGrep with globs actually finds matches (regression: double -- silently matched nothing)", async () => {
  const hits = await gitGrep("Absolute Upstream Boundary", { globs: ["CLAUDE.md"] });
  assert.match(hits, /CLAUDE\.md/);
});

test("gitGrep rejects a glob that looks like a flag", async () => {
  await assert.rejects(() => gitGrep("x", { globs: ["--evil"] }), /Disallowed grep pathspec/);
});
