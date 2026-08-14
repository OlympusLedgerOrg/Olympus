// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { existsSync, rmSync } from "node:fs";
import { resolveInRepo, truncateText, sanitizeDiffArgs, gitDiff } from "../src/repo.mjs";

test("resolveInRepo allows a plain relative path inside the repo", () => {
  const resolved = resolveInRepo("CLAUDE.md");
  assert.ok(resolved.endsWith("CLAUDE.md"));
});

test("resolveInRepo allows the repo root itself", () => {
  const resolved = resolveInRepo(".");
  assert.equal(path.basename(resolved), "Olympus");
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
