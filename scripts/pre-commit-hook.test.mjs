#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Regression coverage for `.githooks/pre-commit`'s re-staging behaviour.
//
// The hook auto-formats staged Rust files and re-stages the result. It used to
// do that with a bare `git add <file>`, which stages the WHOLE working-tree
// file — so a file carrying both staged and unstaged hunks had its unstaged,
// in-progress work swept into the commit, already reformatted in place and
// therefore hard to notice. These tests pin the fixed behaviour: what was
// staged gets formatted and committed, and what was not staged stays out of
// the index and stays in the working tree.
//
// The tests build a throwaway git repo and invoke the hook directly. The hook's
// later `cargo clippy` step fails there (no cargo workspace), which is fine and
// deliberate: formatting and staging happen first, so the index state under
// test is already final by then, and the assertions never look at the exit code.

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, copyFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = path.join(REPO_ROOT, ".githooks", "pre-commit");

/** rustfmt is required — the hook shells out to it. Skip rather than fail. */
function rustfmtAvailable() {
  return spawnSync("rustfmt", ["--version"], { encoding: "utf8" }).status === 0;
}

function git(cwd, ...args) {
  return execFileSync("git", args, { cwd, encoding: "utf8" });
}

/**
 * A throwaway repo containing one committed, already-formatted Rust file.
 * Returns the repo path; caller removes it.
 */
function makeRepo() {
  const dir = mkdtempSync(path.join(tmpdir(), "olympus-hook-"));
  git(dir, "init", "--quiet");
  git(dir, "config", "user.email", "test@example.invalid");
  git(dir, "config", "user.name", "Hook Test");
  mkdirSync(path.join(dir, "src"), { recursive: true });
  writeFileSync(path.join(dir, "src", "lib.rs"), "pub fn kept() -> u8 {\n    1\n}\n");
  git(dir, "add", "-A");
  git(dir, "commit", "--quiet", "--no-verify", "-m", "base");
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  copyFileSync(HOOK, path.join(dir, ".githooks", "pre-commit"));
  return dir;
}

/** Run the hook in `cwd`, ignoring its exit code (see file header). */
function runHook(cwd) {
  return spawnSync("bash", [path.join(cwd, ".githooks", "pre-commit")], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, OLYMPUS_SKIP_PRECOMMIT: "0" },
  });
}

test(
  "a file with staged AND unstaged changes keeps the unstaged part out of the index",
  { skip: rustfmtAvailable() ? false : "rustfmt not installed" },
  () => {
    const dir = makeRepo();
    try {
      const file = path.join(dir, "src", "lib.rs");

      // Staged: a badly formatted function the hook is expected to format.
      writeFileSync(file, "pub fn kept() -> u8 {\n    1\n}\npub fn staged()->u8{2}\n");
      git(dir, "add", "src/lib.rs");

      // Unstaged, on top: work in progress that must NOT be committed.
      writeFileSync(
        file,
        "pub fn kept() -> u8 {\n    1\n}\npub fn staged()->u8{2}\npub fn UNSTAGED_MARKER() {}\n",
      );

      runHook(dir);

      const staged = git(dir, "diff", "--cached");
      assert.match(staged, /pub fn staged/, "the staged function should be in the index");
      assert.doesNotMatch(
        staged,
        /UNSTAGED_MARKER/,
        "unstaged work must never be swept into the index by the hook's re-staging",
      );

      // And it must still be present as an unstaged working-tree change.
      const unstaged = git(dir, "diff");
      assert.match(unstaged, /UNSTAGED_MARKER/, "unstaged work must survive in the working tree");

      // The staged content is the FORMATTED version, not the raw staged bytes —
      // otherwise the commit would carry unformatted code and CI's fmt gate,
      // which the hook exists to pre-empt, would reject it.
      const stagedBlob = git(dir, "show", ":src/lib.rs");
      assert.match(
        stagedBlob,
        /pub fn staged\(\) -> u8 \{\n {4}2\n\}/,
        "the hook should stage the formatted staged content",
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "a file with only staged changes is formatted and staged as before",
  { skip: rustfmtAvailable() ? false : "rustfmt not installed" },
  () => {
    const dir = makeRepo();
    try {
      writeFileSync(path.join(dir, "src", "lib.rs"), "pub fn only_staged()->u8{7}\n");
      git(dir, "add", "src/lib.rs");

      runHook(dir);

      assert.match(
        git(dir, "show", ":src/lib.rs"),
        /pub fn only_staged\(\) -> u8 \{\n {4}7\n\}/,
        "the no-unstaged-changes path must still format and re-stage",
      );
      assert.equal(git(dir, "diff").trim(), "", "working tree should match the index");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
