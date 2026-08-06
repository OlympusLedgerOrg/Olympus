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
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  copyFileSync,
  mkdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = path.join(REPO_ROOT, ".githooks", "pre-commit");

const IN_CI = process.env.CI === "true";

/**
 * Skip only on a developer machine that lacks the toolchain. In CI a missing
 * tool must FAIL: silently skipping every case would report this suite as
 * green while proving nothing, which is the failure mode these tests exist to
 * prevent elsewhere in the hook.
 */
function skipUnless(available, tool) {
  if (available || IN_CI) return false;
  return `${tool} not installed`;
}

/** rustfmt — the hook shells out to it directly. */
function rustfmtAvailable() {
  return spawnSync("rustfmt", ["--version"], { encoding: "utf8" }).status === 0;
}

/** `cargo fmt` drives the pg-embed-local path. */
function cargoAvailable() {
  return spawnSync("cargo", ["fmt", "--version"], { encoding: "utf8" }).status === 0;
}

function git(cwd, ...args) {
  return execFileSync("git", args, { cwd, encoding: "utf8" });
}

/**
 * A minimal `pg-embed-local` crate, committed, so the hook's
 * `cargo fmt --manifest-path pg-embed-local/Cargo.toml --all` step has a real
 * package to format. `lib.rs` declares `mod other` so `--all` actually reaches
 * `other.rs` — without that the write-scope test would pass vacuously.
 */
function makePgEmbedCrate(dir) {
  const crate = path.join(dir, "pg-embed-local");
  mkdirSync(path.join(crate, "src"), { recursive: true });
  writeFileSync(
    path.join(crate, "Cargo.toml"),
    '[package]\nname = "pg-embed-local"\nversion = "0.0.0"\nedition = "2021"\n\n[lib]\npath = "src/lib.rs"\n',
  );
  writeFileSync(
    path.join(crate, "src", "lib.rs"),
    "pub mod other;\npub fn base() -> u8 {\n    1\n}\n",
  );
  writeFileSync(path.join(crate, "src", "other.rs"), "pub fn wip() -> u8 {\n    9\n}\n");
  git(dir, "add", "-A");
  git(dir, "commit", "--quiet", "--no-verify", "-m", "crate");
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
  { skip: skipUnless(rustfmtAvailable(), "rustfmt") },
  () => {
    const dir = makeRepo();
    try {
      const file = path.join(dir, "src", "lib.rs");

      // Staged: a badly formatted function the hook is expected to format.
      writeFileSync(file, "pub fn kept() -> u8 {\n    1\n}\npub fn staged()->u8{2}\n");
      git(dir, "add", "src/lib.rs");

      // Unstaged, on top: work in progress that must NOT be committed. Note it
      // is deliberately left unformatted — the hook must not reformat it
      // either, so the byte comparison below is the real assertion.
      writeFileSync(
        file,
        "pub fn kept() -> u8 {\n    1\n}\npub fn staged()->u8{2}\npub fn UNSTAGED_MARKER(){}\n",
      );
      const before = readFileSync(file);

      runHook(dir);

      const staged = git(dir, "diff", "--cached");
      assert.match(staged, /pub fn staged/, "the staged function should be in the index");
      assert.doesNotMatch(
        staged,
        /UNSTAGED_MARKER/,
        "unstaged work must never be swept into the index by the hook's re-staging",
      );

      // The whole working-tree file must come back byte-for-byte. Checking only
      // that the marker survived would still pass if the hook had reformatted
      // the developer's in-progress file around it.
      assert.deepEqual(
        readFileSync(file),
        before,
        "the working-tree file must be restored byte-for-byte",
      );

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
  "an unstaged DELETION is preserved, not undone by the restore",
  { skip: skipUnless(rustfmtAvailable(), "rustfmt") },
  () => {
    const dir = makeRepo();
    try {
      const file = path.join(dir, "src", "lib.rs");

      // Staged edit, then the developer deletes the file without staging it.
      writeFileSync(file, "pub fn kept() -> u8 {\n    1\n}\npub fn staged()->u8{2}\n");
      git(dir, "add", "src/lib.rs");
      rmSync(file);

      runHook(dir);

      // The backup loop must not try to copy a path that is gone (that failed
      // the hook outright under `set -e`), and the restore must re-apply the
      // deletion rather than resurrecting the file.
      assert.equal(
        existsSync(file),
        false,
        "an unstaged deletion must survive the hook, not be undone",
      );
      assert.match(
        git(dir, "show", ":src/lib.rs"),
        /pub fn staged\(\) -> u8 \{\n {4}2\n\}/,
        "the staged content should still be formatted and staged",
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "an unstaged-only file inside cargo fmt --all's write scope is not rewritten",
  { skip: skipUnless(cargoAvailable(), "cargo") },
  () => {
    const dir = makeRepo();
    try {
      makePgEmbedCrate(dir);
      const other = path.join(dir, "pg-embed-local", "src", "other.rs");

      // Stage an edit to one crate file...
      writeFileSync(
        path.join(dir, "pg-embed-local", "src", "lib.rs"),
        "pub mod other;\npub fn staged()->u8{2}\n",
      );
      git(dir, "add", "pg-embed-local/src/lib.rs");

      // ...and leave a DIFFERENT crate file modified but never staged. It is
      // deliberately unformatted: `cargo fmt --all` rewrites the whole crate,
      // so without an explicit write scope the hook reformats this file in
      // place and the developer's in-progress bytes are silently lost.
      const unstagedOnly = "pub fn wip()->u8{  9  }\n";
      writeFileSync(other, unstagedOnly);

      runHook(dir);

      assert.equal(
        readFileSync(other, "utf8"),
        unstagedOnly,
        "an unstaged-only file in the formatter's write scope must keep its bytes",
      );
      assert.equal(
        git(dir, "diff", "--cached", "--name-only").includes("other.rs"),
        false,
        "an unstaged-only file must never enter the index",
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "a file with only staged changes is formatted and staged as before",
  { skip: skipUnless(rustfmtAvailable(), "rustfmt") },
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
