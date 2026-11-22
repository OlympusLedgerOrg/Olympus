// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { parseArgs } from "../bin/wiserepo.mjs";

const execFileAsync = promisify(execFile);
const CLI = fileURLToPath(new URL("../bin/wiserepo.mjs", import.meta.url));
const MAX_BUFFER = 16 * 1024 * 1024;

test("cli context prints the parsed context.json", async () => {
  const { stdout } = await execFileAsync(process.execPath, [CLI, "context"], {
    maxBuffer: MAX_BUFFER,
  });
  const parsed = JSON.parse(stdout);
  assert.equal(parsed.source, "context.json");
  assert.equal(parsed.data.project, "Olympus");
});

test("cli tools lists all six tools", async () => {
  const { stdout } = await execFileAsync(process.execPath, [CLI, "tools"], {
    maxBuffer: MAX_BUFFER,
  });
  for (const name of [
    "olympus_context",
    "circuit_status",
    "check_invariants",
    "repo_qa",
    "review_diff",
    "summarize",
  ]) {
    assert.match(stdout, new RegExp(`\\b${name}\\b`));
  }
});

test("cli invariants --check exits 0 when every pinned constant is found", async () => {
  const { stdout } = await execFileAsync(process.execPath, [CLI, "invariants", "--check"], {
    maxBuffer: MAX_BUFFER,
  });
  const parsed = JSON.parse(stdout);
  const lazy = parsed.invariants.find((inv) => inv.id === "LAZY_DEPTH");
  assert.ok(lazy, "LAZY_DEPTH should be present");
  assert.equal(lazy.found_in_all_files, true);
});

test("cli rejects an unknown command with exit code 1", async () => {
  await assert.rejects(
    () => execFileAsync(process.execPath, [CLI, "not-a-command"], { maxBuffer: MAX_BUFFER }),
    (err) => err.code === 1,
  );
});

test("parseArgs takes everything after --diff-args as git diff args", () => {
  const parsed = parseArgs(["review", "--diff-args", "main...HEAD", "--stat"]);
  assert.equal(parsed.command, "review");
  assert.deepEqual(parsed.diffArgs, ["main...HEAD", "--stat"]);
});

test("parseArgs collects repeated files and a grep pattern", () => {
  const parsed = parseArgs([
    "qa",
    "how?",
    "-f",
    "CLAUDE.md",
    "--file",
    "AGENTS.md",
    "--grep",
    "leaf_hash",
  ]);
  assert.equal(parsed.command, "qa");
  assert.deepEqual(parsed.files, ["CLAUDE.md", "AGENTS.md"]);
  assert.equal(parsed.grep, "leaf_hash");
  assert.deepEqual(parsed.positional, ["how?"]);
});
