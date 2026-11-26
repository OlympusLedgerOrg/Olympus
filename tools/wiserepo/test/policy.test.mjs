// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { PolicyError } from "../../agent-policy/policy.mjs";
import { gatherContext, runTool } from "../src/mcp-server.mjs";

const execFileAsync = promisify(execFile);
const CLI = fileURLToPath(new URL("../bin/wiserepo.mjs", import.meta.url));

// These assert the refusal itself, not its wording, because the refusal is the
// security boundary: a reworded message must not be able to turn into a pass.

test("repo_qa refuses a protected file before reading it", async () => {
  await assert.rejects(
    () => runTool("repo_qa", { question: "what does this do", files: ["src-tauri/src/main.rs"] }),
    PolicyError,
  );
});

test("repo_qa refuses the agent instructions file", async () => {
  await assert.rejects(
    () => runTool("repo_qa", { question: "q", files: ["AGENTS.md"] }),
    PolicyError,
  );
});

test("summarize refuses a protected file", async () => {
  await assert.rejects(
    () => runTool("summarize", { files: ["crates/olympus-core/src/lib.rs"] }),
    PolicyError,
  );
});

test("grep hits are checked even when no file list is given", async () => {
  // "pub fn" matches under crates/, which is never sendable.
  await assert.rejects(() => runTool("repo_qa", { question: "q", grep: "pub fn" }), PolicyError);
});

test("an allowlisted path still reaches gatherContext", async () => {
  const context = await gatherContext({
    files: ["docs/court-evidence.md"],
    taskClass: "summarize",
  });
  assert.match(context, /## docs\/court-evidence\.md/);
});

test("the refusal is final: it names the path and says not to work around it", async () => {
  await assert.rejects(
    () => runTool("summarize", { files: ["proofs/leaf.circom"] }),
    (error) => {
      assert.ok(error instanceof PolicyError);
      assert.match(error.message, /proofs\/leaf\.circom/);
      assert.match(error.message, /do not retry, rephrase/);
      return true;
    },
  );
});

test("the CLI goes through the same guard", async () => {
  await assert.rejects(
    () =>
      execFileAsync(process.execPath, [
        CLI,
        "qa",
        "what does this do",
        "-f",
        "src-tauri/src/main.rs",
      ]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /agent policy/);
      assert.match(error.stderr, /src-tauri\/src\/main\.rs/);
      return true;
    },
  );
});
