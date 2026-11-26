// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// The CLI (bin/wiserepo.mjs) and the MCP transport share runTool, but only the
// CLI was ever exercised: a broken stdio bootstrap, a tool schema the SDK
// rejects, or a handshake regression would not have failed a single test.
// This drives the real server over a real pipe.

import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { repoRoot } from "../src/repo.mjs";

const SERVER_PATH = fileURLToPath(new URL("../src/mcp-server.mjs", import.meta.url));

test(
  "MCP stdio server completes a handshake, lists its tools and answers a no-model call",
  { timeout: 120_000 },
  async () => {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [SERVER_PATH],
      cwd: repoRoot(),
      stderr: "ignore",
    });
    const client = new Client({ name: "wiserepo-test", version: "0.0.0" }, { capabilities: {} });
    try {
      await client.connect(transport);

      const { tools } = await client.listTools();
      const names = tools.map((tool) => tool.name);
      for (const expected of [
        "repo_qa",
        "review_diff",
        "summarize",
        "olympus_context",
        "circuit_status",
        "check_invariants",
      ]) {
        assert.ok(names.includes(expected), `missing tool "${expected}" in ${names.join(", ")}`);
      }

      // olympus_context needs no model, so this works with no daemon and proves
      // the request/response path end to end rather than just the handshake.
      const result = await client.callTool({ name: "olympus_context", arguments: {} });
      const text = result.content?.[0]?.text ?? "";
      assert.match(
        text,
        /context\.json|"project"/,
        `unexpected tool output: ${text.slice(0, 200)}`,
      );
    } finally {
      await client.close();
    }
  },
);
