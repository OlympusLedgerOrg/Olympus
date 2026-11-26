#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// stdio entry point for MCP clients. `.mcp.json` points here rather than
// straight at the `serena` executable for the same reason wiserepo has a
// launcher: an MCP client spawns `command` in ITS OWN working directory.
//
// Serena resolves its project from that directory (`--project-from-cwd` walks
// up to the nearest `.git`), so a client that starts elsewhere gets no project
// at all — the server comes up, every symbol tool fails, and Serena's own log
// records "No project root found from cwd=…". Pinning the cwd to this checkout
// removes that failure mode without committing a machine-specific path to
// `.mcp.json`.

import { spawn } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

// bin/mcp-launcher.mjs -> tools/serena/bin -> tools/serena -> tools -> repo root.
const MODULE_ROOT = path.resolve(fileURLToPath(new URL("../../..", import.meta.url)));

/**
 * The directory Serena runs in. SERENA_PROJECT_ROOT wins (a relative value
 * resolves against the caller's cwd, which is its documented meaning);
 * otherwise this file's own location decides.
 */
export function resolveLaunchRoot(env = process.env) {
  return path.resolve(env.SERENA_PROJECT_ROOT || MODULE_ROOT);
}

/**
 * The argv Serena is launched with. Exported so the test can pin the contract
 * without spawning a Python process.
 *
 * `--context ide` is Serena's single-project context, the documented choice for
 * per-workspace MCP configs: the project is fixed at startup instead of being
 * switched later through `activate_project`. `--project-from-cwd` is what the
 * pinned cwd below makes meaningful; without it Serena loads no project and
 * every symbol tool fails.
 */
export function serenaArgs(extraArgs = []) {
  return ["start-mcp-server", "--context", "ide", "--project-from-cwd", ...extraArgs];
}

/**
 * Start the Serena MCP server as a child process and return it.
 *
 * `stdio: "inherit"` is the transport: the client's pipes must pass straight
 * through, or the connection is dropped.
 */
export function startServer({
  root = resolveLaunchRoot(),
  env = process.env,
  args = process.argv.slice(2),
} = {}) {
  const command = env.SERENA_BIN || "serena";
  const child = spawn(command, serenaArgs(args), {
    cwd: root,
    env,
    stdio: "inherit",
  });

  // A client shutting the server down signals THIS process, so the signal has
  // to be relayed: otherwise the child keeps a language server running after
  // the client has already recorded the server as stopped.
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      child.kill(signal);
    });
  }

  child.on("error", (err) => {
    process.stderr.write(
      `serena: cannot start '${command}' — ${err.message}\n` +
        `serena: install it (pip install serena-agent, or the uv tool) or point ` +
        `SERENA_BIN at the executable.\n`,
    );
    process.exitCode = 1;
  });

  child.on("exit", (code) => {
    // Mirror the child's status: an MCP client reads this process's exit as the
    // server's, so exiting 0 on a crash would report a clean shutdown.
    process.exitCode = code ?? 1;
  });

  return child;
}

// Same import guard the wiserepo launcher uses, so a test can import the
// functions above without spawning a transport that waits for a client.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startServer();
}
