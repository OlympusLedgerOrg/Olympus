#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// stdio entry point for MCP clients. `.mcp.json` points here rather than
// straight at src/mcp-server.mjs — see README's "Registering it and calling it".
//
// Why a launcher exists: an MCP client spawns `command` in ITS OWN working
// directory, which for a GUI/IDE client is frequently the editor or its
// install directory rather than this repo. File reads are already anchored on
// the module location and `git diff`/`git grep` pass `cwd: repoRoot()`, so the
// server survives that — but a process whose cwd is somewhere else is one
// relative-path mistake away from answering confidently about the wrong tree,
// and that failure reads as "the model is confused", not "the tool looked in
// the wrong directory". Pinning the cwd removes the whole class.
//
// The second job is interpreter identity: it re-executes the server with
// `process.execPath`, the node already running this file. That is what makes
// the absolute-path case in `.mcp.json` (`WISEREPO_NODE`) safe — when bare
// `node` is absent from the client's PATH, the child still starts, and it
// cannot drift to a different interpreter than the one the client resolved.

import { spawn } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

// bin/mcp-launcher.mjs -> tools/wiserepo/bin -> tools/wiserepo -> tools -> repo root.
const MODULE_ROOT = path.resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const SERVER_PATH = fileURLToPath(new URL("../src/mcp-server.mjs", import.meta.url));

/**
 * The directory the server process runs in.
 *
 * Same precedence as src/repo.mjs::repoRoot(): an explicit WISEREPO_ROOT wins
 * (a relative value resolves against the caller's cwd, which is its documented
 * meaning), otherwise this file's own location decides — so the answer never
 * depends on where the client happened to launch the command.
 */
export function resolveLaunchRoot(env = process.env) {
  return path.resolve(env.WISEREPO_ROOT || MODULE_ROOT);
}

/**
 * Start the MCP server as a child process and return it.
 *
 * `stdio: "inherit"` is load-bearing, not decoration: the client's pipes ARE
 * the transport, so anything other than inheriting them drops the connection.
 */
export function startServer({
  root = resolveLaunchRoot(),
  env = process.env,
  args = process.argv.slice(2),
} = {}) {
  const child = spawn(process.execPath, [SERVER_PATH, ...args], {
    cwd: root,
    // Pin WISEREPO_ROOT to the resolved root so the server's own root logic and
    // this process's cwd cannot disagree about which tree is being read.
    env: { ...env, WISEREPO_ROOT: root },
    stdio: "inherit",
  });

  // A client shutting the server down signals THIS process, so the signal has
  // to be relayed: otherwise the child keeps a model request running after the
  // client has already recorded the server as stopped.
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      child.kill(signal);
    });
  }

  child.on("error", (err) => {
    process.stderr.write(
      `wiserepo: cannot start ${SERVER_PATH} with ${process.execPath} — ${err.message}\n`,
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

// Same import guard the CLI and the server use, so tests can import the
// functions above without spawning a transport that waits forever for a client
// that is not there.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startServer();
}
