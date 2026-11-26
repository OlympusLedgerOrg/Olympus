// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// `.mcp.json` starts Serena through this launcher, so the things it exists to
// get right are pinned here: the argv (a single-project context plus
// cwd-based project detection), the working directory it runs in, and the
// failure mode when Serena is not installed.
//
// The handshake test is skipped unless SERENA_BIN points at a real executable,
// because CI has no Python Serena install; the argv/cwd/error tests are not,
// since they are the part that can silently regress.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { resolveLaunchRoot, serenaArgs } from "../bin/mcp-launcher.mjs";

const LAUNCHER = fileURLToPath(new URL("../bin/mcp-launcher.mjs", import.meta.url));
const REPO_ROOT = path.resolve(fileURLToPath(new URL("../../..", import.meta.url)));

test("serenaArgs starts the stdio server in the single-project context", () => {
  assert.deepEqual(serenaArgs(), ["start-mcp-server", "--context", "ide", "--project-from-cwd"]);

  // Client-supplied arguments are appended, never substituted: dropping the
  // pinned flags because a caller passed one would lose the project.
  assert.deepEqual(serenaArgs(["--log-level", "DEBUG"]), [
    "start-mcp-server",
    "--context",
    "ide",
    "--project-from-cwd",
    "--log-level",
    "DEBUG",
  ]);
});

test("resolveLaunchRoot defaults to this checkout, not the caller's cwd", () => {
  const root = resolveLaunchRoot({});
  assert.equal(root, REPO_ROOT);

  // The point of pinning: it is a real Olympus checkout, identified from data
  // rather than from the path string alone.
  const pkg = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  assert.equal(pkg.name, "olympus-workspace");
});

test("SERENA_PROJECT_ROOT overrides the launch root", () => {
  const absolute = path.join(REPO_ROOT, "tools");
  assert.equal(resolveLaunchRoot({ SERENA_PROJECT_ROOT: absolute }), absolute);

  // A relative override resolves against the caller's cwd, which is its
  // documented meaning (same rule as wiserepo's WISEREPO_ROOT).
  assert.equal(
    resolveLaunchRoot({ SERENA_PROJECT_ROOT: path.join("some", "relative") }),
    path.resolve("some", "relative"),
  );
});

test(
  "a missing serena executable fails with exit 1 and names SERENA_BIN",
  { timeout: 30_000 },
  async () => {
    const missing = path.join(os.tmpdir(), "olympus-no-such-serena.exe");
    const child = spawn(process.execPath, [LAUNCHER], {
      cwd: os.tmpdir(),
      env: { ...process.env, SERENA_BIN: missing },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });

    const code = await new Promise((resolve, reject) => {
      child.on("error", reject);
      child.on("exit", resolve);
    });

    // Exiting 0 here would report a clean shutdown to the MCP client while no
    // server ever ran.
    assert.equal(code, 1);
    assert.match(stderr, /cannot start/);
    assert.match(stderr, /SERENA_BIN/);
  },
);

test(
  "launcher handshakes from a foreign cwd and exposes symbol tools",
  {
    timeout: 180_000,
    skip:
      !process.env.SERENA_BIN || !existsSync(process.env.SERENA_BIN)
        ? "SERENA_BIN is not set to an installed Serena executable"
        : false,
  },
  async () => {
    const child = spawn(
      process.execPath,
      // Dashboard and GUI log window off. The handshake is the MCP contract, and
      // on Windows the dashboard's pywebview window can outlive the kill below
      // and keep the test runner's pipes open — observed once as a `serena:test`
      // run that printed every check and then never exited.
      [LAUNCHER, "--enable-web-dashboard", "false", "--enable-gui-log-window", "false"],
      {
        // Deliberately NOT the repo: this is the cwd bug the launcher exists to
        // absorb (a client spawns the command in its own directory).
        cwd: os.tmpdir(),
        env: { ...process.env, SERENA_BIN: process.env.SERENA_BIN },
        stdio: ["pipe", "pipe", "ignore"],
      },
    );

    const pending = new Map();
    let buffer = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      buffer += chunk;
      let newline;
      while ((newline = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (!line) continue;
        const message = JSON.parse(line);
        const resolve = pending.get(message.id);
        if (resolve) {
          pending.delete(message.id);
          resolve(message);
        }
      }
    });

    let nextId = 1;
    const request = (method, params) => {
      const id = nextId++;
      const reply = new Promise((resolve) => pending.set(id, resolve));
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      return reply;
    };

    try {
      const init = await request("initialize", {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "serena-launcher-test", version: "0.0.0" },
      });
      assert.equal(init.result?.serverInfo?.name, "Serena", JSON.stringify(init));

      child.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized", params: {} })}\n`,
      );

      const listed = await request("tools/list", {});
      const names = (listed.result?.tools ?? []).map((tool) => tool.name);
      // These are the symbol-level tools the routing section promises; their
      // absence means the project/context came up wrong, not that the client
      // asked for the wrong thing.
      for (const expected of [
        "find_symbol",
        "find_referencing_symbols",
        "get_diagnostics_for_file",
      ]) {
        assert.ok(names.includes(expected), `missing tool "${expected}" in ${names.join(", ")}`);
      }
    } finally {
      // Deterministic teardown: close the transport, ask nicely, then insist.
      // Leaving the child's pipes open is what turns a passing run into a hang.
      child.stdin.end();
      child.kill();
      let timer;
      const exited = await Promise.race([
        once(child, "exit").then(() => true),
        new Promise((resolve) => {
          timer = setTimeout(() => resolve(false), 10_000);
        }),
      ]);
      clearTimeout(timer);
      if (!exited) {
        child.kill("SIGKILL");
      }
      child.stdout.destroy();
    }
  },
);
