// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// `.mcp.json` starts Serena through this launcher, so the things it exists to
// get right are pinned here: the argv (a single-project context plus
// cwd-based project detection), the working directory it runs in, and the
// failure mode when Serena is not installed.
//
// The handshake test is skipped unless SERENA_BIN points at a real executable.
// SERENA_REQUIRE_HANDSHAKE turns that skip into a failure; CI sets it, so a job
// whose Serena install silently went missing cannot report a green suite that
// never exercised the handshake. The argv/cwd/error tests never skip.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { resolveLaunchRoot, serenaArgs } from "../bin/mcp-launcher.mjs";

const LAUNCHER = fileURLToPath(new URL("../bin/mcp-launcher.mjs", import.meta.url));
const REPO_ROOT = path.resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const SERENA_BIN = process.env.SERENA_BIN;
// Any value but empty/0/false requires the handshake, so a typo in the CI job's
// "1" still demands it rather than quietly restoring the skip.
const HANDSHAKE_REQUIRED = !["", "0", "false"].includes(
  (process.env.SERENA_REQUIRE_HANDSHAKE ?? "").trim().toLowerCase(),
);

/**
 * Stop the launched server whether or not it is still running.
 *
 * A child that exited on its own (a crashed launcher, or a server that quit
 * after a bad request) leaves `exitCode` set. Teardown that ends its stdin,
 * kills it and then waits for an `exit` event that already fired would either
 * throw on the destroyed stream or sit out the whole timeout. Check first, and
 * register the exit listener before signalling so an exit in between is not
 * missed.
 */
export const stopServer = async (child) => {
  const hasExited = () => child.exitCode !== null || child.signalCode !== null;

  child.stdin.destroy();
  if (hasExited()) {
    child.stdout.destroy();
    return;
  }

  const waitForExit = new Promise((resolve) => {
    let timer;
    const onExit = () => {
      clearTimeout(timer);
      resolve(true);
    };
    timer = setTimeout(() => {
      child.off("exit", onExit);
      resolve(false);
    }, 10_000);
    child.once("exit", onExit);
    // The child can exit between the check above and the listener, and the
    // event would then never arrive for this listener.
    if (hasExited()) {
      child.off("exit", onExit);
      clearTimeout(timer);
      resolve(true);
    }
  });

  child.kill();
  if (!(await waitForExit)) {
    child.kill("SIGKILL");
  }
  child.stdout.destroy();
};

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
  "stopServer returns at once for a child that already exited",
  { timeout: 30_000 },
  async () => {
    // A launcher that dies on startup (bad argv, crashed interpreter) leaves the
    // handshake's teardown holding a dead child. Drive that state directly: the
    // old teardown ended stdin, killed, and waited for an `exit` that had already
    // fired, so a failure turned into a 10 s hang or a stream error.
    const child = spawn(process.execPath, ["-e", ""], { stdio: ["pipe", "pipe", "ignore"] });
    await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", resolve);
    });

    assert.equal(typeof child.exitCode, "number", "the child must have exited before teardown");

    const started = Date.now();
    await stopServer(child);
    const elapsed = Date.now() - started;

    // Well under the 10 s kill window: a wait here means the already-exited
    // branch was not taken and the helper is still blocking on a dead child.
    assert.ok(elapsed < 2_000, `teardown took ${elapsed}ms for an already-exited child`);
    assert.equal(child.stdout.destroyed, true);
  },
);

test(
  "a required handshake fails rather than skips when Serena is absent",
  { timeout: 90_000 },
  async () => {
    // The CI job sets SERENA_REQUIRE_HANDSHAKE=1 precisely so a green run cannot
    // mean "skipped". Prove the flag does that: run this file the way CI would,
    // but with SERENA_BIN removed, and require a failing exit.
    const env = { ...process.env, SERENA_REQUIRE_HANDSHAKE: "1" };
    delete env.SERENA_BIN;
    // Inherited from the runner running this very file: without removing it the
    // child believes it is itself a test-runner child, refuses to run files and
    // exits 0, which would make this check pass for the wrong reason.
    delete env.NODE_TEST_CONTEXT;

    const child = spawn(
      process.execPath,
      [
        "--test",
        "--test-name-pattern=launcher handshakes",
        "tools/serena/test/mcp-launcher.test.mjs",
      ],
      { cwd: REPO_ROOT, env, stdio: ["ignore", "pipe", "pipe"] },
    );
    let output = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => (output += chunk));
    child.stderr.on("data", (chunk) => (output += chunk));
    const code = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", resolve);
    });

    assert.equal(code, 1, `expected a failing run without Serena, got ${code}:\n${output}`);
    assert.match(output, /SERENA_REQUIRE_HANDSHAKE/);
  },
);

test(
  "launcher handshakes from a foreign cwd and exposes symbol tools",
  {
    timeout: 180_000,
    skip:
      !SERENA_BIN || !existsSync(SERENA_BIN)
        ? HANDSHAKE_REQUIRED
          ? false
          : "SERENA_BIN is not set to an installed Serena executable"
        : false,
  },
  async () => {
    assert.ok(
      SERENA_BIN && existsSync(SERENA_BIN),
      "SERENA_REQUIRE_HANDSHAKE is set but SERENA_BIN does not name an installed Serena executable",
    );

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
        env: { ...process.env, SERENA_BIN },
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
      // Closing the child's pipes is what turns a passing run into a prompt exit,
      // and the child must be stoppable even if it already died.
      await stopServer(child);
    }
  },
);
