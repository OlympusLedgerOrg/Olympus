// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { GateError, escalationTier, parseArgs, planVerification, runGate } from "./verify.mjs";

const commandsFor = (plan, id) =>
  plan.scopes
    .filter((scope) => scope.id === id)
    .flatMap((scope) =>
      scope.commands.map((command) => `${command.cmd} ${command.args.join(" ")}`),
    );

test("a documentation-only change runs only the tooling checks", () => {
  const plan = planVerification(["docs/architecture.md", "CHANGELOG.md"]);
  assert.deepEqual(
    plan.scopes.map((scope) => scope.id),
    ["tooling"],
  );
  assert.deepEqual(commandsFor(plan, "tooling"), [
    "node node_modules/prettier/bin/prettier.cjs --check **/*.{js,mjs,cjs,ts,tsx,json,css,yml,yaml}",
    "node scripts/check-license-headers.mjs",
  ]);
});

test("a workspace crate runs fmt, clippy and its own tests", () => {
  const plan = planVerification(["crates/olympus-crypto/src/lib.rs"]);
  assert.deepEqual(commandsFor(plan, "rust"), [
    "cargo fmt --all --check",
    "cargo clippy -p olympus-crypto -- -D warnings",
    "cargo test -p olympus-crypto",
  ]);
});

test("src-tauri maps to the olympus-desktop package", () => {
  const plan = planVerification(["src-tauri/src/main.rs"]);
  assert.deepEqual(commandsFor(plan, "rust"), [
    "cargo fmt --all --check",
    "cargo clippy -p olympus-desktop -- -D warnings",
    "cargo test -p olympus-desktop",
  ]);
});

test("a root manifest change checks the whole workspace", () => {
  const plan = planVerification(["Cargo.lock"]);
  assert.deepEqual(commandsFor(plan, "rust"), [
    "cargo fmt --all --check",
    "cargo clippy --workspace -- -D warnings",
    "cargo test --workspace",
  ]);
});

test("--fast drops the test suites but keeps the compile and lint checks", () => {
  const plan = planVerification(["crates/olympus-crypto/src/lib.rs"], { fast: true });
  assert.deepEqual(commandsFor(plan, "rust"), [
    "cargo fmt --all --check",
    "cargo clippy -p olympus-crypto -- -D warnings",
  ]);
});

test("the UI scope runs from inside app/public-ui", () => {
  const plan = planVerification(["app/public-ui/src/App.tsx"]);
  const scope = plan.scopes.find((entry) => entry.id === "ui");
  assert.deepEqual(
    scope.commands.map((command) => `${command.cwd}: ${command.cmd} ${command.args.join(" ")}`),
    [
      "app/public-ui: node node_modules/typescript/bin/tsc -b",
      "app/public-ui: node node_modules/eslint/bin/eslint.js . --max-warnings 0",
      "app/public-ui: node node_modules/vitest/vitest.mjs run",
    ],
  );
});

test("verifiers/rust and its fuzz harness use --manifest-path", () => {
  const plan = planVerification(["verifiers/rust/src/lib.rs"]);
  assert.deepEqual(commandsFor(plan, "verifiers-rust"), [
    "cargo fmt --manifest-path verifiers/rust/Cargo.toml --check",
    "cargo clippy --manifest-path verifiers/rust/Cargo.toml -- -D warnings",
    "cargo test --manifest-path verifiers/rust/Cargo.toml",
  ]);

  const fuzz = planVerification(["verifiers/rust/fuzz/fuzz_targets/hash.rs"]);
  assert.deepEqual(commandsFor(fuzz, "verifiers-rust"), [
    "cargo check --manifest-path verifiers/rust/fuzz/Cargo.toml",
  ]);
});

test("clients/cli uses its locked, all-features invocation", () => {
  const plan = planVerification(["clients/cli/src/main.rs"]);
  assert.deepEqual(commandsFor(plan, "clients-cli"), [
    "cargo fmt --manifest-path clients/cli/Cargo.toml --check",
    "cargo clippy --manifest-path clients/cli/Cargo.toml --all-features -- -D warnings",
    "cargo test --locked --manifest-path clients/cli/Cargo.toml --all-features",
  ]);
});

test("pg-embed-local runs only its library tests, as CI does", () => {
  const plan = planVerification(["pg-embed-local/src/lib.rs"]);
  assert.deepEqual(commandsFor(plan, "pg-embed"), [
    "cargo test --locked --manifest-path pg-embed-local/Cargo.toml --lib --no-default-features --features rt_tokio",
  ]);
});

test("the Python client and JS verifier are reached at all", () => {
  const python = planVerification(["clients/python/src/olympus_manifest/hashing.py"]);
  assert.deepEqual(commandsFor(python, "python-client"), [
    "python -m pytest -q clients/python/tests",
  ]);

  // The PyO3 backend is a separate Cargo workspace: it gets fmt/clippy via
  // --manifest-path, never the root workspace, plus the Python suite.
  const native = planVerification(["clients/python/native/src/lib.rs"]);
  assert.deepEqual(commandsFor(native, "python-native"), [
    "cargo fmt --manifest-path clients/python/native/Cargo.toml --check",
    "cargo clippy --locked --manifest-path clients/python/native/Cargo.toml -- -D warnings",
  ]);
  assert.deepEqual(commandsFor(native, "python-client"), [
    "python -m pytest -q clients/python/tests",
  ]);
  assert.equal(
    native.scopes.some((entry) => entry.id === "rust"),
    false,
  );

  const js = planVerification(["verifiers/javascript/verifier.js"]);
  const scope = js.scopes.find((entry) => entry.id === "verifiers-javascript");
  assert.deepEqual(
    scope.commands.map((command) => `${command.cwd}: ${command.cmd} ${command.args.join(" ")}`),
    ["verifiers/javascript: npm test"],
  );
});

test("a touched tool runs its own test files", () => {
  const plan = planVerification(["tools/qwen-local/ask.mjs"]);
  const commands = commandsFor(plan, "tools:qwen-local");
  assert.equal(commands.length, 1);
  assert.match(commands[0], /--test .*tools\/qwen-local\/ask\.test\.mjs/);
});

test("a TOML change adds the TOML formatter", () => {
  const plan = planVerification(["taplo.toml"]);
  assert.ok(commandsFor(plan, "tooling").includes("node scripts/taplo.mjs format --check"));
});

test("the gate stops at the first failure and names the tier", () => {
  const plan = {
    files: ["crates/olympus-crypto/src/lib.rs"],
    scopes: [
      {
        id: "tooling",
        files: [],
        commands: [
          { cmd: "a", args: [] },
          { cmd: "b", args: [] },
        ],
      },
      { id: "rust", files: [], commands: [{ cmd: "c", args: [] }] },
    ],
  };
  const seen = [];
  const runner = (command) => {
    seen.push(command.cmd);
    return { status: command.cmd === "b" ? 101 : 0 };
  };
  const verdict = runGate(plan, { runner });
  assert.equal(verdict.ok, false);
  assert.equal(verdict.escalated, true);
  assert.equal(verdict.tier, "top");
  assert.equal(verdict.failed.scope, "tooling");
  assert.equal(verdict.failed.command, "b");
  assert.deepEqual(seen, ["a", "b"]);
  assert.equal(verdict.ran.length, 2);
});

test("a passing plan runs every command in order", () => {
  const plan = {
    files: ["app/public-ui/src/App.tsx"],
    scopes: [
      { id: "tooling", files: [], commands: [{ cmd: "a", args: [] }] },
      { id: "ui", files: [], commands: [{ cmd: "b", args: [] }] },
    ],
  };
  const seen = [];
  const verdict = runGate(plan, {
    runner: (command) => {
      seen.push(command.cmd);
      return { status: 0 };
    },
  });
  assert.equal(verdict.ok, true);
  assert.equal(verdict.escalated, false);
  assert.equal(verdict.tier, null);
  assert.deepEqual(seen, ["a", "b"]);
});

test("escalation goes to top for critical prefixes and mid otherwise", () => {
  assert.equal(escalationTier(["crates/olympus-crypto/src/lib.rs"]), "top");
  assert.equal(escalationTier(["src-tauri/src/api/ingest.rs"]), "top");
  assert.equal(escalationTier(["app/public-ui/src/App.tsx"]), "mid");
  assert.equal(escalationTier(["tools/qwen-local/ask.mjs"]), "mid");
});

test("an unknown argument is a usage error, not a silent pass", () => {
  assert.throws(() => parseArgs(["--nope"]), GateError);
  assert.throws(() => parseArgs(["--base"]), GateError);
});
