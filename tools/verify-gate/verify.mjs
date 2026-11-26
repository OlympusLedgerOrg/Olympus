#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Run the repo's own checks for whatever a change actually touched.
 *
 * The failure this exists to prevent is specific: a cheap tier edits three
 * files, the agent runs a test for the wrong package (or none), reports
 * success, and CI finds the rest. AGENTS.md already documents which command is
 * the gate for each scope — including the ones a root-level command silently
 * skips, like `verifiers/rust`, `clients/cli`, and eslint from outside
 * `app/public-ui`. This encodes that table and runs it in cheapest-first order.
 *
 * It stops at the first failure instead of collecting the rest. The point of
 * that is the escalation: a failed check means the change was not finished by
 * the tier that produced it, and running the remaining scopes spends minutes
 * proving the same thing. The verdict names the tier the fix belongs to —
 * `top` when any touched file sits under a policy critical prefix, `mid`
 * otherwise.
 *
 * It is not a CI replacement: it runs the per-package checks an agent can run
 * locally before committing. `--fast` runs the compile/lint half only and is
 * explicitly not a substitute for a full run.
 */

import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

import { isCriticalPath, loadPolicy } from "../agent-policy/policy.mjs";

export const REPO_ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));

/** Root-workspace package per directory. Directory names match package names. */
const RUST_PACKAGES = new Map([
  ["src-tauri", "olympus-desktop"],
  ["crates/olympus-crypto", "olympus-crypto"],
  ["crates/olympus-manifest", "olympus-manifest"],
  ["crates/light-poseidon", "light-poseidon"],
  ["crates/babyjubjub-permissive", "babyjubjub-permissive"],
]);

const ROOT_MANIFESTS = new Set(["Cargo.toml", "Cargo.lock"]);

export const USAGE = `Usage: node tools/verify-gate/verify.mjs [options]

Options:
  --base <ref>        verify <ref>...HEAD instead of the working tree
  --changed a,b,c     verify exactly these paths (no git call)
  --fast              fmt/lint/typecheck only; skips test suites
  --dry-run           print the plan and exit without running anything
  --json              print the verdict as JSON
  --help              show this message

Exit codes: 0 all checks passed, 1 a check failed (escalate), 2 usage/git error.
`;

/** A local invocation problem: bad arguments or an unreadable working tree. */
export class GateError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "GateError";
  }
}

const toRepoPath = (file) => file.replace(/\\/g, "/").replace(/^\.\//, "");

const under = (file, dir) => file === dir || file.startsWith(`${dir}/`);

function lines(text) {
  return String(text ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

/** `*.test.mjs` under one tool directory, excluding dependencies. */
export function discoverToolTests(dir, root = REPO_ROOT) {
  const found = [];
  const walk = (relative) => {
    let entries;
    try {
      entries = readdirSync(path.join(root, relative), { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === "eval") continue;
        walk(`${relative}/${entry.name}`);
      } else if (entry.isFile() && entry.name.endsWith(".test.mjs")) {
        found.push(`${relative}/${entry.name}`);
      }
    }
  };
  walk(toRepoPath(dir));
  return found.sort();
}

/**
 * Turn a changed-file list into scopes and their commands.
 *
 * Pure: no git, no filesystem walk beyond discovering a touched tool's test
 * files, and no command is run. That is what lets the tests assert the exact
 * invocation for each scope — the part that silently drifts from AGENTS.md.
 */
export function planVerification(changedFiles, { fast = false, root = REPO_ROOT } = {}) {
  const files = [...new Set(changedFiles.map(toRepoPath).filter(Boolean))];
  const scopes = [];
  const add = (id, scopeFiles, commands) => {
    if (commands.length === 0) return;
    scopes.push({ id, files: scopeFiles.sort(), commands });
  };

  if (files.length > 0) {
    // The binaries are invoked directly rather than through `pnpm <script>`.
    // pnpm verifies the dependency graph before running a script and, when the
    // lockfile disagrees with the installed tree, installs to "fix" it — which
    // rewrites pnpm-lock.yaml. A verification gate that dirties the tree it is
    // checking is not a gate.
    const commands = [
      {
        cmd: "node",
        args: [
          "node_modules/prettier/bin/prettier.cjs",
          "--check",
          "**/*.{js,mjs,cjs,ts,tsx,json,css,yml,yaml}",
        ],
      },
    ];
    if (files.some((file) => file.endsWith(".toml"))) {
      commands.push({
        cmd: "node",
        args: ["node_modules/@taplo/cli/dist/cli.js", "format", "--check"],
      });
    }
    commands.push({ cmd: "node", args: ["scripts/check-license-headers.mjs"] });
    add("tooling", files, commands);
  }

  const rustFiles = files.filter((file) =>
    [...RUST_PACKAGES.keys()].some((dir) => under(file, dir)),
  );
  const workspaceWide = files.some((file) => ROOT_MANIFESTS.has(file));
  if (rustFiles.length > 0 || workspaceWide) {
    const commands = [{ cmd: "cargo", args: ["fmt", "--all", "--check"] }];
    if (workspaceWide) {
      // A root manifest change can move any crate's dependency graph, so the
      // per-package split would be a guess.
      commands.push({ cmd: "cargo", args: ["clippy", "--workspace", "--", "-D", "warnings"] });
      if (!fast) commands.push({ cmd: "cargo", args: ["test", "--workspace"] });
    } else {
      const packages = [
        ...new Set(
          rustFiles.map((file) =>
            RUST_PACKAGES.get([...RUST_PACKAGES.keys()].find((dir) => under(file, dir))),
          ),
        ),
      ].sort();
      for (const pkg of packages) {
        commands.push({ cmd: "cargo", args: ["clippy", "-p", pkg, "--", "-D", "warnings"] });
        if (!fast) commands.push({ cmd: "cargo", args: ["test", "-p", pkg] });
      }
    }
    // A root-manifest change has no files of its own to report, so name the
    // manifest that caused the scope.
    add("rust", rustFiles.length > 0 ? rustFiles : ["Cargo.toml"], commands);
  }

  const verifierRust = files.filter((file) => under(file, "verifiers/rust"));
  if (verifierRust.length > 0) {
    const fuzzOnly = verifierRust.every((file) => under(file, "verifiers/rust/fuzz"));
    const commands = [];
    if (fuzzOnly) {
      commands.push({
        cmd: "cargo",
        args: ["check", "--manifest-path", "verifiers/rust/fuzz/Cargo.toml"],
      });
    } else {
      commands.push({
        cmd: "cargo",
        args: ["fmt", "--manifest-path", "verifiers/rust/Cargo.toml", "--check"],
      });
      commands.push({
        cmd: "cargo",
        args: ["clippy", "--manifest-path", "verifiers/rust/Cargo.toml", "--", "-D", "warnings"],
      });
      if (!fast) {
        commands.push({
          cmd: "cargo",
          args: ["test", "--manifest-path", "verifiers/rust/Cargo.toml"],
        });
      }
    }
    add("verifiers-rust", verifierRust, commands);
  }

  const clientsCli = files.filter((file) => under(file, "clients/cli"));
  if (clientsCli.length > 0) {
    const commands = [
      { cmd: "cargo", args: ["fmt", "--manifest-path", "clients/cli/Cargo.toml", "--check"] },
      {
        cmd: "cargo",
        args: [
          "clippy",
          "--manifest-path",
          "clients/cli/Cargo.toml",
          "--all-features",
          "--",
          "-D",
          "warnings",
        ],
      },
    ];
    if (!fast) {
      commands.push({
        cmd: "cargo",
        args: ["test", "--locked", "--manifest-path", "clients/cli/Cargo.toml", "--all-features"],
      });
    }
    add("clients-cli", clientsCli, commands);
  }

  const python = files.filter((file) => under(file, "clients/python"));
  if (python.length > 0) {
    add("python-client", python, [
      { cmd: "python", args: ["-m", "pytest", "-q", "clients/python/tests"] },
    ]);
  }

  const ui = files.filter((file) => under(file, "app/public-ui"));
  if (ui.length > 0) {
    const cwd = "app/public-ui";
    // From inside the directory, because a root-level eslint invocation
    // silently ignores it and exits 0.
    const commands = [
      { cmd: "node", args: ["node_modules/typescript/bin/tsc", "-b"], cwd },
      { cmd: "node", args: ["node_modules/eslint/bin/eslint.js", ".", "--max-warnings", "0"], cwd },
    ];
    if (!fast) commands.push({ cmd: "node", args: ["node_modules/vitest/vitest.mjs", "run"], cwd });
    add("ui", ui, commands);
  }

  const verifierJs = files.filter((file) => under(file, "verifiers/javascript"));
  if (verifierJs.length > 0) {
    // Not a pnpm workspace member, so `pnpm --filter` never reaches it.
    add("verifiers-javascript", verifierJs, [
      { cmd: "npm", args: ["test"], cwd: "verifiers/javascript" },
    ]);
  }

  const pgEmbed = files.filter((file) => under(file, "pg-embed-local"));
  if (pgEmbed.length > 0) {
    add("pg-embed", pgEmbed, [
      {
        cmd: "cargo",
        args: [
          "test",
          "--locked",
          "--manifest-path",
          "pg-embed-local/Cargo.toml",
          "--lib",
          "--no-default-features",
          "--features",
          "rt_tokio",
        ],
      },
    ]);
  }

  // One scope per touched tool directory: its own tests run, and nothing else.
  for (const dir of [
    ...new Set(files.map((file) => /^(tools\/[^/]+)\//.exec(file)?.[1]).filter(Boolean)),
  ].sort()) {
    const tests = discoverToolTests(dir, root);
    if (tests.length === 0) continue;
    add(
      `tools:${dir.slice("tools/".length)}`,
      files.filter((file) => under(file, dir)),
      [{ cmd: process.execPath, args: ["--test", ...tests] }],
    );
  }

  return { files, scopes };
}

/**
 * The tier a failure belongs to: `top` when the change touches something the
 * policy calls critical, `mid` otherwise. Local is not an option — the point of
 * a failure is that the tier that produced the change did not finish it.
 */
export function escalationTier(files, policy = loadPolicy()) {
  return files.some((file) => isCriticalPath(file, policy)) ? "top" : "mid";
}

const quote = (arg) => (/[\s"]/.test(arg) ? `"${arg.replace(/"/g, '\\"')}"` : arg);

/**
 * Run one command from the repo root. `shell` only on Windows, where `pnpm`,
 * `npm` and `cargo` are `.cmd` shims that `spawnSync` refuses to execute
 * directly (EINVAL, and EFTYPE for a shell script) when a shell is not used.
 */
export function runCommand({ cmd, args, cwd }, { root = REPO_ROOT } = {}) {
  const shell = process.platform === "win32";
  const result = spawnSync(shell ? [cmd, ...args].map(quote).join(" ") : cmd, shell ? [] : args, {
    cwd: path.resolve(root, cwd ?? "."),
    stdio: "inherit",
    shell,
  });
  if (result.error) {
    return { status: 1, error: result.error.message };
  }
  return { status: result.status ?? 1 };
}

/**
 * Execute a plan, stopping at the first failure.
 *
 * `runner` is injectable so the tests can prove the stop — the ordering is the
 * behaviour that matters, and running real compilers to check it would make the
 * suite unusable.
 */
export function runGate(plan, { runner = runCommand, onCommand = () => {} } = {}) {
  const ran = [];
  for (const scope of plan.scopes) {
    for (const command of scope.commands) {
      onCommand(scope, command);
      const result = runner(command);
      const record = {
        scope: scope.id,
        command: [command.cmd, ...command.args].join(" "),
        exitCode: result.status,
      };
      ran.push(record);
      if (result.status !== 0) {
        return {
          ok: false,
          escalated: true,
          tier: escalationTier(plan.files),
          failed: record,
          ran,
        };
      }
    }
  }
  return { ok: true, escalated: false, tier: null, failed: null, ran };
}

function runGit(args) {
  const result = spawnSync("git", args, { cwd: REPO_ROOT, encoding: "utf8" });
  if (result.error) throw new GateError(`git ${args.join(" ")} failed: ${result.error.message}`);
  if (result.status !== 0) {
    throw new GateError(`git ${args.join(" ")} exited ${result.status}: ${result.stderr.trim()}`);
  }
  return result.stdout;
}

/** Changed files: a commit range when `base` is given, else the working tree. */
export function changedFiles({ base } = {}) {
  const tracked = lines(
    runGit(base ? ["diff", "--name-only", `${base}...HEAD`] : ["diff", "--name-only", "HEAD"]),
  );
  const untracked = base ? [] : lines(runGit(["ls-files", "--others", "--exclude-standard"]));
  return [...new Set([...tracked, ...untracked])];
}

export function parseArgs(argv) {
  const options = { base: undefined, changed: null, fast: false, dryRun: false, json: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = () => {
      const next = argv[++i];
      if (next === undefined) throw new GateError(`${arg} needs a value`);
      return next;
    };
    if (arg === "--help" || arg === "-h") options.help = true;
    else if (arg === "--fast") options.fast = true;
    else if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--json") options.json = true;
    else if (arg === "--base") options.base = value();
    else if (arg.startsWith("--base=")) options.base = arg.slice(7);
    else if (arg === "--changed") options.changed = value().split(",").filter(Boolean);
    else if (arg.startsWith("--changed="))
      options.changed = arg.slice(10).split(",").filter(Boolean);
    else throw new GateError(`unknown argument: ${arg}`);
  }
  return options;
}

export async function main(argv = process.argv.slice(2)) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`verify-gate: ${error.message}\n${USAGE}`);
    return 2;
  }
  if (options.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  let files;
  try {
    files = options.changed ?? changedFiles({ base: options.base });
  } catch (error) {
    process.stderr.write(`verify-gate: ${error.message}\n`);
    return 2;
  }
  const plan = planVerification(files, { fast: options.fast });

  if (options.dryRun || plan.scopes.length === 0) {
    if (options.json) {
      process.stdout.write(
        `${JSON.stringify({ files, scopes: plan.scopes, ran: false }, null, 2)}\n`,
      );
    } else {
      process.stdout.write(
        `verify-gate: ${files.length} changed file(s) -> ${plan.scopes.length} scope(s)\n`,
      );
      for (const scope of plan.scopes) {
        for (const command of scope.commands) {
          process.stdout.write(
            `  [${scope.id}] ${[command.cmd, ...command.args].join(" ")}` +
              `${command.cwd ? ` (cwd ${command.cwd})` : ""}\n`,
          );
        }
      }
      if (plan.scopes.length === 0) process.stdout.write("  no package checks apply\n");
    }
    return 0;
  }

  if (!options.json) {
    process.stdout.write(
      `verify-gate: ${files.length} changed file(s) -> ${plan.scopes.length} scope(s)\n`,
    );
  }
  const verdict = runGate(plan, {
    onCommand: (scope, command) => {
      if (options.json) return;
      process.stdout.write(`[${scope.id}] ${[command.cmd, ...command.args].join(" ")}\n`);
    },
  });

  if (options.json) {
    process.stdout.write(`${JSON.stringify({ files, ...verdict }, null, 2)}\n`);
  } else if (verdict.ok) {
    process.stdout.write(
      `PASS: ${verdict.ran.length} check(s) across ${plan.scopes.length} scope(s)\n`,
    );
  } else {
    process.stdout.write(
      `FAIL: [${verdict.failed.scope}] ${verdict.failed.command} (exit ${verdict.failed.exitCode})\n` +
        `escalate: true, tier: ${verdict.tier} — the change was not finished by the tier that ` +
        `produced it. Move the fix to "${verdict.tier}" and re-run; do not re-prompt the same tier.\n`,
    );
  }
  return verdict.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main();
}
