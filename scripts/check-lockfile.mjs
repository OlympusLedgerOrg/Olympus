#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Guard against a lockfile that every CI job will reject.
//
// Every workflow starts with `pnpm install --frozen-lockfile`. When the
// lockfile is internally inconsistent that single step fails everywhere at
// once, before any real gate runs — so the failure reads as a broken pipeline
// rather than a broken lockfile, and the branch can look clean locally.
//
// `pnpm install --frozen-lockfile --lockfile-only` is not enough on its own.
// It compares each importer's specifiers against package.json but never
// resolves the dependency graph, so a snapshot naming a peer version that does
// not exist in the lockfile still passes it and only fails at the real install
// (the stale vitest peer pointer that blocked the pipeline this way).
//
// This script checks both halves:
//   1. specifiers — delegated to pnpm itself, with --lockfile-only so nothing
//      is written;
//   2. references — every importer edge, snapshot edge and peer suffix must
//      name an id that the lockfile actually defines.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { load as loadYaml } from "js-yaml";

const NON_REGISTRY = /^(?:link:|file:|workspace:|https?:|git\+|github:)/;
const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"];
const EDGE_FIELDS = ["dependencies", "optionalDependencies"];
const MAX_REPORTED = 12;

/** The part of an id before its parenthesised peer contexts. */
function splitHead(id) {
  const paren = id.indexOf("(");
  return paren === -1 ? id : id.slice(0, paren);
}

/** Top-level `(…)` groups of a peer-context suffix, balanced rather than split on ")". */
function peerGroups(suffix) {
  const groups = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < suffix.length; i += 1) {
    const char = suffix[i];
    if (char === "(") {
      if (depth === 0) start = i + 1;
      depth += 1;
    } else if (char === ")") {
      depth -= 1;
      if (depth === 0 && start !== -1) {
        groups.push(suffix.slice(start, i));
        start = -1;
      }
    }
  }
  return groups;
}

/**
 * Every package id named by `id`, outermost first. `vite@8.2.1(a@1)(b@2)` yields
 * ["vite@8.2.1", "a@1", "b@2"]; nested contexts (`vite@8.2.1(@types/node@26)`)
 * are walked too, because those are the versions that go stale.
 */
export function collectIds(id) {
  const paren = id.indexOf("(");
  const ids = [paren === -1 ? id : id.slice(0, paren)];
  if (paren !== -1) {
    for (const group of peerGroups(id.slice(paren))) ids.push(...collectIds(group));
  }
  return ids;
}

/** Every unresolved reference in `lockfile`, deduplicated, as {where, id, reason}. */
export function findLockfileProblems(lockfile) {
  const problems = [];
  const seen = new Set();
  const packages = new Set(Object.keys(lockfile?.packages ?? {}));
  const snapshots = new Set(Object.keys(lockfile?.snapshots ?? {}));
  // lockfileVersion 9 resolves through `snapshots`; older files only have `packages`.
  const useSnapshots = lockfile?.snapshots != null;

  const add = (where, id, reason) => {
    const key = `${reason}:${id}`;
    if (seen.has(key)) return;
    seen.add(key);
    problems.push({ where, id, reason });
  };

  const resolves = (id) =>
    useSnapshots ? snapshots.has(id) || packages.has(id) : packages.has(id);

  const checkPeers = (id, where) => {
    for (const peer of collectIds(id).slice(1)) {
      if (!packages.has(peer)) add(where, peer, "unknown peer version");
    }
  };

  for (const [importerPath, importer] of Object.entries(lockfile?.importers ?? {})) {
    if (!importer || typeof importer !== "object") continue;
    const label = importerPath === "." ? "root" : importerPath;
    for (const field of DEP_FIELDS) {
      for (const [name, entry] of Object.entries(importer[field] ?? {})) {
        const version = typeof entry === "string" ? entry : entry?.version;
        if (!version || NON_REGISTRY.test(version)) continue;
        // An aliased dependency resolves to `<real-name>@<version>`, so a value
        // that already carries a name is used as-is.
        const id = splitHead(version).includes("@") ? version : `${name}@${version}`;
        if (!resolves(id)) add(`${label} ${field}`, id, "unresolved dependency");
        checkPeers(id, `${label} ${field}`);
      }
    }
  }

  for (const [snapshotId, snapshot] of Object.entries(lockfile?.snapshots ?? {})) {
    if (!snapshot || typeof snapshot !== "object") continue;
    checkPeers(snapshotId, `snapshot ${snapshotId}`);
    for (const field of EDGE_FIELDS) {
      for (const [name, value] of Object.entries(snapshot[field] ?? {})) {
        if (typeof value !== "string" || NON_REGISTRY.test(value)) continue;
        const id = splitHead(value).includes("@") ? value : `${name}@${value}`;
        const where = `snapshot ${snapshotId} › ${field}`;
        if (!resolves(id)) add(where, id, "unresolved snapshot");
        checkPeers(id, where);
      }
    }
  }

  return problems;
}

function runPnpmSpecifierCheck(cwd) {
  const windows = process.platform === "win32";
  const result = spawnSync(
    windows ? "pnpm.cmd" : "pnpm",
    ["install", "--frozen-lockfile", "--lockfile-only", "--ignore-scripts"],
    { cwd, encoding: "utf8", timeout: 120_000, shell: windows },
  );
  if (result.error) {
    return { skipped: `pnpm could not run (${result.error.code ?? result.error.message})` };
  }
  if (result.status === 0) return null;
  return { output: `${result.stdout ?? ""}${result.stderr ?? ""}`.trim() };
}

function main() {
  const cwd = process.cwd();
  const path = resolve(cwd, "pnpm-lock.yaml");

  let lockfile;
  try {
    lockfile = loadYaml(readFileSync(path, "utf8"));
  } catch (error) {
    console.error(`✗ cannot read ${path}: ${error.message}`);
    process.exit(1);
  }

  const problems = findLockfileProblems(lockfile);
  const specifier = runPnpmSpecifierCheck(cwd);
  const specifierFailed = Boolean(specifier?.output);

  if (!problems.length && !specifierFailed) {
    if (specifier?.skipped) {
      console.log(
        `✓ pnpm-lock.yaml references resolve (specifier check skipped: ${specifier.skipped})`,
      );
    } else {
      console.log("✓ pnpm-lock.yaml matches every workspace manifest and resolves internally");
    }
    process.exit(0);
  }

  console.error("✗ pnpm-lock.yaml would fail `pnpm install --frozen-lockfile`\n");
  if (specifierFailed) {
    for (const line of specifier.output.split(/\r?\n/)) console.error(`  ${line}`);
    console.error("");
  }
  for (const problem of problems.slice(0, MAX_REPORTED)) {
    console.error(`  ${problem.reason}: ${problem.id}`);
    console.error(`    referenced from ${problem.where}`);
  }
  if (problems.length > MAX_REPORTED) {
    console.error(`  …and ${problems.length - MAX_REPORTED} more`);
  }
  console.error(
    "\nEvery CI job starts with `pnpm install --frozen-lockfile`, so this blocks all of them.",
  );
  console.error("Regenerate the lockfile with `pnpm install` and commit the result.");
  process.exit(1);
}

const invokedDirectly =
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) main();
