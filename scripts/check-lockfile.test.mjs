#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { collectIds, findLockfileProblems } from "./check-lockfile.mjs";

const ids = (problems) => problems.map((problem) => problem.id);

test("a consistent lockfile has no problems", () => {
  const lockfile = {
    lockfileVersion: "9.0",
    importers: {
      ".": { devDependencies: { prettier: { specifier: "^3.9.6", version: "3.9.6" } } },
      "app/public-ui": { dependencies: { react: { specifier: "^19.2.8", version: "19.2.8" } } },
    },
    packages: { "prettier@3.9.6": {}, "react@19.2.8": {} },
    snapshots: { "prettier@3.9.6": {}, "react@19.2.8": {} },
  };
  assert.deepEqual(findLockfileProblems(lockfile), []);
});

test("a peer suffix naming a version that does not exist is reported", () => {
  // The shape of the stale vitest pointer: the edge's peer context says
  // vite@8.2.0 while only 8.2.1 was resolved.
  const lockfile = {
    lockfileVersion: "9.0",
    importers: {
      "app/public-ui": {
        devDependencies: {
          "jest-dom": { specifier: "^7.0.1", version: "7.0.1(vitest@4.1.10(vite@8.2.1(a@1.0.0)))" },
        },
      },
    },
    packages: {
      "jest-dom@7.0.1": {},
      "vitest@4.1.10": {},
      "vite@8.2.1": {},
      "vite@8.2.0": {},
      "a@1.0.0": {},
    },
    snapshots: {
      "jest-dom@7.0.1(vitest@4.1.10(vite@8.2.1(a@1.0.0)))": {
        optionalDependencies: { vitest: "4.1.10(vite@8.2.0(a@1.0.0))" },
      },
      "vitest@4.1.10": {},
    },
  };
  const problems = findLockfileProblems(lockfile);
  assert.ok(
    problems.some((problem) => problem.id === "vitest@4.1.10(vite@8.2.0(a@1.0.0))"),
    `expected the stale snapshot id to be reported, got ${JSON.stringify(problems)}`,
  );
});

test("a dangling snapshot edge is reported with its referrer", () => {
  const lockfile = {
    lockfileVersion: "9.0",
    importers: {},
    packages: { "a@1.0.5": {} },
    snapshots: { "a@1.0.5": { dependencies: { b: "2.0.0" } } },
  };
  const problems = findLockfileProblems(lockfile);
  assert.equal(problems.length, 1);
  assert.equal(problems[0].id, "b@2.0.0");
  assert.match(problems[0].where, /snapshot a@1\.0\.5/);
  assert.equal(problems[0].reason, "unresolved snapshot");
});

test("a missing peer package is reported even when the edge itself resolves", () => {
  const lockfile = {
    lockfileVersion: "9.0",
    importers: {},
    packages: { "a@1.0.0": {}, "vite@8.2.1": {} },
    snapshots: { "a@1.0.0(vite@8.2.0)": {} },
  };
  const problems = findLockfileProblems(lockfile);
  assert.deepEqual(ids(problems), ["vite@8.2.0"]);
  assert.equal(problems[0].reason, "unknown peer version");
});

test("an importer pointing at a version with no snapshot is reported", () => {
  const lockfile = {
    lockfileVersion: "9.0",
    importers: { proofs: { dependencies: { blake3: { specifier: "^2.1.7", version: "2.1.6" } } } },
    packages: { "blake3@2.1.7": {} },
    snapshots: { "blake3@2.1.7": {} },
  };
  const problems = findLockfileProblems(lockfile);
  assert.deepEqual(ids(problems), ["blake3@2.1.6"]);
  assert.match(problems[0].where, /^proofs dependencies$/);
});

test("workspace and file links are not treated as registry references", () => {
  const lockfile = {
    lockfileVersion: "9.0",
    importers: {
      proofs: {
        dependencies: {
          jsonpath: { specifier: "file:./safe-jsonpath", version: "file:proofs/safe-jsonpath" },
        },
        devDependencies: {
          "@olympus/ui": { specifier: "workspace:*", version: "link:../app/public-ui" },
        },
      },
    },
    packages: {},
    snapshots: {},
  };
  assert.deepEqual(findLockfileProblems(lockfile), []);
});

test("scoped package names split at the last @", () => {
  assert.deepEqual(collectIds("@testing-library/jest-dom@7.0.1(vite@8.2.1(@types/node@26.1.2))"), [
    "@testing-library/jest-dom@7.0.1",
    "vite@8.2.1",
    "@types/node@26.1.2",
  ]);
});

test("lockfiles without a snapshots section fall back to packages", () => {
  const lockfile = {
    lockfileVersion: "6.0",
    importers: { ".": { dependencies: { a: { specifier: "^1.0.0", version: "1.0.0" } } } },
    packages: { "a@1.0.0": {} },
  };
  assert.deepEqual(findLockfileProblems(lockfile), []);
});
