#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";

const repo = process.cwd();
const baselinePath = path.join(repo, ".license-header-baseline");
const updateBaseline = process.argv.includes("--update-baseline");
const sourceExtensions = new Set([
  ".circom",
  ".css",
  ".js",
  ".mjs",
  ".cjs",
  ".ps1",
  ".py",
  ".rs",
  ".sh",
  ".sql",
  ".ts",
  ".tsx",
]);

const ignoredPrefixes = [
  ".git/",
  ".github/actions/",
  "app/public-ui/dist/",
  "app/public-ui/coverage/",
  "crates/glib-0.18.5-patched/",
  "crates/ppv-lite86-patched/",
  "node_modules/",
  "pg-embed-local/",
  "proofs/build/",
  "proofs/keys/",
  "proofs/vendor/",
  "target/",
  "verifiers/rust/target/",
];

const ignoredSegments = ["/node_modules/", "/target/", "/dist/"];
const headerPattern = /\bSPDX-License-Identifier:\s*Apache-2\.0\b/;

const toRepoPath = (file) => file.replace(/\\/g, "/");

const listGitFiles = (args) => {
  const output = execFileSync("git", args, { cwd: repo, encoding: "utf8" });
  return output.split("\0").filter(Boolean).map(toRepoPath);
};

const uniqueSorted = (values) => [...new Set(values)].sort((a, b) => a.localeCompare(b));

const readBaseline = () => {
  if (!existsSync(baselinePath)) {
    return new Set();
  }
  const entries = readFileSync(baselinePath, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  return new Set(entries);
};

const isCandidate = (file) => {
  const repoPath = toRepoPath(file);
  if (!sourceExtensions.has(path.extname(repoPath))) {
    return false;
  }
  if (ignoredPrefixes.some((prefix) => repoPath.startsWith(prefix))) {
    return false;
  }
  return !ignoredSegments.some((segment) => repoPath.includes(segment));
};

const hasHeader = (file) => {
  const text = readFileSync(path.join(repo, file), "utf8");
  return headerPattern.test(text.slice(0, 2048));
};

const files = uniqueSorted([
  ...listGitFiles(["ls-files", "-z"]),
  ...listGitFiles(["ls-files", "--others", "--exclude-standard", "-z"]),
]).filter(isCandidate);

const missing = files.filter((file) => !hasHeader(file));

if (updateBaseline) {
  const body = [
    "# First-party source files that predate the SPDX-header gate.",
    "# Remove entries as files receive an SPDX-License-Identifier header.",
    ...missing,
    "",
  ].join("\n");
  writeFileSync(baselinePath, body, "utf8");
  console.log(`Updated .license-header-baseline (${missing.length} legacy files).`);
  process.exit(0);
}

const baseline = readBaseline();
const missingWithoutBaseline = missing.filter((file) => !baseline.has(file));
const staleBaselineEntries = [...baseline].filter(
  (file) => !files.includes(file) || !missing.includes(file),
);

if (missingWithoutBaseline.length > 0 || staleBaselineEntries.length > 0) {
  console.error("License header check failed.");
  if (missingWithoutBaseline.length > 0) {
    console.error("\nMissing SPDX-License-Identifier: Apache-2.0 header:");
    for (const file of missingWithoutBaseline) {
      console.error(`  - ${file}`);
    }
  }
  if (staleBaselineEntries.length > 0) {
    console.error("\nStale .license-header-baseline entries:");
    for (const file of staleBaselineEntries) {
      console.error(`  - ${file}`);
    }
  }
  console.error("\nRun `pnpm license:headers:update-baseline` after intentional baseline changes.");
  process.exit(1);
}

console.log(
  `License header check passed (${files.length - missing.length} headered, ${missing.length} baseline entries).`,
);
