#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

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
const headerScanBytes = 2048;
const headerPattern = /^SPDX-License-Identifier:\s*Apache-2\.0$/;
const lineCommentPrefixes = ["//", "#", "--"];

const toRepoPath = (file) => file.replace(/\\/g, "/");

const listGitFiles = (args) => {
  const output = execFileSync("git", args, { cwd: repo, encoding: "utf8" });
  return output.split("\0").filter(Boolean).map(toRepoPath);
};

const uniqueSorted = (values) => [...new Set(values)].sort((a, b) => a.localeCompare(b));

const lineCommentText = (line) => {
  const trimmed = line.trim();
  for (const prefix of lineCommentPrefixes) {
    if (trimmed.startsWith(prefix) && !trimmed.startsWith("#!")) {
      return trimmed.slice(prefix.length).trim();
    }
  }
  return null;
};

const blockCommentTexts = (lines, startIndex) => {
  if (!lines[startIndex].trim().startsWith("/*")) {
    return null;
  }

  const contents = [];
  for (let index = startIndex; index < lines.length; index += 1) {
    let line = lines[index].trim();
    if (index === startIndex) {
      line = line.slice(2);
    }
    const end = line.indexOf("*/");
    if (end !== -1) {
      line = line.slice(0, end);
    }
    const normalized = line.replace(/^\*\s?/, "").trim();
    if (normalized.length > 0) {
      contents.push(normalized);
    }
    if (end !== -1) {
      return { contents, nextIndex: index + 1 };
    }
  }

  return { contents, nextIndex: lines.length };
};

export const hasSpdxLicenseHeader = (text) => {
  const lines = text
    .slice(0, headerScanBytes)
    .replace(/^\uFEFF/, "")
    .split(/\r?\n/);
  let index = 0;
  if (lines[index]?.startsWith("#!")) {
    index += 1;
  }

  while (index < lines.length) {
    if (lines[index].trim() === "") {
      index += 1;
      continue;
    }

    const block = blockCommentTexts(lines, index);
    if (block !== null) {
      if (block.contents.some((line) => headerPattern.test(line))) {
        return true;
      }
      index = block.nextIndex;
      continue;
    }

    const commentText = lineCommentText(lines[index]);
    if (commentText === null) {
      return false;
    }
    if (headerPattern.test(commentText)) {
      return true;
    }
    index += 1;
  }

  return false;
};

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
  return hasSpdxLicenseHeader(text);
};

const main = () => {
  const files = uniqueSorted([
    ...listGitFiles(["ls-files", "-z"]),
    ...listGitFiles(["ls-files", "--others", "--exclude-standard", "-z"]),
  ]).filter(isCandidate);

  const missing = files.filter((file) => !hasHeader(file));
  const baseline = readBaseline();

  if (updateBaseline) {
    const legacyMissing = missing.filter((file) => baseline.has(file));
    const body = [
      "# First-party source files that predate the SPDX-header gate.",
      "# Remove entries as files receive an SPDX-License-Identifier header.",
      ...legacyMissing,
      "",
    ].join("\n");
    writeFileSync(baselinePath, body, "utf8");
    console.log(`Updated .license-header-baseline (${legacyMissing.length} legacy files).`);
    process.exit(0);
  }

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
    console.error(
      "\nRun `pnpm license:headers:update-baseline` after intentional baseline changes.",
    );
    process.exit(1);
  }

  console.log(
    `License header check passed (${files.length - missing.length} headered, ${missing.length} baseline entries).`,
  );
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
