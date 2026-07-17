#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

export const workflowHasElevatedAuthority = (contents) =>
  /(?:^|[{,])\s*[a-z-]+:\s*write(?:\s|[,}#]|$)/m.test(contents) ||
  /^\s*permissions:\s*write-all(?:\s|#|$)/m.test(contents) ||
  /\bsecrets(?:\.|\[)/.test(contents);

export const mutableExternalActions = (contents) => {
  const violations = [];
  for (const [index, line] of contents.split(/\r?\n/).entries()) {
    const match = /^\s*-?\s*uses\s*:\s*(?:"([^"]+)"|'([^']+)'|([^\s#]+))/.exec(line);
    if (!match) continue;
    const action = match[1] ?? match[2] ?? match[3];
    if (action.startsWith("./")) continue;

    if (action.startsWith("docker://")) {
      if (!/^docker:\/\/[^@\s]+@sha256:[0-9a-f]{64}$/.test(action)) {
        violations.push({ line: index + 1, action });
      }
      continue;
    }

    const separator = action.lastIndexOf("@");
    const ref = separator === -1 ? "" : action.slice(separator + 1);
    if (!/^[0-9a-f]{40}$/.test(ref)) {
      violations.push({ line: index + 1, action });
    }
  }
  return violations;
};

const localActionManifests = (root) => {
  const actionRoot = path.join(root, ".github/actions");
  if (!existsSync(actionRoot)) return [];

  const manifests = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(entryPath);
      } else if (entry.isFile() && (entry.name === "action.yml" || entry.name === "action.yaml")) {
        manifests.push(path.relative(root, entryPath).split(path.sep).join("/"));
      }
    }
  };
  visit(actionRoot);
  return manifests.sort((left, right) => left.localeCompare(right));
};

export const checkPrivilegedWorkflows = (root = process.cwd()) => {
  const violations = [];
  const workflowDirectory = path.join(root, ".github/workflows");
  const workflows = readdirSync(workflowDirectory)
    .filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"))
    .sort((left, right) => left.localeCompare(right));
  for (const file of workflows) {
    const workflow = `.github/workflows/${file}`;
    const contents = readFileSync(path.join(workflowDirectory, file), "utf8");
    if (!workflowHasElevatedAuthority(contents)) continue;
    for (const violation of mutableExternalActions(contents)) {
      violations.push(`${workflow}:${violation.line}: ${violation.action}`);
    }
  }

  // Local composites execute inside their caller's job and can therefore
  // inherit its token, permissions, and secret-bearing environment. Keep
  // their external dependencies immutable even when today's callers happen
  // to be read-only.
  for (const manifest of localActionManifests(root)) {
    const contents = readFileSync(path.join(root, manifest), "utf8");
    for (const violation of mutableExternalActions(contents)) {
      violations.push(`${manifest}:${violation.line}: ${violation.action}`);
    }
  }
  return violations;
};

const main = () => {
  const violations = checkPrivilegedWorkflows();
  if (violations.length > 0) {
    throw new Error(
      `privileged workflows and local composites must pin external actions to immutable revisions:\n${violations.join("\n")}`,
    );
  }
  console.log("Privileged workflow action pins verified.");
};

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
