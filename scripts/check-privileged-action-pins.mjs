#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import { load } from "js-yaml";

const parseYaml = (contents) => {
  const parsed = load(contents);
  if (parsed === null || parsed === undefined) return {};
  if (typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("workflow YAML must contain a mapping at its root");
  }
  return parsed;
};

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

const containsSecretReference = (value) => {
  if (typeof value === "string") return /\bsecrets(?:\.|\[)/.test(value);
  if (Array.isArray(value)) return value.some(containsSecretReference);
  if (value && typeof value === "object") {
    return Object.values(value).some(containsSecretReference);
  }
  return false;
};

const permissionsArePotentiallyPrivileged = (permissions) => {
  if (permissions === undefined || permissions === null) return true;
  if (typeof permissions === "string") return permissions === "write-all";
  if (typeof permissions !== "object" || Array.isArray(permissions)) return true;
  return Object.values(permissions).some((value) => value === "write");
};

export const workflowHasElevatedAuthority = (contents) => {
  const workflow = parseYaml(contents);
  const hasWorkflowPermissions = hasOwn(workflow, "permissions");
  if (hasWorkflowPermissions && permissionsArePotentiallyPrivileged(workflow.permissions)) {
    return true;
  }

  if (workflow.jobs && typeof workflow.jobs === "object" && !Array.isArray(workflow.jobs)) {
    for (const job of Object.values(workflow.jobs)) {
      if (!job || typeof job !== "object" || Array.isArray(job)) return true;
      if (hasOwn(job, "permissions")) {
        if (permissionsArePotentiallyPrivileged(job.permissions)) return true;
      } else if (!hasWorkflowPermissions) {
        // With neither workflow nor job permissions declared, repository
        // defaults decide the token authority and may include writes.
        return true;
      }
    }
  } else if (!hasWorkflowPermissions) {
    return true;
  }
  return containsSecretReference(workflow);
};

const actionReferences = (contents) => {
  const usesLines = contents
    .split(/\r?\n/)
    .map((line, index) => (/^\s*(?:-\s*)?["']?uses["']?\s*:/.test(line) ? index + 1 : null))
    .filter((line) => line !== null);
  const references = [];
  const visit = (value) => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      if (key === "uses") {
        if (typeof child !== "string" || child.trim().length === 0) {
          throw new Error("workflow uses values must be non-empty strings");
        }
        references.push({
          line: usesLines[references.length] ?? 1,
          action: child.trim(),
        });
      } else {
        visit(child);
      }
    }
  };
  visit(parseYaml(contents));
  return references;
};

const isMutableExternalAction = (action) => {
  if (action.startsWith("./")) return false;
  if (action.startsWith("docker://")) {
    return !/^docker:\/\/[^@\s]+@sha256:[0-9a-f]{64}$/.test(action);
  }
  const separator = action.lastIndexOf("@");
  const ref = separator === -1 ? "" : action.slice(separator + 1);
  return !/^[0-9a-f]{40}$/.test(ref);
};

export const mutableExternalActions = (contents) =>
  actionReferences(contents).filter(({ action }) => isMutableExternalAction(action));

const REVIEWED_NODE_VERSION = "22.14.0";
const REVIEWED_RUST_VERSION = "1.95.0";

export const mutableToolchainInputs = (contents) => {
  const violations = [];
  const visit = (value) => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (!value || typeof value !== "object") return;

    if (typeof value.uses === "string" && value.uses.startsWith("actions/setup-node@")) {
      const version = value.with?.["node-version"];
      if (String(version ?? "") !== REVIEWED_NODE_VERSION) {
        violations.push(
          `actions/setup-node must select exact reviewed Node.js ${REVIEWED_NODE_VERSION}`,
        );
      }
    }

    if (
      typeof value.uses === "string" &&
      value.uses.startsWith("taiki-e/install-action@") &&
      value.with?.tool !== undefined &&
      !/@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(String(value.with.tool))
    ) {
      violations.push(`taiki-e tool must include an exact version: ${String(value.with.tool)}`);
    }

    if (
      typeof value.uses === "string" &&
      value.uses.startsWith("dtolnay/rust-toolchain@") &&
      String(value.with?.toolchain ?? "") !== REVIEWED_RUST_VERSION
    ) {
      violations.push(
        `dtolnay/rust-toolchain must select exact reviewed Rust ${REVIEWED_RUST_VERSION}`,
      );
    }

    if (typeof value.run === "string") {
      for (const line of value.run.split(/\r?\n/)) {
        const command = line.replace(/#.*$/, "").trim();
        if (
          /\bcargo(?:\s+\+\S+)?\s+install\s+/.test(command) &&
          !/\s--version(?:=|\s)/.test(command)
        ) {
          violations.push(`cargo install must include --version: ${command}`);
        }
        if (/\b(?:cargo|rustc)\s+\+nightly(?:\s|$)/.test(command)) {
          violations.push(`nightly toolchain alias must be date-pinned: ${command}`);
        }
        if (/\brustup\s+toolchain\s+install\s+nightly(?:\s|$)/.test(command)) {
          violations.push(`rustup nightly install must be date-pinned: ${command}`);
        }
      }
    }

    Object.values(value).forEach(visit);
  };
  visit(parseYaml(contents));
  return [...new Set(violations)];
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
  const visitedLocalManifests = new Set();
  const displayPath = (absolutePath) => path.relative(root, absolutePath).split(path.sep).join("/");

  const resolveLocalManifest = (action) => {
    const candidate = path.resolve(root, action.slice(2));
    const relative = path.relative(root, candidate);
    if (relative.startsWith("..") || path.isAbsolute(relative)) {
      throw new Error(`local action escapes the repository: ${action}`);
    }
    if (existsSync(candidate) && statSync(candidate).isFile()) {
      if (!candidate.endsWith(".yml") && !candidate.endsWith(".yaml")) {
        throw new Error(`local uses target is not a YAML manifest: ${action}`);
      }
      return candidate;
    }
    for (const manifestName of ["action.yml", "action.yaml"]) {
      const manifest = path.join(candidate, manifestName);
      if (existsSync(manifest) && statSync(manifest).isFile()) return manifest;
    }
    throw new Error(`local action manifest not found: ${action}`);
  };

  const inspectReferences = (source, contents) => {
    for (const violation of mutableToolchainInputs(contents)) {
      violations.push(`${source}: ${violation}`);
    }
    for (const reference of actionReferences(contents)) {
      if (!reference.action.startsWith("./")) {
        if (isMutableExternalAction(reference.action)) {
          violations.push(`${source}:${reference.line}: ${reference.action}`);
        }
        continue;
      }

      let manifest;
      try {
        manifest = resolveLocalManifest(reference.action);
      } catch (error) {
        violations.push(`${source}:${reference.line}: ${error.message}`);
        continue;
      }
      if (visitedLocalManifests.has(manifest)) continue;
      visitedLocalManifests.add(manifest);
      inspectReferences(displayPath(manifest), readFileSync(manifest, "utf8"));
    }
  };

  const workflowDirectory = path.join(root, ".github/workflows");
  const workflows = readdirSync(workflowDirectory)
    .filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"))
    .sort((left, right) => left.localeCompare(right));
  for (const file of workflows) {
    const workflow = `.github/workflows/${file}`;
    const contents = readFileSync(path.join(workflowDirectory, file), "utf8");
    inspectReferences(workflow, contents);
  }

  // Local composites execute inside their caller's job and can therefore
  // inherit its token, permissions, and secret-bearing environment. Keep
  // their external dependencies immutable even when today's callers happen
  // to be read-only.
  for (const manifest of localActionManifests(root)) {
    const absoluteManifest = path.join(root, manifest);
    if (visitedLocalManifests.has(absoluteManifest)) continue;
    visitedLocalManifests.add(absoluteManifest);
    inspectReferences(manifest, readFileSync(absoluteManifest, "utf8"));
  }
  return violations;
};

const main = () => {
  const violations = checkPrivilegedWorkflows();
  if (violations.length > 0) {
    throw new Error(
      `workflows and local composites must pin external actions and executable toolchains:\n${violations.join("\n")}`,
    );
  }
  console.log("All workflow and local-action dependency pins verified.");
};

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
