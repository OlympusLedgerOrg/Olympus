#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Two tripwires for the preview release channel
 * (docs/plans/preview-release-channel.md).
 *
 * 1. CONTAINMENT. `OLYMPUS_RELEASE_CHANNEL=preview` flips the meaning of an
 *    absent `OLYMPUS_ENV` from production to development
 *    (`src-tauri/src/env.rs`). That is safe in exactly one place — the preview
 *    workflow — and nowhere else. Set anywhere a `v*` tag build or a CI test
 *    job could see it, it would silently disable the production secret gates.
 *    So: only `.github/workflows/tauri-preview.yml` may mention it.
 *
 * 2. PIN AGREEMENT. `tauri-preview.yml` deliberately does not re-run the
 *    release preflight, which means the two workflows are separate files that
 *    can drift. Where they pin the same third-party action or toolchain, the
 *    pins must agree, so a security bump to one is not silently missing from
 *    the other.
 *
 * Run via `pnpm preview-channel:check` (wired into `pnpm tooling:check`).
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));

const CHANNEL_ENV = "OLYMPUS_RELEASE_CHANNEL";
const PREVIEW_WORKFLOW = ".github/workflows/tauri-preview.yml";
const RELEASE_WORKFLOW = ".github/workflows/tauri-release.yml";
const SHARED_ACTION = ".github/actions/setup-build-toolchain/action.yml";

/** Files that legitimately discuss the channel without configuring a build. */
const DOC_EXTENSIONS = new Set([".md"]);

/** Directories never worth scanning. */
const SKIP_DIRECTORIES = new Set([
  ".git",
  "node_modules",
  "target",
  "dist",
  ".claude",
  "proofs/build",
  "proofs/keys",
]);

const walk = (root, relative = "") => {
  const absolute = path.join(root, relative);
  const out = [];
  for (const entry of readdirSync(absolute, { withFileTypes: true })) {
    const next = relative ? path.posix.join(relative, entry.name) : entry.name;
    if (SKIP_DIRECTORIES.has(entry.name) || SKIP_DIRECTORIES.has(next)) continue;
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      out.push(...walk(root, next));
    } else if (entry.isFile()) {
      out.push(next);
    }
  }
  return out;
};

/**
 * Every file that mentions `OLYMPUS_RELEASE_CHANNEL`, excluding documentation
 * (which must be free to explain it) and this checker plus its own test.
 */
export const findChannelMentions = (root) => {
  const self = new Set([
    "scripts/check-preview-channel.mjs",
    "scripts/check-preview-channel.test.mjs",
  ]);
  const offenders = [];
  for (const relative of walk(root)) {
    if (self.has(relative)) continue;
    if (DOC_EXTENSIONS.has(path.extname(relative))) continue;
    if (statSync(path.join(root, relative)).size > 2_000_000) continue;
    let contents;
    try {
      contents = readFileSync(path.join(root, relative), "utf8");
    } catch {
      continue;
    }
    if (contents.includes(CHANNEL_ENV)) offenders.push(relative);
  }
  return offenders.sort();
};

export const checkContainment = (root) => {
  const errors = [];
  const mentions = findChannelMentions(root);
  // The preview workflow is the only producer. `build.rs` reads it at compile
  // time and re-emits it as a `rustc-env`; `env.rs` reads that re-emitted value
  // through `env!`. Nothing else may touch it.
  const permitted = new Set([PREVIEW_WORKFLOW, "src-tauri/build.rs", "src-tauri/src/env.rs"]);
  for (const file of mentions) {
    if (!permitted.has(file)) {
      errors.push(
        `${file} mentions ${CHANNEL_ENV}. Only ${PREVIEW_WORKFLOW} may set it, and only ` +
          `src-tauri/build.rs and src-tauri/src/env.rs may read it — setting it anywhere a ` +
          `v* tag build or a test job could see it silently disables the production secret gates.`,
      );
    }
  }
  if (!mentions.includes(PREVIEW_WORKFLOW)) {
    errors.push(
      `${PREVIEW_WORKFLOW} no longer sets ${CHANNEL_ENV}; preview builds would be ` +
        `stamped as stable and refuse to start for anyone without the production secrets.`,
    );
  }
  return errors;
};

/** Map of `owner/action` (or `./local/path`) → pinned ref, from `uses:` lines. */
export const collectActionPins = (contents) => {
  const pins = new Map();
  const pattern = /^\s*(?:-\s*)?uses:\s*([^\s#]+)\s*$/gm;
  let match;
  while ((match = pattern.exec(contents)) !== null) {
    const value = match[1];
    if (value.startsWith("./")) continue; // local composite actions carry no ref
    const at = value.lastIndexOf("@");
    if (at <= 0) continue;
    pins.set(value.slice(0, at), value.slice(at + 1));
  }
  return pins;
};

/**
 * Pinned tool versions that must not drift between the two workflows.
 *
 * A workflow states them inline (`toolchain: 1.95.0`); the shared composite
 * action states them as input defaults, because its callers pass no version.
 * Both spellings are read here so the comparison is like-for-like.
 */
export const collectToolVersions = (contents) => ({
  rust:
    /^\s*toolchain:\s*"?([0-9]+\.[0-9]+\.[0-9]+)"?\s*$/m.exec(contents)?.[1] ??
    compositeInputDefault(contents, "rust-toolchain"),
  node:
    /^\s*node-version:\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$/m.exec(contents)?.[1] ??
    compositeInputDefault(contents, "node-version"),
  tauriCli:
    /cargo install tauri-cli --version ([0-9]+\.[0-9]+\.[0-9]+)/.exec(contents)?.[1] ?? null,
});

/**
 * The `default:` of a named composite-action input, e.g. for
 *   rust-toolchain:
 *     description: ...
 *     default: "1.95.0"
 * returns "1.95.0". Scoped to the lines following the input name so a
 * `default:` belonging to a different input is never picked up.
 */
const compositeInputDefault = (contents, inputName) => {
  const start = new RegExp(`^\\s*${inputName}:\\s*$`, "m").exec(contents);
  if (!start) return null;
  const rest = contents.slice(start.index + start[0].length);
  // Stop at the next top-level-ish key so we stay inside this input's block.
  const block = rest.split(/\n(?=\s{0,2}\S)/, 1)[0] ?? rest;
  return /default:\s*"?([0-9]+\.[0-9]+\.[0-9]+)"?/.exec(block)?.[1] ?? null;
};

export const checkPinAgreement = (root) => {
  const read = (relative) => readFileSync(path.join(root, relative), "utf8");
  const release = read(RELEASE_WORKFLOW);
  const preview = read(PREVIEW_WORKFLOW);
  const shared = read(SHARED_ACTION);

  const errors = [];

  const releasePins = collectActionPins(release);
  // The preview path reaches third-party actions both directly and through the
  // shared composite action, so both files count as "the preview side".
  const previewPins = new Map([...collectActionPins(shared), ...collectActionPins(preview)]);
  for (const [action, previewRef] of previewPins) {
    const releaseRef = releasePins.get(action);
    if (releaseRef !== undefined && releaseRef !== previewRef) {
      errors.push(
        `${action} is pinned to ${releaseRef} in ${RELEASE_WORKFLOW} but ${previewRef} on the ` +
          `preview path. Bump both together.`,
      );
    }
  }

  const releaseVersions = collectToolVersions(release);
  const previewVersions = {
    ...collectToolVersions(shared),
    ...Object.fromEntries(
      Object.entries(collectToolVersions(preview)).filter(([, value]) => value !== null),
    ),
  };
  for (const [tool, releaseVersion] of Object.entries(releaseVersions)) {
    const previewVersion = previewVersions[tool];
    if (releaseVersion === null) continue;
    if (previewVersion === undefined || previewVersion === null) {
      errors.push(
        `the preview path does not pin ${tool}; ${RELEASE_WORKFLOW} pins ${releaseVersion}.`,
      );
    } else if (previewVersion !== releaseVersion) {
      errors.push(
        `${tool} is ${releaseVersion} in ${RELEASE_WORKFLOW} but ${previewVersion} on the ` +
          `preview path. Bump both together.`,
      );
    }
  }

  return errors;
};

export const checkPreviewChannel = (root = REPO_ROOT) => [
  ...checkContainment(root),
  ...checkPinAgreement(root),
];

const main = () => {
  const errors = checkPreviewChannel();
  if (errors.length > 0) {
    for (const error of errors) console.error(`preview-channel: ${error}`);
    console.error(
      "\nSee docs/plans/preview-release-channel.md (sections D1 and D2) for why these hold.",
    );
    process.exitCode = 1;
    return;
  }
  console.log("preview-channel: containment and pin agreement OK");
};

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
