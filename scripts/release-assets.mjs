#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const FORMAT = "olympus-release-assets/v1";
const MANIFEST_NAME = "RELEASE_ASSETS.json";
const CHECKSUMS_NAME = "SHA256SUMS";

const TARGETS = new Map([
  [
    "x86_64-pc-windows-msvc",
    {
      required: ["msi", "nsis"],
      optional: [],
    },
  ],
  [
    "x86_64-apple-darwin",
    {
      required: ["dmg"],
      optional: ["macos-updater"],
    },
  ],
  [
    "aarch64-apple-darwin",
    {
      required: ["dmg"],
      optional: ["macos-updater"],
    },
  ],
  [
    "x86_64-unknown-linux-gnu",
    {
      required: ["deb", "appimage", "rpm"],
      optional: [],
    },
  ],
]);

const SBOMS = ["olympus-desktop.cdx.json", "public-ui.cdx.json"];

const artifactType = (name) => {
  if (name.endsWith(".app.tar.gz")) return "macos-updater";
  if (name.endsWith(".AppImage")) return "appimage";
  if (name.endsWith(".msi")) return "msi";
  if (name.endsWith(".exe")) return "nsis";
  if (name.endsWith(".dmg")) return "dmg";
  if (name.endsWith(".deb")) return "deb";
  if (name.endsWith(".rpm")) return "rpm";
  return null;
};

const sha256 = (file) => {
  const hash = createHash("sha256");
  hash.update(readFileSync(file));
  return hash.digest("hex");
};

const sortedDirectoryFiles = (directory) => {
  if (!existsSync(directory) || !statSync(directory).isDirectory()) {
    throw new Error(`missing directory: ${directory}`);
  }

  const entries = readdirSync(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
      throw new Error(`symbolic links are not allowed in release assets: ${entry.name}`);
    }
    if (!entry.isFile()) {
      throw new Error(`nested release asset entries are not allowed: ${entry.name}`);
    }
    files.push(entry.name);
  }
  return files.sort((left, right) => left.localeCompare(right));
};

const recursiveFiles = (directory, prefix = "") => {
  if (!existsSync(directory) || !statSync(directory).isDirectory()) {
    throw new Error(`missing directory: ${directory}`);
  }

  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const relative = prefix ? path.join(prefix, entry.name) : entry.name;
    if (entry.isSymbolicLink()) {
      throw new Error(`symbolic links are not allowed in release artifacts: ${relative}`);
    }
    if (entry.isDirectory()) {
      files.push(...recursiveFiles(path.join(directory, entry.name), relative));
    } else if (entry.isFile()) {
      files.push(relative);
    } else {
      throw new Error(`unsupported release artifact entry: ${relative}`);
    }
  }
  return files.sort((left, right) => left.localeCompare(right));
};

const requireEmptyOutput = (directory) => {
  if (existsSync(directory)) {
    if (!statSync(directory).isDirectory() || readdirSync(directory).length !== 0) {
      throw new Error(`output directory must be absent or empty: ${directory}`);
    }
  } else {
    mkdirSync(directory, { recursive: true });
  }
};

const safeAssetName = (name) => {
  if (
    typeof name !== "string" ||
    name.length === 0 ||
    name === "." ||
    name === ".." ||
    name.includes("/") ||
    name.includes("\\") ||
    /[\u0000-\u001f\u007f]/.test(name) ||
    name.trim() !== name ||
    path.basename(name) !== name
  ) {
    throw new Error(`unsafe release asset name: ${JSON.stringify(name)}`);
  }
  return name;
};

const validateInstallerCoverage = (assets) => {
  const installers = assets.filter((asset) => asset.kind === "installer");

  for (const [target, policy] of TARGETS) {
    const targetAssets = installers.filter((asset) => asset.target === target);
    const counts = new Map();
    for (const asset of targetAssets) {
      if (!asset.name.startsWith(`${target}--`)) {
        throw new Error(`installer name is not bound to target ${target}: ${asset.name}`);
      }
      const type = artifactType(asset.name);
      if (type === null || (!policy.required.includes(type) && !policy.optional.includes(type))) {
        throw new Error(`unexpected installer type for ${target}: ${asset.name}`);
      }
      counts.set(type, (counts.get(type) ?? 0) + 1);
    }

    for (const type of policy.required) {
      if (counts.get(type) !== 1) {
        throw new Error(`${target} must contain exactly one ${type} installer`);
      }
    }
    for (const type of policy.optional) {
      if ((counts.get(type) ?? 0) > 1) {
        throw new Error(`${target} contains more than one optional ${type} artifact`);
      }
    }
  }

  const unknownTargets = new Set(
    installers.map((asset) => asset.target).filter((target) => !TARGETS.has(target)),
  );
  if (unknownTargets.size > 0) {
    throw new Error(`unknown release targets: ${[...unknownTargets].sort().join(", ")}`);
  }
};

const metadataFor = (file, fields) => {
  const size = statSync(file).size;
  if (size <= 0) throw new Error(`release assets must not be empty: ${fields.name}`);
  return {
    ...fields,
    sha256: sha256(file),
    size,
  };
};

export const stageReleaseAssets = ({ input, sbom, output, tag, commit, installerChecksums }) => {
  if (!tag) throw new Error("release tag/ref must not be empty");
  if (!commit || !/^[0-9a-f]{40}$/i.test(commit)) {
    throw new Error("source commit must be a 40-character Git object id");
  }
  requireEmptyOutput(output);

  const assets = [];
  const installerNames = new Set();

  for (const [target, policy] of TARGETS) {
    const sourceDirectory = path.join(input, `olympus-${target}`);
    for (const sourceRelativePath of recursiveFiles(sourceDirectory)) {
      const sourceName = path.basename(sourceRelativePath);
      const type = artifactType(sourceName);
      if (type === null || (!policy.required.includes(type) && !policy.optional.includes(type))) {
        throw new Error(`unexpected release artifact for ${target}: ${sourceName}`);
      }

      const name = safeAssetName(`${target}--${sourceName}`);
      if (installerNames.has(name)) throw new Error(`duplicate release asset name: ${name}`);
      installerNames.add(name);

      const source = path.join(sourceDirectory, sourceRelativePath);
      const destination = path.join(output, name);
      copyFileSync(source, destination, 0);
      assets.push(metadataFor(destination, { name, kind: "installer", target }));
    }
  }

  for (const name of SBOMS) {
    safeAssetName(name);
    const source = path.join(sbom, name);
    if (!existsSync(source) || !statSync(source).isFile() || statSync(source).size === 0) {
      throw new Error(`missing or empty release SBOM: ${source}`);
    }
    const destination = path.join(output, name);
    copyFileSync(source, destination, 0);
    assets.push(metadataFor(destination, { name, kind: "sbom" }));
  }

  assets.sort((left, right) => left.name.localeCompare(right.name));
  validateInstallerCoverage(assets);

  const manifest = {
    format: FORMAT,
    releaseTag: tag,
    sourceCommit: commit.toLowerCase(),
    assets,
  };
  const manifestPath = path.join(output, MANIFEST_NAME);
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  const checksumEntries = [
    ...assets.map((asset) => [asset.sha256, asset.name]),
    [sha256(manifestPath), MANIFEST_NAME],
  ].sort((left, right) => left[1].localeCompare(right[1]));
  writeFileSync(
    path.join(output, CHECKSUMS_NAME),
    `${checksumEntries.map(([digest, name]) => `${digest}  ${name}`).join("\n")}\n`,
    "utf8",
  );

  const installerEntries = assets
    .filter((asset) => asset.kind === "installer")
    .map((asset) => `${asset.sha256}  ${asset.name}`);
  writeFileSync(installerChecksums, `${installerEntries.join("\n")}\n`, "utf8");

  return manifest;
};

const parseManifest = (input, expectedTag, expectedCommit) => {
  const manifestPath = path.join(input, MANIFEST_NAME);
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (error) {
    throw new Error(`invalid ${MANIFEST_NAME}: ${error.message}`);
  }

  if (manifest.format !== FORMAT) throw new Error(`unsupported release manifest format`);
  if (expectedTag && manifest.releaseTag !== expectedTag) {
    throw new Error(
      `release manifest tag mismatch: expected ${expectedTag}, got ${manifest.releaseTag}`,
    );
  }
  if (!/^[0-9a-f]{40}$/.test(manifest.sourceCommit ?? "")) {
    throw new Error("release manifest has an invalid source commit");
  }
  if (expectedCommit && manifest.sourceCommit !== expectedCommit.toLowerCase()) {
    throw new Error(
      `release manifest commit mismatch: expected ${expectedCommit}, got ${manifest.sourceCommit}`,
    );
  }
  if (!Array.isArray(manifest.assets) || manifest.assets.length === 0) {
    throw new Error("release manifest contains no assets");
  }

  const names = new Set();
  for (const asset of manifest.assets) {
    safeAssetName(asset.name);
    if (names.has(asset.name)) throw new Error(`duplicate manifest asset: ${asset.name}`);
    names.add(asset.name);
    if (asset.kind !== "installer" && asset.kind !== "sbom") {
      throw new Error(`unsupported asset kind for ${asset.name}`);
    }
    if (asset.kind === "installer" && typeof asset.target !== "string") {
      throw new Error(`installer target missing for ${asset.name}`);
    }
    if (asset.kind === "sbom" && !SBOMS.includes(asset.name)) {
      throw new Error(`unexpected release SBOM: ${asset.name}`);
    }
    if (!/^[0-9a-f]{64}$/.test(asset.sha256 ?? "")) {
      throw new Error(`invalid SHA-256 for ${asset.name}`);
    }
    if (!Number.isSafeInteger(asset.size) || asset.size <= 0) {
      throw new Error(`invalid size for ${asset.name}`);
    }
  }

  for (const sbomName of SBOMS) {
    if (!names.has(sbomName)) throw new Error(`release manifest is missing ${sbomName}`);
  }
  validateInstallerCoverage(manifest.assets);
  return manifest;
};

const parseChecksums = (input) => {
  const checksums = new Map();
  const contents = readFileSync(path.join(input, CHECKSUMS_NAME), "utf8");
  for (const line of contents.split(/\r?\n/)) {
    if (line.length === 0) continue;
    const match = /^([0-9a-f]{64})  ([^/\\]+)$/.exec(line);
    if (!match) throw new Error(`malformed ${CHECKSUMS_NAME} line: ${line}`);
    const [, digest, name] = match;
    safeAssetName(name);
    if (checksums.has(name)) throw new Error(`duplicate checksum entry: ${name}`);
    checksums.set(name, digest);
  }
  return checksums;
};

export const verifyReleaseAssets = ({ input, output, tag, commit }) => {
  const manifest = parseManifest(input, tag, commit);
  const expected = new Map(manifest.assets.map((asset) => [asset.name, asset.sha256]));
  expected.set(MANIFEST_NAME, sha256(path.join(input, MANIFEST_NAME)));

  const checksums = parseChecksums(input);
  if (checksums.size !== expected.size) {
    throw new Error(`${CHECKSUMS_NAME} does not cover the exact release manifest asset set`);
  }
  for (const [name, digest] of expected) {
    if (checksums.get(name) !== digest) {
      throw new Error(`${CHECKSUMS_NAME} mismatch or missing entry for ${name}`);
    }
  }

  const expectedFiles = new Set([...expected.keys(), CHECKSUMS_NAME]);
  for (const name of sortedDirectoryFiles(input)) {
    if (!expectedFiles.has(name)) {
      throw new Error(`stale or unmanifested release asset: ${name}`);
    }
  }

  for (const asset of manifest.assets) {
    const file = path.join(input, asset.name);
    if (!existsSync(file) || !statSync(file).isFile()) {
      throw new Error(`manifested release asset is missing: ${asset.name}`);
    }
    if (statSync(file).size !== asset.size) {
      throw new Error(`release asset size mismatch: ${asset.name}`);
    }
    if (sha256(file) !== asset.sha256) {
      throw new Error(`release asset digest mismatch: ${asset.name}`);
    }
  }

  if (output) {
    requireEmptyOutput(output);
    for (const name of expectedFiles) {
      copyFileSync(path.join(input, name), path.join(output, name), 0);
    }
  }

  return manifest;
};

const parseArguments = (argv) => {
  const [command, ...rest] = argv;
  const options = {};
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index];
    const value = rest[index + 1];
    if (!flag?.startsWith("--") || value === undefined) {
      throw new Error(`expected --name value argument, got ${flag ?? "end of input"}`);
    }
    options[flag.slice(2)] = value;
  }
  return { command, options };
};

const main = () => {
  const { command, options } = parseArguments(process.argv.slice(2));
  if (command === "stage") {
    stageReleaseAssets({
      input: options.input,
      sbom: options.sbom,
      output: options.output,
      tag: options.tag,
      commit: options.commit,
      installerChecksums: options["installer-checksums"],
    });
    return;
  }
  if (command === "verify") {
    verifyReleaseAssets({
      input: options.input,
      output: options.output,
      tag: options.tag,
      commit: options.commit,
    });
    return;
  }
  throw new Error("usage: release-assets.mjs stage|verify --input DIR [options]");
};

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    console.error(`release asset verification failed: ${error.message}`);
    process.exitCode = 1;
  }
}
