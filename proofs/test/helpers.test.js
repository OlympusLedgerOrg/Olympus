// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");

const proofsDir = path.resolve(__dirname, "..");

function runNode(script, { input, env } = {}) {
  const result = spawnSync(process.execPath, [path.join(proofsDir, script)], {
    cwd: proofsDir,
    encoding: "utf8",
    env: { ...process.env, ...env },
    input,
    maxBuffer: 16 * 1024 * 1024,
    timeout: 120_000,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout;
}

test("document and sparse-tree input generator emits valid witness shapes", () => {
  runNode("test_inputs/generate_inputs.js", {
    // Exercise the configurable tree logic without allocating the full 2^20
    // default tree in every lightweight helper-test run. The production-depth
    // witness is exercised by the circuit smoke/prover jobs.
    env: { OLYMPUS_DOCUMENT_MERKLE_DEPTH: "8" },
  });

  const document = JSON.parse(
    fs.readFileSync(path.join(proofsDir, "build/document_existence_input.json"), "utf8"),
  );
  assert.equal(document.pathElements.length, 8);
  assert.equal(document.pathIndices.length, 8);
  assert.equal(document.treeSize, "1");

  const nonExistence = JSON.parse(
    fs.readFileSync(path.join(proofsDir, "build/non_existence_input.json"), "utf8"),
  );
  assert.equal(nonExistence.key.length, 32);
  assert.equal(nonExistence.pathElements.length, 256);
  assert.match(nonExistence.root, /^\d+$/);
});

test("unified input generator emits every fixed-width circuit field", () => {
  const input = JSON.parse(runNode("test_inputs/generate_unified_inputs.js"));
  assert.equal(input.documentSections.length, 8);
  assert.equal(input.sectionLengths.length, 8);
  assert.equal(input.sectionHashes.length, 8);
  assert.equal(input.merklePath.length, 20);
  assert.equal(input.merkleIndices.length, 20);
  assert.equal(input.ledgerPathElements.length, 256);
  assert.equal(input.ledgerKey.length, 32);
});

test("Poseidon vector helper emits deterministic decimal vectors", () => {
  const output = JSON.parse(runNode("test_inputs/poseidon_vectors.js"));
  assert.deepEqual(output.vectors, [
    {
      a: "0",
      b: "0",
      out: "14744269619966411208579211824598458697587494354926760081771325075741142829156",
    },
    {
      a: "1",
      b: "2",
      out: "7853200120776062878684798364095072458815029376092732009249414926327459813530",
    },
    {
      a: "42",
      b: "0",
      out: "4062130046788682276592684126400580992160311099061031008181023682089773591896",
    },
    {
      a: "21888242871839275222246405745257275088548364400416034343698204186575808495616",
      b: "123",
      out: "19832056004160252043977190200923737134120130395162839341077156927692574252633",
    },
  ]);
  for (const vector of output.vectors) {
    assert.match(vector.a, /^\d+$/);
    assert.match(vector.b, /^\d+$/);
    assert.match(vector.out, /^\d+$/);
  }
});

test("snarkjs line protocol rejects unknown operations without crashing", () => {
  const output = runNode("snarkjs_node_helper.js", {
    input: '{"op":"not-a-real-operation"}\n',
  });
  const response = JSON.parse(output.trim());
  assert.match(response.error, /^Unknown op:/);
});
