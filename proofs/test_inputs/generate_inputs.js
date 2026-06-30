#!/usr/bin/env node
// -----------------------------------------------------------------------
// generate_inputs.js — Generate valid Poseidon Merkle inputs for smoke tests
//
// Produces JSON input files that the circom WASM witness generators can
// consume. Each file contains a complete, valid witness for its circuit.
//
// Usage:  node generate_inputs.js
// Output: proofs/build/<circuit>_input.json
// -----------------------------------------------------------------------
"use strict";

const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");
const path = require("path");

const BUILD_DIR = path.join(__dirname, "..", "build");
const POSEIDON_DOMAIN_NODE = 2;

function envInt(name, fallback) {
  if (!process.env[name]) {
    return fallback;
  }
  const value = Number.parseInt(process.env[name], 10);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`Invalid ${name} value: ${process.env[name]}`);
  }
  return value;
}

// -----------------------------------------------------------------------
function domainPoseidon(poseidon, F, domain, left, right) {
  const taggedLeft = poseidon([BigInt(domain), left]);
  const out = poseidon([F.toObject(taggedLeft), right]);
  return F.toObject(out);
}

// Build a depth-N Merkle tree from leaves using the same domain-separated
// node hash as proofs/circuits/lib/merkleProof.circom.
// Returns { root, layers } where layers[0] = leaves
// -----------------------------------------------------------------------
function buildMerkleTree(poseidon, F, leaves, depth) {
  // Pad leaves to 2^depth with zeros
  const width = 1 << depth;
  const padded = Array(width).fill(BigInt(0));
  for (let i = 0; i < leaves.length && i < width; i++) {
    padded[i] = leaves[i];
  }

  const layers = [padded];
  let current = padded;
  for (let d = 0; d < depth; d++) {
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(
        domainPoseidon(poseidon, F, POSEIDON_DOMAIN_NODE, current[i], current[i + 1])
      );
    }
    current = next;
    layers.push(current);
  }
  return { root: current[0], layers };
}

// -----------------------------------------------------------------------
// Extract a Merkle proof (sibling path) for a given leaf index
// pathIndices are LSB-first bits (idx & 1 then idx >>= 1)
// -----------------------------------------------------------------------
function getMerkleProof(layers, index, depth) {
  const pathElements = [];
  const pathIndices = [];
  let idx = index;
  for (let d = 0; d < depth; d++) {
    const sibIdx = idx ^ 1;
    pathElements.push(layers[d][sibIdx]);
    pathIndices.push(idx & 1);
    idx >>= 1;
  }
  return { pathElements, pathIndices };
}

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  fs.mkdirSync(BUILD_DIR, { recursive: true });

  // =====================================================================
  // 1. document_existence  (configurable depth, prove leaf at index 0)
  // =====================================================================
  {
    const depth = envInt("OLYMPUS_DOCUMENT_MERKLE_DEPTH", 20);
    const leafValue = BigInt(42);
    const leafIndex = 0;
    // treeSize may be <= 2^depth (LessThanBounded(depth) constraint).
    // We have 1 committed leaf at index 0, so treeSize=1 is correct.
    const treeSize = 1;

    const { root, layers } = buildMerkleTree(poseidon, F, [leafValue], depth);
    const { pathElements, pathIndices } = getMerkleProof(layers, leafIndex, depth);

    const input = {
      root: root.toString(),
      leafIndex: leafIndex.toString(),
      treeSize: treeSize.toString(),
      leaf: leafValue.toString(),
      pathElements: pathElements.map((e) => e.toString()),
      pathIndices: pathIndices.map((e) => e.toString()),
    };

    const outPath = path.join(BUILD_DIR, "document_existence_input.json");
    fs.writeFileSync(outPath, JSON.stringify(input, null, 2));
    console.log(`  ✓ document_existence input -> ${outPath}`);
  }

  // =====================================================================
  // 2. non_existence  (depth=256 sparse Merkle, prove all-zero key absent)
  //
  // Circuit interface: root (public), key[32] + pathElements[256] (private).
  // pathIndices are derived internally from key bits — NOT a circuit input.
  //
  // We use an all-zero empty tree.  For a sparse tree where every leaf = 0
  // the level hashes collapse: levelHash[0] = 0 (sentinel), and each higher
  // level is domainPoseidon(NODE, levelHash[d], levelHash[d]).
  // For the all-zero key every path bit is 0 (go left at every level), so
  // every sibling is the right child = levelHash[d].
  // =====================================================================
  {
    const SMT_DEPTH = 256;
    // All-zero 32-byte key
    const key = Array(SMT_DEPTH / 8).fill(0);

    // Build per-level zero hashes lazily (avoids 2^256 allocation)
    const levelHashes = [BigInt(0)]; // levelHashes[0] = leaf sentinel = 0
    for (let d = 0; d < SMT_DEPTH; d++) {
      levelHashes.push(
        domainPoseidon(poseidon, F, POSEIDON_DOMAIN_NODE, levelHashes[d], levelHashes[d])
      );
    }
    const root = levelHashes[SMT_DEPTH];

    // For all-zero key: all path bits are 0 (go left), sibling at level d is levelHashes[d]
    const pathElements = [];
    for (let d = 0; d < SMT_DEPTH; d++) {
      pathElements.push(levelHashes[d]);
    }

    const input = {
      root: root.toString(),
      key: key.map((v) => v.toString()),
      pathElements: pathElements.map((e) => e.toString()),
    };

    const outPath = path.join(BUILD_DIR, "non_existence_input.json");
    fs.writeFileSync(outPath, JSON.stringify(input, null, 2));
    console.log(`  ✓ non_existence input      -> ${outPath}`);
  }

  console.log("\n  All test inputs generated.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
