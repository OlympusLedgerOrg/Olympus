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

// -----------------------------------------------------------------------
// Build a depth-N Merkle tree from leaves using Poseidon(2)
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
      const h = poseidon([current[i], current[i + 1]]);
      next.push(F.toObject(h));
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
  // 1. document_existence  (depth = 20, prove leaf at index 0)
  // =====================================================================
  {
    const depth = 20;
    const leafValue = BigInt(42);
    const leafIndex = 0;

    const { root, layers } = buildMerkleTree(poseidon, F, [leafValue], depth);
    const { pathElements, pathIndices } = getMerkleProof(layers, leafIndex, depth);

    const input = {
      root: root.toString(),
      leafIndex: leafIndex.toString(),
      leaf: leafValue.toString(),
      pathElements: pathElements.map((e) => e.toString()),
      pathIndices: pathIndices.map((e) => e.toString()),
    };

    const outPath = path.join(BUILD_DIR, "document_existence_input.json");
    fs.writeFileSync(outPath, JSON.stringify(input, null, 2));
    console.log(`  ✓ document_existence input -> ${outPath}`);
  }

  // =====================================================================
  // 2. non_existence  (depth = 20, prove leaf at index 5 is empty (0))
  //    NOTE: For smoke tests we use an all-zero tree, so every index is empty.
  // =====================================================================
  {
    const depth = 20;
    const leafIndex = 5;

    const { root, layers } = buildMerkleTree(poseidon, F, [], depth);
    const { pathElements, pathIndices } = getMerkleProof(layers, leafIndex, depth);

    const input = {
      root: root.toString(),
      leafIndex: leafIndex.toString(),
      pathElements: pathElements.map((e) => e.toString()),
      pathIndices: pathIndices.map((e) => e.toString()),
    };

    const outPath = path.join(BUILD_DIR, "non_existence_input.json");
    fs.writeFileSync(outPath, JSON.stringify(input, null, 2));
    console.log(`  ✓ non_existence input      -> ${outPath}`);
  }

  // =====================================================================
  // 3. redaction_validity  (maxLeaves = 16, depth = 4)
  //    Reveal leaves 0 and 2 out of 4 set leaves
  // =====================================================================
  {
    const maxLeaves = 16;
    const depth = 4;

    // Build a tree with some non-zero leaves
    const rawLeaves = [BigInt(100), BigInt(200), BigInt(300), BigInt(400)];
    const allLeaves = Array(maxLeaves).fill(BigInt(0));
    for (let i = 0; i < rawLeaves.length; i++) allLeaves[i] = rawLeaves[i];

    const { root, layers } = buildMerkleTree(poseidon, F, allLeaves, depth);

    // Reveal mask: reveal indices 0 and 2
    const revealMask = Array(maxLeaves).fill(0);
    revealMask[0] = 1;
    revealMask[2] = 1;
    const revealedCount = revealMask.reduce((a, b) => a + b, 0);

    // Gather per-leaf Merkle proofs
    const allPathElements = [];
    const allPathIndices = [];
    for (let i = 0; i < maxLeaves; i++) {
      const { pathElements, pathIndices } = getMerkleProof(layers, i, depth);
      allPathElements.push(pathElements.map((e) => e.toString()));
      allPathIndices.push(pathIndices.map((e) => e.toString()));
    }

    // Compute redacted commitment: chain Poseidon over revealed leaves
    const revealedLeaves = allLeaves.map((v, i) => (revealMask[i] === 1 ? v : BigInt(0)));

    let acc = F.toObject(poseidon([BigInt(revealedCount), revealedLeaves[0]]));
    for (let k = 1; k < maxLeaves; k++) {
      acc = F.toObject(poseidon([acc, revealedLeaves[k]]));
    }

    const input = {
      originalRoot: root.toString(),
      redactedCommitment: acc.toString(),
      revealedCount: revealedCount.toString(),
      originalLeaves: allLeaves.map((v) => v.toString()),
      revealMask: revealMask.map((v) => v.toString()),
      pathElements: allPathElements,
      pathIndices: allPathIndices,
    };

    const outPath = path.join(BUILD_DIR, "redaction_validity_input.json");
    fs.writeFileSync(outPath, JSON.stringify(input, null, 2));
    console.log(`  ✓ redaction_validity input  -> ${outPath}`);
  }

  console.log("\n  All test inputs generated.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
