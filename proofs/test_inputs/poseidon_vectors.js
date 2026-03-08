#!/usr/bin/env node
// -----------------------------------------------------------------------
// poseidon_vectors.js — Emit deterministic Poseidon(2) test vectors
//
// Uses circomlibjs buildPoseidon (same parameters as circomlib circuits).
// Outputs machine-readable JSON to stdout so Python parity tests can
// compare results against poseidon_py.
//
// Usage:  node poseidon_vectors.js
// Output: {"vectors":[{"a":"...","b":"...","out":"..."}, ...]}
//         All numbers are decimal strings.
// -----------------------------------------------------------------------
"use strict";

const { buildPoseidon } = require("circomlibjs");

// BN128 scalar field prime
const SNARK_SCALAR_FIELD = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const rawVectors = [
    { a: BigInt(0), b: BigInt(0) },
    { a: BigInt(1), b: BigInt(2) },
    { a: BigInt(42), b: BigInt(0) },
    { a: SNARK_SCALAR_FIELD - BigInt(1), b: BigInt(123) },
  ];

  const vectors = rawVectors.map(({ a, b }) => {
    const hash = poseidon([a, b]);
    const out = F.toObject(hash);
    return {
      a: a.toString(),
      b: b.toString(),
      out: out.toString(),
    };
  });

  process.stdout.write(JSON.stringify({ vectors }) + "\n");
}

main().catch((err) => {
  process.stderr.write(err.stack + "\n");
  process.exit(1);
});
