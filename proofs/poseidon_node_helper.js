#!/usr/bin/env node
// -----------------------------------------------------------------------
// poseidon_node_helper.js — Persistent line-delimited JSON server
//
// Reads newline-terminated JSON requests from stdin one line at a time,
// computes the requested Poseidon operation with circomlibjs, and writes
// a newline-terminated JSON response to stdout.  The process stays alive
// for the lifetime of the parent Python interpreter; a single `node`
// spawn amortises the V8 + circomlibjs start-up cost across all hash
// calls in a session.
//
// Protocol (line-delimited JSON, all integers as decimal strings):
//
//   Single pair:
//     → {"op":"hash2","a":"<int>","b":"<int>"}
//     ← {"out":"<int>"}
//
//   Batch pairs (hash a full tree level in one round-trip):
//     → {"op":"batch_hash2","pairs":[{"a":"<int>","b":"<int>"},...]}
//     ← {"outs":["<int>",...]}
//
//   Full Merkle root:
//     → {"op":"merkle_root","leaves":["<int>",...][,"depth":N]}
//     ← {"out":"<int>"}
//
//   Errors:
//     ← {"error":"<message>"}
//
// The process exits cleanly when stdin is closed (rl "close" event).
// -----------------------------------------------------------------------
"use strict";

const { buildPoseidon } = require("circomlibjs");
const readline = require("readline");

const SNARK_SCALAR_FIELD = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

function buildMerkleRoot(poseidon, F, leaves, depth) {
  let level;
  if (depth !== undefined && depth !== null) {
    const width = 1 << depth;
    level = Array(width).fill(BigInt(0));
    for (let i = 0; i < leaves.length && i < width; i++) {
      level[i] = leaves[i];
    }
  } else {
    level = [...leaves];
    if (level.length % 2 === 1) {
      level.push(level[level.length - 1]);
    }
  }

  while (level.length > 1) {
    if (level.length % 2 === 1) {
      level.push(level[level.length - 1]);
    }
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const h = poseidon([level[i], level[i + 1]]);
      next.push(F.toObject(h) % SNARK_SCALAR_FIELD);
    }
    level = next;
  }
  return (level[0] % SNARK_SCALAR_FIELD).toString();
}

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });

  rl.on("line", (raw) => {
    const line = raw.trim();
    if (!line) return;

    let req;
    try {
      req = JSON.parse(line);
    } catch (e) {
      process.stdout.write(
        JSON.stringify({ error: "JSON parse error: " + e.message }) + "\n"
      );
      return;
    }

    let response;
    try {
      if (req.op === "hash2") {
        const a = BigInt(req.a) % SNARK_SCALAR_FIELD;
        const b = BigInt(req.b) % SNARK_SCALAR_FIELD;
        const h = poseidon([a, b]);
        response = { out: (F.toObject(h) % SNARK_SCALAR_FIELD).toString() };
      } else if (req.op === "batch_hash2") {
        const outs = (req.pairs || []).map((pair) => {
          const a = BigInt(pair.a) % SNARK_SCALAR_FIELD;
          const b = BigInt(pair.b) % SNARK_SCALAR_FIELD;
          const h = poseidon([a, b]);
          return (F.toObject(h) % SNARK_SCALAR_FIELD).toString();
        });
        response = { outs };
      } else if (req.op === "merkle_root") {
        const leaves = (req.leaves || []).map(
          (s) => BigInt(s) % SNARK_SCALAR_FIELD
        );
        const depth =
          req.depth !== undefined && req.depth !== null ? req.depth : undefined;
        response = { out: buildMerkleRoot(poseidon, F, leaves, depth) };
      } else {
        response = { error: "Unknown op: " + req.op };
      }
    } catch (e) {
      response = { error: e.message };
    }

    process.stdout.write(JSON.stringify(response) + "\n");
  });

  rl.on("close", () => {
    process.exit(0);
  });
}

main().catch((err) => {
  process.stderr.write(err.stack + "\n");
  process.exit(1);
});
