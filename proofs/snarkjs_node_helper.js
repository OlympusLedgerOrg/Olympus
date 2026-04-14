#!/usr/bin/env node
// -----------------------------------------------------------------------
// snarkjs_node_helper.js — Persistent line-delimited JSON server for
//                          snarkjs Groth16 operations.
//
// Reads newline-terminated JSON requests from stdin, dispatches to the
// snarkjs programmatic API, and writes newline-terminated JSON responses
// to stdout.  The process stays alive for the lifetime of the parent
// Python ProofGenerator instance, amortising V8 + snarkjs start-up cost
// across all prove/verify calls in a session.
//
// Protocol (line-delimited JSON):
//
//   fullProve (witness generation + Groth16 proof in one step):
//     → {"op":"fullProve","input":{...},"wasmFile":"/path","zkeyFile":"/path"}
//     ← {"proof":{...},"publicSignals":[...]}
//
//   prove (from pre-computed witness file):
//     → {"op":"prove","witnessFile":"/path","zkeyFile":"/path"}
//     ← {"proof":{...},"publicSignals":[...]}
//
//   verify:
//     → {"op":"verify","vkeyFile":"/path","proof":{...},"publicSignals":[...]}
//     ← {"ok":true}
//     → {"op":"verify","vkeyFile":"/path","proof":{...},"publicSignals":[...]}
//     ← {"ok":false}
//
//   Errors:
//     ← {"error":"<message>"}
//
// The process exits cleanly when stdin is closed (rl "close" event).
//
// Requirements: Node.js >= 18, snarkjs (npm dependency in proofs/)
// -----------------------------------------------------------------------
"use strict";

const snarkjs = require("snarkjs");
const readline = require("readline");
const fs = require("fs");
const path = require("path");

// -----------------------------------------------------------------------
// Validate file paths: must be absolute and must exist
// -----------------------------------------------------------------------
function validateFilePath(filePath, label) {
  if (typeof filePath !== "string" || filePath.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  if (!path.isAbsolute(filePath)) {
    throw new Error(`${label} must be an absolute path, got: ${filePath}`);
  }
  if (!fs.existsSync(filePath)) {
    throw new Error(`${label} not found: ${filePath}`);
  }
}

// -----------------------------------------------------------------------
// Operation handlers
// -----------------------------------------------------------------------

async function handleFullProve(req) {
  const { input, wasmFile, zkeyFile } = req;

  if (input == null || typeof input !== "object") {
    throw new Error("fullProve requires an 'input' object");
  }
  validateFilePath(wasmFile, "wasmFile");
  validateFilePath(zkeyFile, "zkeyFile");

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    wasmFile,
    zkeyFile
  );
  return { proof, publicSignals };
}

async function handleProve(req) {
  const { witnessFile, zkeyFile } = req;

  validateFilePath(witnessFile, "witnessFile");
  validateFilePath(zkeyFile, "zkeyFile");

  const { proof, publicSignals } = await snarkjs.groth16.prove(
    zkeyFile,
    witnessFile
  );
  return { proof, publicSignals };
}

async function handleVerify(req) {
  const { vkeyFile, proof, publicSignals } = req;

  validateFilePath(vkeyFile, "vkeyFile");

  if (proof == null || typeof proof !== "object") {
    throw new Error("verify requires a 'proof' object");
  }
  if (!Array.isArray(publicSignals)) {
    throw new Error("verify requires a 'publicSignals' array");
  }

  const vkey = JSON.parse(fs.readFileSync(vkeyFile, "utf-8"));
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  return { ok: !!ok };
}

// -----------------------------------------------------------------------
// Main event loop
// -----------------------------------------------------------------------

async function main() {
  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });

  rl.on("line", async (raw) => {
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
      switch (req.op) {
        case "fullProve":
          response = await handleFullProve(req);
          break;
        case "prove":
          response = await handleProve(req);
          break;
        case "verify":
          response = await handleVerify(req);
          break;
        default:
          response = { error: "Unknown op: " + req.op };
      }
    } catch (e) {
      response = { error: e.message || String(e) };
    }

    process.stdout.write(JSON.stringify(response) + "\n");
  });

  rl.on("close", () => {
    process.exit(0);
  });
}

main().catch((err) => {
  process.stderr.write((err.stack || String(err)) + "\n");
  process.exit(1);
});
