#!/usr/bin/env node
/**
 * Smoke test for verify.js — synthesise a v2 checkpoint bundle from
 * deterministic test material, run `node verify.js verify-checkpoint`
 * against it, and assert the JS-side checks accept it. Then mutate
 * each field in turn and assert the verifier rejects.
 *
 * The Groth16 (check 4) is not exercised here — that's the Rust
 * verifier's job (`verifiers/rust/src/bin/verify.rs`). The synthetic
 * bundle ships a placeholder proof block; verify.js prints the cargo
 * invocation and exits 0 if checks 1–3 pass.
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const { blake3 } = require("@noble/hashes/blake3.js");
const { ed25519 } = require("@noble/curves/ed25519.js");
const { buildEddsa, buildPoseidon } = require("./circom_compat.js");

const TextEncoder_ = require("util").TextEncoder;
const enc = new TextEncoder_();
const FORMAT_VERSION = 2;
const ANCHOR_DOMAIN = enc.encode("OLY:CHECKPOINT_ANCHOR:V2");
const STATEMENT_DOMAIN = enc.encode("OLY:CHECKPOINT:STATEMENT:V2");
const BN254_SCALAR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BABYJUBJUB_SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

function i64ToBE8(n) {
  const buf = new Uint8Array(8);
  let v = BigInt.asIntN(64, BigInt(n));
  let u = v < 0n ? (1n << 64n) + v : v;
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(u & 0xffn);
    u >>= 8n;
  }
  return buf;
}

function toHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

function concatBytes(...arrs) {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function u32ToBE4(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function lp(bytes) {
  return concatBytes(u32ToBE4(bytes.length), bytes);
}

function littleEndianBigInt(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}

function bigEndianBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function bigIntToBE32(value) {
  let n = BigInt(value);
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function checkpointMessage(cp) {
  const digest = blake3(
    concatBytes(
      STATEMENT_DOMAIN,
      new Uint8Array([FORMAT_VERSION]),
      lp(enc.encode(cp.checkpoint_scope)),
      lp(enc.encode(cp.shard_id)),
      lp(enc.encode(cp.ledger_root)),
      i64ToBE8(cp.tree_size),
      i64ToBE8(cp.checkpoint_timestamp),
      lp(enc.encode(cp.authority_pubkey_hash)),
    ),
  );
  return littleEndianBigInt(digest) % BN254_SCALAR_MODULUS;
}

function computeAnchorHash(cp, bjj) {
  return blake3(
    concatBytes(
      ANCHOR_DOMAIN,
      new Uint8Array([FORMAT_VERSION]),
      lp(enc.encode(cp.checkpoint_scope)),
      lp(enc.encode(cp.shard_id)),
      lp(enc.encode(cp.ledger_root)),
      i64ToBE8(cp.tree_size),
      i64ToBE8(cp.checkpoint_timestamp),
      lp(enc.encode(cp.authority_pubkey_hash)),
      lp(enc.encode(bjj.signature.r8x)),
      lp(enc.encode(bjj.signature.r8y)),
      lp(enc.encode(bjj.signature.s)),
    ),
  );
}

async function buildSyntheticBundle() {
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = eddsa.F;

  // Deterministic BJJ private key — 32 zero bytes.
  const bjjPriv = new Uint8Array(32);
  bjjPriv[31] = 1;
  const A = eddsa.prv2pub(bjjPriv);
  const Ax = F.toObject(A[0]).toString();
  const Ay = F.toObject(A[1]).toString();
  const authPubkeyHash = F.toObject(poseidon([A[0], A[1]])).toString();

  const node = (left, right) => poseidon([poseidon([F.e(2n), left]), right]);
  const appendedLeaf = F.e(12345678901234567890n);
  const pathElements = [];
  let empty = F.e(0n);
  let ledger = appendedLeaf;
  for (let i = 0; i < 20; i++) {
    pathElements.push(toHex(bigIntToBE32(F.toObject(empty))));
    ledger = node(ledger, empty);
    empty = node(empty, empty);
  }
  const ledgerRoot = F.toObject(ledger).toString();
  const previousRootHex = toHex(bigIntToBE32(F.toObject(empty)));
  const appendedLeafHex = toHex(bigIntToBE32(F.toObject(appendedLeaf)));
  const checkpoint = {
    id: "00000000-0000-0000-0000-000000000001",
    format_version: "2",
    checkpoint_scope: "shard",
    shard_id: "files",
    ledger_root: ledgerRoot,
    tree_size: "1",
    checkpoint_timestamp: "1700000000",
    authority_pubkey_hash: authPubkeyHash,
  };
  const message = checkpointMessage(checkpoint);
  const sig = eddsa.signPoseidon(bjjPriv, F.e(message));
  const sigR8x = F.toObject(sig.R8[0]).toString();
  const sigR8y = F.toObject(sig.R8[1]).toString();
  const sigS = sig.S.toString();
  const bjjBlock = {
    scheme: "BabyJubJub-EdDSA-Poseidon",
    pubkey: { x: Ax, y: Ay },
    signature: { r8x: sigR8x, r8y: sigR8y, s: sigS },
    message: message.toString(),
    message_doc: "test",
  };

  const transitionDigest = blake3(
    concatBytes(
      enc.encode("OLY:SNAPSHOT:PERSIST:V1"),
      lp(bigIntToBE32(F.toObject(empty))),
      lp(bigIntToBE32(F.toObject(ledger))),
      lp(i64ToBE8(1)),
    ),
  );
  const transitionMessage = bigEndianBigInt(transitionDigest) % BABYJUBJUB_SUBGROUP_ORDER;
  const transitionSig = eddsa.signPoseidon(bjjPriv, F.e(transitionMessage));
  const appendTransition = {
    scheme: "Poseidon-one-leaf-append + BabyJubJub-EdDSA",
    previous_root_hex: previousRootHex,
    current_root: ledgerRoot,
    previous_tree_size: "0",
    current_tree_size: "1",
    appended_leaf_hex: appendedLeafHex,
    path: { path_elements: pathElements, path_indices: Array(20).fill(0) },
    signature: {
      r8x: F.toObject(transitionSig.R8[0]).toString(),
      r8y: F.toObject(transitionSig.R8[1]).toString(),
      s: transitionSig.S.toString(),
    },
    message: transitionMessage.toString(),
    message_doc: "test",
  };

  const anchorHash = computeAnchorHash(
    {
      ...checkpoint,
    },
    bjjBlock,
  );
  const anchorHex = toHex(anchorHash);

  // Ed25519 keypair — deterministic.
  const edSk = new Uint8Array(32);
  edSk[0] = 7;
  const edPk = ed25519.getPublicKey(edSk);
  const edSig = ed25519.sign(anchorHash, edSk);

  return {
    schema: "olympus-checkpoint-bundle/v3",
    checkpoint,
    bjj_eddsa_poseidon: bjjBlock,
    append_transition: appendTransition,
    ed25519: {
      scheme: "Ed25519 (RFC 8032)",
      pubkey_hex: toHex(edPk),
      signature_hex: toHex(edSig),
      message_hex: anchorHex,
      message_doc: "test",
    },
    anchor_hash: {
      algorithm: "BLAKE3",
      domain: "OLY:CHECKPOINT_ANCHOR:V2",
      value_hex: anchorHex,
      recompute_doc: "test",
    },
    groth16: {
      scheme: "Groth16 over BN254 (snarkjs format)",
      circuit: "document_existence",
      vkey_ref: "proofs/keys/verification_keys/document_existence_vkey.json",
      proof: { pi_a: [], pi_b: [], pi_c: [] },
      public_signals: [],
    },
  };
}

function runVerifier(bundlePath, expectedExitCode) {
  let result;
  try {
    execFileSync("node", ["verify.js", "verify-checkpoint", "--bundle", bundlePath], {
      stdio: "pipe",
    });
    result = { exitCode: 0 };
  } catch (e) {
    // Treat missing or non-numeric status, spawn failures, and signal termination as errors
    if (e.status === undefined || e.status === null || typeof e.status !== "number") {
      throw new Error(
        `Verifier process failed without numeric exit code: ${e.message}\nstderr: ${e.stderr?.toString() || "(none)"}`,
      );
    }
    result = { exitCode: e.status, stderr: e.stderr?.toString() || "" };
  }
  if (result.exitCode !== expectedExitCode) {
    throw new Error(
      `Expected exit code ${expectedExitCode}, got ${result.exitCode}${result.stderr ? `\nstderr: ${result.stderr}` : ""}`,
    );
  }
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "olympus-bundle-test-"));
  const bundle = await buildSyntheticBundle();

  // 1. Happy path
  const okPath = path.join(tmp, "ok.json");
  fs.writeFileSync(okPath, JSON.stringify(bundle));
  runVerifier(okPath, 0);
  console.log("PASS  happy-path accept");

  // 2. Tamper anchor_hash.value_hex → check 1 rejects
  const t1 = JSON.parse(JSON.stringify(bundle));
  t1.anchor_hash.value_hex = "0".repeat(64);
  const t1Path = path.join(tmp, "t1.json");
  fs.writeFileSync(t1Path, JSON.stringify(t1));
  runVerifier(t1Path, 1);
  console.log("PASS  tamper anchor_hash → reject");

  // 3. Tamper Ed25519 signature → check 2 rejects
  const t2 = JSON.parse(JSON.stringify(bundle));
  // Flip a byte in the signature.
  const sigBytes = Buffer.from(t2.ed25519.signature_hex, "hex");
  sigBytes[0] ^= 0x01;
  t2.ed25519.signature_hex = sigBytes.toString("hex");
  const t2Path = path.join(tmp, "t2.json");
  fs.writeFileSync(t2Path, JSON.stringify(t2));
  runVerifier(t2Path, 1);
  console.log("PASS  tamper Ed25519 sig → reject");

  // 4. Tamper BJJ signature S → check 3b rejects
  const t3 = JSON.parse(JSON.stringify(bundle));
  t3.bjj_eddsa_poseidon.signature.s = (BigInt(t3.bjj_eddsa_poseidon.signature.s) + 1n).toString();
  const t3Path = path.join(tmp, "t3.json");
  fs.writeFileSync(t3Path, JSON.stringify(t3));
  runVerifier(t3Path, 1);
  console.log("PASS  tamper BJJ sig.S → reject");

  const tTransition = JSON.parse(JSON.stringify(bundle));
  tTransition.append_transition.path.path_indices[0] = 1;
  const tTransitionPath = path.join(tmp, "t-transition.json");
  fs.writeFileSync(tTransitionPath, JSON.stringify(tTransition));
  runVerifier(tTransitionPath, 1);
  console.log("PASS  tamper append-consistency path → reject");

  // 5. Tamper authority_pubkey_hash → check 3a rejects
  const t4 = JSON.parse(JSON.stringify(bundle));
  t4.checkpoint.authority_pubkey_hash = "999";
  // Recompute the anchor hash so check 1 doesn't fire first.
  const recomputed = computeAnchorHash(
    {
      ...t4.checkpoint,
    },
    t4.bjj_eddsa_poseidon,
  );
  t4.anchor_hash.value_hex = toHex(recomputed);
  t4.ed25519.message_hex = toHex(recomputed);
  // Re-sign Ed25519 with the same key so check 2 passes.
  const edSk = new Uint8Array(32);
  edSk[0] = 7;
  t4.ed25519.signature_hex = toHex(ed25519.sign(recomputed, edSk));
  const t4Path = path.join(tmp, "t4.json");
  fs.writeFileSync(t4Path, JSON.stringify(t4));
  runVerifier(t4Path, 1);
  console.log("PASS  tamper authority_pubkey_hash → reject");

  // 6. Relabel the signed shard, while recomputing/re-signing only the outer
  // anchor layer. The BJJ statement binding must still reject.
  const tScope = JSON.parse(JSON.stringify(bundle));
  tScope.checkpoint.shard_id = "other";
  const relabelledAnchor = computeAnchorHash(tScope.checkpoint, tScope.bjj_eddsa_poseidon);
  tScope.anchor_hash.value_hex = toHex(relabelledAnchor);
  tScope.ed25519.message_hex = toHex(relabelledAnchor);
  const relabelEdSk = new Uint8Array(32);
  relabelEdSk[0] = 7;
  tScope.ed25519.signature_hex = toHex(ed25519.sign(relabelledAnchor, relabelEdSk));
  const tScopePath = path.join(tmp, "t-scope.json");
  fs.writeFileSync(tScopePath, JSON.stringify(tScope));
  runVerifier(tScopePath, 1);
  console.log("PASS  relabel signed shard → reject");

  // 7. Hexadecimal and non-canonical decimal roots are not alternate wire
  // encodings for a BN254 field element.
  const tHexRoot = JSON.parse(JSON.stringify(bundle));
  tHexRoot.checkpoint.ledger_root = "0x2a";
  const tHexRootPath = path.join(tmp, "t-hex-root.json");
  fs.writeFileSync(tHexRootPath, JSON.stringify(tHexRoot));
  runVerifier(tHexRootPath, 2);
  console.log("PASS  hexadecimal ledger root → reject");

  const tLeadingZero = JSON.parse(JSON.stringify(bundle));
  tLeadingZero.checkpoint.ledger_root = `0${tLeadingZero.checkpoint.ledger_root}`;
  const tLeadingZeroPath = path.join(tmp, "t-leading-zero.json");
  fs.writeFileSync(tLeadingZeroPath, JSON.stringify(tLeadingZero));
  runVerifier(tLeadingZeroPath, 2);
  console.log("PASS  non-canonical decimal root → reject");

  // 8. Shard syntax matches the Rust ingestion and federation boundary.
  const tBadShard = JSON.parse(JSON.stringify(bundle));
  tBadShard.checkpoint.shard_id = "../files";
  const tBadShardPath = path.join(tmp, "t-bad-shard.json");
  fs.writeFileSync(tBadShardPath, JSON.stringify(tBadShard));
  runVerifier(tBadShardPath, 2);
  console.log("PASS  invalid shard identifier → reject");

  // 9. Wrong schema version → exit 2
  const t5 = JSON.parse(JSON.stringify(bundle));
  t5.schema = "olympus-checkpoint-bundle/v999";
  const t5Path = path.join(tmp, "t5.json");
  fs.writeFileSync(t5Path, JSON.stringify(t5));
  runVerifier(t5Path, 2);
  console.log("PASS  wrong schema version → reject");

  // 10. A different, shell-safe circuit identifier is still unsupported by bundle v2.
  const t6 = JSON.parse(JSON.stringify(bundle));
  t6.groth16.circuit = "non_existence";
  const t6Path = path.join(tmp, "t6.json");
  fs.writeFileSync(t6Path, JSON.stringify(t6));
  runVerifier(t6Path, 2);
  console.log("PASS  unsupported Groth16 circuit → reject");

  // 11. A traversal vkey path must never reach the printed shell command.
  const t7 = JSON.parse(JSON.stringify(bundle));
  t7.groth16.vkey_ref = "../../attacker_vkey.json";
  const t7Path = path.join(tmp, "t7.json");
  fs.writeFileSync(t7Path, JSON.stringify(t7));
  runVerifier(t7Path, 2);
  console.log("PASS  unsafe Groth16 vkey path → reject");

  // 12. The order-2 point (0, -1) is on Baby Jubjub but outside its
  // prime-order subgroup and must be rejected before EdDSA verification.
  const tLowOrder = JSON.parse(JSON.stringify(bundle));
  tLowOrder.bjj_eddsa_poseidon.pubkey.x = "0";
  tLowOrder.bjj_eddsa_poseidon.pubkey.y =
    "21888242871839275222246405745257275088548364400416034343698204186575808495616";
  const tLowOrderPath = path.join(tmp, "t-low-order.json");
  fs.writeFileSync(tLowOrderPath, JSON.stringify(tLowOrder));
  runVerifier(tLowOrderPath, 1);
  console.log("PASS  low-order BJJ pubkey → reject");

  console.log("\nAll verify.js smoke tests passed.");
}

main().catch((e) => {
  console.error(e.stack || e.message || e);
  process.exit(1);
});
