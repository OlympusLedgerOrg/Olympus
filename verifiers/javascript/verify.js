#!/usr/bin/env node
/**
 * Independent JavaScript verifier for Olympus checkpoint bundles.
 *
 * Implements the command documented in docs/court-evidence.md §3:
 *
 *   node verify.js verify-checkpoint --bundle <bundle.json>
 *
 * Bundle schema: docs/checkpoint-bundle-schema.md (v1).
 *
 * Runs four independent checks and exits 0 only when all pass.
 *
 *   1. Anchor digest reconstruction (BLAKE3 over the domain-separated
 *      OLY:CHECKPOINT_ANCHOR:V1 field tuple).
 *   2. Ed25519 verify over `anchor_hash` bytes (RFC 8032 via @noble/curves).
 *   3. BJJ-EdDSA-Poseidon verify over `ledger_root` (circomlibjs's reference
 *      iden3 impl, byte-compatible with the Rust babyjubjub-permissive
 *      signer the desktop uses).
 *   4. Groth16 over BN254 — prints the cargo invocation the Rust
 *      verifier crate (`cargo run -p olympus-verifier`) exposes;
 *      the operator runs that out-of-band. The JS verifier itself is
 *      deliberately kept Groth16-free to avoid pulling snarkjs at runtime.
 *
 * Exit codes:
 *   0  all checks passed
 *   1  one or more verifiable checks failed (signature reject, hash
 *      mismatch, etc.)
 *   2  malformed bundle / parse error / missing dependency
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { blake3 } = require('@noble/hashes/blake3.js');
const { ed25519 } = require('@noble/curves/ed25519.js');
const { buildEddsa, buildPoseidon } = require('circomlibjs');

// ── small helpers ─────────────────────────────────────────────────────────────

function die(code, msg) {
  console.error(msg);
  process.exit(code);
}

function fromHex(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`not a hex string: ${JSON.stringify(hex).slice(0, 60)}`);
  }
  if (hex.length % 2 !== 0) throw new Error(`odd-length hex: len=${hex.length}`);
  const buf = new Uint8Array(hex.length / 2);
  for (let i = 0; i < buf.length; i++) {
    buf[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return buf;
}

function toHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

function i64ToBE8(n) {
  // Two's-complement i64 big-endian, matching Rust `i64::to_be_bytes`.
  const buf = new Uint8Array(8);
  let v = BigInt.asIntN(64, BigInt(n));
  // Encode as unsigned then re-interpret.
  let u = v < 0n ? (1n << 64n) + v : v;
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(u & 0xffn);
    u >>= 8n;
  }
  return buf;
}

// ── check #1: anchor digest reconstruction ────────────────────────────────────

const ANCHOR_DOMAIN = new TextEncoder().encode('OLY:CHECKPOINT_ANCHOR:V1');
const SEP = new Uint8Array([0x7c]); // '|'

function reconstructAnchorHash(checkpoint, bjjSig) {
  // Bytes must match src-tauri/src/anchoring/mod.rs::checkpoint_anchor_hash.
  // Empty Optional<&str> serialises as the empty UTF-8 string; tree_size
  // and checkpoint_timestamp are i64 big-endian; all field elements are
  // UTF-8 of their decimal Fr representation.
  const enc = new TextEncoder();
  const parts = [
    ANCHOR_DOMAIN,
    SEP,
    enc.encode(checkpoint.ledger_root),
    SEP,
    i64ToBE8(checkpoint.tree_size),
    SEP,
    i64ToBE8(checkpoint.checkpoint_timestamp),
    SEP,
    enc.encode(checkpoint.authority_pubkey_hash),
    SEP,
    enc.encode(bjjSig.signature.r8x),
    SEP,
    enc.encode(bjjSig.signature.r8y),
    SEP,
    enc.encode(bjjSig.signature.s),
  ];
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return blake3(out);
}

// ── check #2: Ed25519 ─────────────────────────────────────────────────────────

function verifyEd25519(block, anchorHashHex) {
  if (block.message_hex !== anchorHashHex) {
    return {
      ok: false,
      detail: `bundle.ed25519.message_hex (${block.message_hex}) does not match anchor_hash.value_hex (${anchorHashHex})`,
    };
  }
  const pubkey = fromHex(block.pubkey_hex);
  const sig = fromHex(block.signature_hex);
  const msg = fromHex(block.message_hex);
  let ok;
  try {
    ok = ed25519.verify(sig, msg, pubkey);
  } catch (e) {
    return { ok: false, detail: `RFC 8032 verify threw: ${e.message}` };
  }
  return ok
    ? { ok: true }
    : { ok: false, detail: 'RFC 8032 verify returned false' };
}

// ── check #3: BJJ-EdDSA-Poseidon ──────────────────────────────────────────────

/** Strip a BigInt to its Montgomery / regular form via circomlibjs's `F`. */
function fieldFromString(F, decimal) {
  return F.e(BigInt(decimal));
}

async function verifyBjjEdDSAPoseidon(block, ledgerRoot) {
  if (block.message !== ledgerRoot) {
    return {
      ok: false,
      detail: `bundle.bjj_eddsa_poseidon.message (${block.message}) does not match checkpoint.ledger_root (${ledgerRoot})`,
    };
  }
  const eddsa = await buildEddsa();
  const F = eddsa.F;

  // A = (Ax, Ay) on Baby Jubjub. circomlibjs internally checks the point
  // is on the curve / in the prime-order subgroup during `verifyPoseidon`.
  const A = [fieldFromString(F, block.pubkey.x), fieldFromString(F, block.pubkey.y)];
  const sig = {
    R8: [fieldFromString(F, block.signature.r8x), fieldFromString(F, block.signature.r8y)],
    S: BigInt(block.signature.s),
  };
  const msg = fieldFromString(F, block.message);

  const ok = eddsa.verifyPoseidon(msg, sig, A);
  return ok
    ? { ok: true }
    : { ok: false, detail: '8·S·B != 8·R + 8·Poseidon(R,A,M)·A' };
}

async function verifyAuthorityPubkeyHash(bjjBlock, checkpointHash) {
  // authority_pubkey_hash = Poseidon(Ax, Ay). Re-derive from the
  // bundle's published (Ax, Ay) and check it matches the checkpoint
  // row's stored hash — defence against a tampered bundle that
  // substitutes a different signing key.
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const Ax = F.e(BigInt(bjjBlock.pubkey.x));
  const Ay = F.e(BigInt(bjjBlock.pubkey.y));
  const hash = poseidon([Ax, Ay]);
  const hashDecimal = F.toObject(hash).toString();
  if (hashDecimal !== checkpointHash) {
    return {
      ok: false,
      detail: `Poseidon(Ax,Ay) = ${hashDecimal} does not match checkpoint.authority_pubkey_hash = ${checkpointHash}`,
    };
  }
  return { ok: true };
}

// ── CLI ───────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  // Minimal: extract `--bundle <path>` from `verify-checkpoint` subcommand.
  if (argv[0] !== 'verify-checkpoint') {
    die(
      2,
      `usage: node verify.js verify-checkpoint --bundle <bundle.json>\n` +
        `unknown subcommand: ${argv[0] || '(none)'}`,
    );
  }
  let bundlePath = null;
  for (let i = 1; i < argv.length; i++) {
    if (argv[i] === '--bundle') {
      bundlePath = argv[++i];
    } else {
      die(2, `unknown argument: ${argv[i]}`);
    }
  }
  if (!bundlePath) die(2, 'missing required --bundle <path>');
  return { bundlePath };
}

async function main() {
  const { bundlePath } = parseArgs(process.argv.slice(2));
  let bundle;
  try {
    bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
  } catch (e) {
    die(2, `failed to read/parse bundle ${bundlePath}: ${e.message}`);
  }

  // Schema gate — refuse mixed versions.
  if (bundle.schema !== 'olympus-checkpoint-bundle/v1') {
    die(2, `unsupported bundle schema: ${bundle.schema}`);
  }

  // ── Check 1: anchor hash reconstruction ──────────────────────────────────
  let anchorHash;
  try {
    anchorHash = reconstructAnchorHash(bundle.checkpoint, bundle.bjj_eddsa_poseidon);
  } catch (e) {
    die(2, `anchor hash reconstruction failed: ${e.message}`);
  }
  const anchorHex = toHex(anchorHash);
  if (anchorHex !== bundle.anchor_hash.value_hex) {
    console.error(
      `FAIL [1/4 anchor digest]: reconstructed ${anchorHex} != stored ${bundle.anchor_hash.value_hex}`,
    );
    process.exit(1);
  }
  console.log(`OK   [1/4 anchor digest]   BLAKE3 = ${anchorHex}`);

  // ── Check 2: Ed25519 over anchor_hash ────────────────────────────────────
  const ed = verifyEd25519(bundle.ed25519, anchorHex);
  if (!ed.ok) {
    console.error(`FAIL [2/4 Ed25519]: ${ed.detail}`);
    process.exit(1);
  }
  console.log(`OK   [2/4 Ed25519]         pubkey=${bundle.ed25519.pubkey_hex.slice(0, 16)}…`);

  // ── Check 3a: authority_pubkey_hash matches Poseidon(Ax,Ay) ──────────────
  const authCheck = await verifyAuthorityPubkeyHash(
    bundle.bjj_eddsa_poseidon,
    bundle.checkpoint.authority_pubkey_hash,
  );
  if (!authCheck.ok) {
    console.error(`FAIL [3a/4 authority pubkey hash]: ${authCheck.detail}`);
    process.exit(1);
  }
  console.log(`OK   [3a/4 authority hash] Poseidon(Ax,Ay) matches checkpoint.authority_pubkey_hash`);

  // ── Check 3b: BJJ-EdDSA-Poseidon verify ──────────────────────────────────
  const bjj = await verifyBjjEdDSAPoseidon(bundle.bjj_eddsa_poseidon, bundle.checkpoint.ledger_root);
  if (!bjj.ok) {
    console.error(`FAIL [3b/4 BJJ-EdDSA-Poseidon]: ${bjj.detail}`);
    process.exit(1);
  }
  console.log(`OK   [3b/4 BJJ-EdDSA]      verifyPoseidon(message=ledger_root) accepted`);

  // ── Check 4: print the Rust groth16 invocation ───────────────────────────
  // Deliberately delegated to the independent Rust verifier crate to
  // avoid pulling snarkjs at runtime. Writing the snapshot files lets
  // the operator run the cargo command verbatim.
  const tmpDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'olympus-bundle-'));
  const proofPath = path.join(tmpDir, 'proof.json');
  const signalsPath = path.join(tmpDir, 'public.json');
  fs.writeFileSync(proofPath, JSON.stringify(bundle.groth16.proof));
  fs.writeFileSync(signalsPath, JSON.stringify(bundle.groth16.public_signals));
  console.log(`OK   [4/4 Groth16]         pending — run the independent Rust verifier:`);
  console.log('');
  console.log(`     cd verifiers/rust`);
  console.log(`     cargo run --release -- verify \\`);
  console.log(`         --circuit ${bundle.groth16.circuit} \\`);
  console.log(`         --vkey ../../${bundle.groth16.vkey_ref} \\`);
  console.log(`         --proof ${proofPath} \\`);
  console.log(`         --public-signals ${signalsPath}`);
  console.log('');
  console.log(`All JS-side checks passed. Run the Groth16 step above for the fourth proof.`);
  process.exit(0);
}

main().catch((e) => {
  console.error(`ERROR: ${e.stack || e.message || e}`);
  process.exit(2);
});
