#!/usr/bin/env node
/**
 * Smoke test for verify.js — synthesise a v1 checkpoint bundle from
 * deterministic test material, run `node verify.js verify-checkpoint`
 * against it, and assert the JS-side checks accept it. Then mutate
 * each field in turn and assert the verifier rejects.
 *
 * The Groth16 (check 4) is not exercised here — that's the Rust
 * verifier's job (`verifiers/rust/src/bin/verify.rs`). The synthetic
 * bundle ships a placeholder proof block; verify.js prints the cargo
 * invocation and exits 0 if checks 1–3 pass.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const { blake3 } = require('@noble/hashes/blake3.js');
const { ed25519 } = require('@noble/curves/ed25519');
const { buildEddsa, buildPoseidon } = require('circomlibjs');

const TextEncoder_ = require('util').TextEncoder;
const enc = new (TextEncoder_)();
const SEP = new Uint8Array([0x7c]);
const ANCHOR_DOMAIN = enc.encode('OLY:CHECKPOINT_ANCHOR:V1');

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
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
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

function computeAnchorHash(cp, bjj) {
  return blake3(
    concatBytes(
      ANCHOR_DOMAIN, SEP,
      enc.encode(cp.ledger_root), SEP,
      i64ToBE8(cp.tree_size), SEP,
      i64ToBE8(cp.checkpoint_timestamp), SEP,
      enc.encode(cp.authority_pubkey_hash), SEP,
      enc.encode(bjj.signature.r8x), SEP,
      enc.encode(bjj.signature.r8y), SEP,
      enc.encode(bjj.signature.s),
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

  // Sign Poseidon(ledger_root) — but the federation flow signs
  // ledger_root directly, so message = ledger_root.
  const ledgerRoot = '12345678901234567890';
  const msg = F.e(BigInt(ledgerRoot));
  const sig = eddsa.signPoseidon(bjjPriv, msg);
  const sigR8x = F.toObject(sig.R8[0]).toString();
  const sigR8y = F.toObject(sig.R8[1]).toString();
  const sigS = sig.S.toString();

  const checkpoint = {
    id: '00000000-0000-0000-0000-000000000001',
    ledger_root: ledgerRoot,
    tree_size: '42',
    checkpoint_timestamp: '1700000000',
    authority_pubkey_hash: authPubkeyHash,
  };
  const bjjBlock = {
    scheme: 'BabyJubJub-EdDSA-Poseidon',
    pubkey: { x: Ax, y: Ay },
    signature: { r8x: sigR8x, r8y: sigR8y, s: sigS },
    message: ledgerRoot,
    message_doc: 'test',
  };

  const anchorHash = computeAnchorHash(
    {
      ledger_root: checkpoint.ledger_root,
      tree_size: Number(checkpoint.tree_size),
      checkpoint_timestamp: Number(checkpoint.checkpoint_timestamp),
      authority_pubkey_hash: checkpoint.authority_pubkey_hash,
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
    schema: 'olympus-checkpoint-bundle/v1',
    checkpoint,
    bjj_eddsa_poseidon: bjjBlock,
    ed25519: {
      scheme: 'Ed25519 (RFC 8032)',
      pubkey_hex: toHex(edPk),
      signature_hex: toHex(edSig),
      message_hex: anchorHex,
      message_doc: 'test',
    },
    anchor_hash: {
      algorithm: 'BLAKE3',
      domain: 'OLY:CHECKPOINT_ANCHOR:V1',
      value_hex: anchorHex,
      recompute_doc: 'test',
    },
    groth16: {
      scheme: 'Groth16 over BN254 (snarkjs format)',
      circuit: 'document_existence',
      vkey_ref: 'proofs/keys/verification_keys/document_existence_vkey.json',
      proof: { pi_a: [], pi_b: [], pi_c: [] },
      public_signals: [],
    },
  };
}

function runVerifier(bundlePath, expectAccept) {
  let result;
  try {
    execFileSync('node', ['verify.js', 'verify-checkpoint', '--bundle', bundlePath], {
      stdio: 'pipe',
    });
    result = { exitCode: 0 };
  } catch (e) {
    result = { exitCode: e.status, stderr: e.stderr?.toString() || '' };
  }
  if (expectAccept && result.exitCode !== 0) {
    throw new Error(
      `expected accept, got exit ${result.exitCode}: ${result.stderr || ''}`,
    );
  }
  if (!expectAccept && result.exitCode === 0) {
    throw new Error(`expected reject, got accept`);
  }
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'olympus-bundle-test-'));
  const bundle = await buildSyntheticBundle();

  // 1. Happy path
  const okPath = path.join(tmp, 'ok.json');
  fs.writeFileSync(okPath, JSON.stringify(bundle));
  runVerifier(okPath, true);
  console.log('PASS  happy-path accept');

  // 2. Tamper anchor_hash.value_hex → check 1 rejects
  const t1 = JSON.parse(JSON.stringify(bundle));
  t1.anchor_hash.value_hex = '0'.repeat(64);
  const t1Path = path.join(tmp, 't1.json');
  fs.writeFileSync(t1Path, JSON.stringify(t1));
  runVerifier(t1Path, false);
  console.log('PASS  tamper anchor_hash → reject');

  // 3. Tamper Ed25519 signature → check 2 rejects
  const t2 = JSON.parse(JSON.stringify(bundle));
  // Flip a byte in the signature.
  const sigBytes = Buffer.from(t2.ed25519.signature_hex, 'hex');
  sigBytes[0] ^= 0x01;
  t2.ed25519.signature_hex = sigBytes.toString('hex');
  const t2Path = path.join(tmp, 't2.json');
  fs.writeFileSync(t2Path, JSON.stringify(t2));
  runVerifier(t2Path, false);
  console.log('PASS  tamper Ed25519 sig → reject');

  // 4. Tamper BJJ signature S → check 3b rejects
  const t3 = JSON.parse(JSON.stringify(bundle));
  t3.bjj_eddsa_poseidon.signature.s = (BigInt(t3.bjj_eddsa_poseidon.signature.s) + 1n).toString();
  const t3Path = path.join(tmp, 't3.json');
  fs.writeFileSync(t3Path, JSON.stringify(t3));
  runVerifier(t3Path, false);
  console.log('PASS  tamper BJJ sig.S → reject');

  // 5. Tamper authority_pubkey_hash → check 3a rejects
  const t4 = JSON.parse(JSON.stringify(bundle));
  t4.checkpoint.authority_pubkey_hash = '999';
  // Recompute the anchor hash so check 1 doesn't fire first.
  const recomputed = computeAnchorHash(
    {
      ledger_root: t4.checkpoint.ledger_root,
      tree_size: Number(t4.checkpoint.tree_size),
      checkpoint_timestamp: Number(t4.checkpoint.checkpoint_timestamp),
      authority_pubkey_hash: t4.checkpoint.authority_pubkey_hash,
    },
    t4.bjj_eddsa_poseidon,
  );
  t4.anchor_hash.value_hex = toHex(recomputed);
  t4.ed25519.message_hex = toHex(recomputed);
  // Re-sign Ed25519 with the same key so check 2 passes.
  const edSk = new Uint8Array(32);
  edSk[0] = 7;
  t4.ed25519.signature_hex = toHex(ed25519.sign(recomputed, edSk));
  const t4Path = path.join(tmp, 't4.json');
  fs.writeFileSync(t4Path, JSON.stringify(t4));
  runVerifier(t4Path, false);
  console.log('PASS  tamper authority_pubkey_hash → reject');

  // 6. Wrong schema version → exit 2
  const t5 = JSON.parse(JSON.stringify(bundle));
  t5.schema = 'olympus-checkpoint-bundle/v999';
  const t5Path = path.join(tmp, 't5.json');
  fs.writeFileSync(t5Path, JSON.stringify(t5));
  runVerifier(t5Path, false);
  console.log('PASS  wrong schema version → reject');

  console.log('\nAll verify.js smoke tests passed.');
}

main().catch((e) => {
  console.error(e.stack || e.message || e);
  process.exit(1);
});
