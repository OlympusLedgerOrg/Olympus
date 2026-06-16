#!/usr/bin/env node
/**
 * Independent (cross-language) differential verifier for the checkpoint-quorum
 * golden vectors (ADR-0033, `OLY:CHECKPOINT:QUORUM:V2`).
 *
 * Re-derives the co-sign message from scratch (BLAKE3 over length-prefixed
 * framing of `(chain_id, epoch, root, threshold, signers)`, then `Fr_le`
 * reduction) and verifies the M-of-N BabyJubJub EdDSA-Poseidon quorum with
 * circomlibjs, then asserts the result matches the Rust-generated expectations
 * in `verifiers/test_vectors/checkpoint_quorum_vectors.json`.
 *
 * This is the byte-for-byte producer/verifier parity check: the vectors are
 * emitted by the Rust producer + authoritative verifier
 * (`cargo run -p olympus-desktop --example gen_checkpoint_quorum_vectors`); this
 * script re-verifies them with a fully independent JS implementation. Any
 * divergence in the message byte layout or the signature scheme fails here.
 *
 * circomlibjs is GPL-3.0 and a test-time devDependency only (see
 * `test_babyjubjub_parity.js` for the licensing note); it is never imported by
 * the shipped verifier (`verifier.js` / `client.js`) nor by any runtime artifact.
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { blake3 } = require('@noble/hashes/blake3.js');
const { buildEddsa } = require('circomlibjs');

const DOMAIN = 'OLY:CHECKPOINT:QUORUM:V2';
const enc = new (require('util').TextEncoder)();

function u32be(n) {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

// Signed 64-bit big-endian — mirrors Rust `i64::to_be_bytes`.
function i64be(n) {
  let v = BigInt.asIntN(64, BigInt(n));
  let u = v < 0n ? (1n << 64n) + v : v;
  const b = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(u & 0xffn);
    u >>= 8n;
  }
  return b;
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

// Length-prefixed string: u32be(byteLen) || utf8(str). Mirrors the Rust
// `h.update(&(s.len() as u32).to_be_bytes()); h.update(s.as_bytes());`.
function lp(str) {
  const b = enc.encode(str);
  return concatBytes(u32be(b.length), b);
}

// Canonical decimal of a field element given as a decimal string. Mirrors the
// Rust `parse_fr -> fr_to_decimal` normalisation (e.g. "007" -> "7").
function canon(dec) {
  return BigInt(dec).toString();
}

// Little-endian byte array -> BigInt. Mirrors `Fr::from_le_bytes_mod_order`
// (the mod-r reduction is then done by circomlibjs `F.e`).
function leToBigInt(bytes) {
  let acc = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) acc = (acc << 8n) | BigInt(bytes[i]);
  return acc;
}

// Build the co-sign message field element for (chain_id, epoch, root, threshold, signers).
function messageField(F, chainId, epoch, root, threshold, signers) {
  // Canonical, deduped, sorted (x,y) — matches Rust BTreeSet<(String, String)>
  // ordering (lexicographic over the canonical decimal strings).
  const seen = new Set();
  const canonical = [];
  for (const s of signers) {
    const x = canon(s.x);
    const y = canon(s.y);
    const id = `${x},${y}`;
    if (!seen.has(id)) {
      seen.add(id);
      canonical.push({ x, y });
    }
  }
  canonical.sort((a, b) =>
    a.x < b.x ? -1 : a.x > b.x ? 1 : a.y < b.y ? -1 : a.y > b.y ? 1 : 0,
  );

  const parts = [
    enc.encode(DOMAIN),
    lp(canon(chainId)),
    i64be(epoch),
    lp(canon(root)),
    u32be(threshold),
    u32be(canonical.length),
  ];
  for (const s of canonical) {
    parts.push(lp(s.x));
    parts.push(lp(s.y));
  }
  const digest = blake3(concatBytes(...parts));
  return { field: F.e(leToBigInt(digest)), canonical };
}

function verifyCase(eddsa, F, c) {
  const { field, canonical } = messageField(F, c.chain_id, c.epoch, c.root, c.threshold, c.signers);

  // (1) Message byte-layout parity — the core cross-impl assertion.
  assert.strictEqual(
    F.toObject(field).toString(),
    c.expected.message,
    `${c.name}: re-derived message diverges from the Rust vector`,
  );

  // (2) M-of-N counting with the same rules as `verify_checkpoint_quorum`:
  //     member-only, dedup by canonical pubkey, BJJ-EdDSA verify, threshold floor.
  const allowed = new Set(canonical.map((s) => `${s.x},${s.y}`));
  const counted = new Set();
  for (const cs of c.cosignatures) {
    // Parse field elements inside try/catch so a malformed cosignature is
    // *skipped*, matching Rust verify_checkpoint_quorum's fail-closed
    // `let (Ok(..), ..) = (parse_fr(..)) else { continue; }` rather than
    // aborting the whole case.
    let id;
    let pub;
    let sig;
    try {
      id = `${canon(cs.x)},${canon(cs.y)}`;
      pub = [F.e(BigInt(cs.x)), F.e(BigInt(cs.y))];
      sig = { R8: [F.e(BigInt(cs.r8x)), F.e(BigInt(cs.r8y))], S: BigInt(cs.s) };
    } catch {
      continue;
    }
    if (!allowed.has(id) || counted.has(id)) continue;
    if (eddsa.verifyPoseidon(field, sig, pub)) counted.add(id);
  }
  const valid = counted.size;
  const total = allowed.size;
  const satisfied = c.threshold >= 1 && valid >= c.threshold;

  assert.strictEqual(valid, c.expected.valid_signatures, `${c.name}: valid_signatures`);
  assert.strictEqual(total, c.expected.total_signers, `${c.name}: total_signers`);
  assert.strictEqual(satisfied, c.expected.satisfied, `${c.name}: satisfied`);
}

async function main() {
  const vectorsPath = path.join(
    __dirname,
    '..',
    'test_vectors',
    'checkpoint_quorum_vectors.json',
  );
  if (!fs.existsSync(vectorsPath)) {
    throw new Error(
      `checkpoint_quorum_vectors.json missing. Regenerate with:\n` +
        `  cargo run -p olympus-desktop --example gen_checkpoint_quorum_vectors`,
    );
  }
  const doc = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));
  assert.strictEqual(doc.domain, DOMAIN, 'domain tag');
  assert.ok(Array.isArray(doc.cases) && doc.cases.length > 0, 'cases must be non-empty');

  const eddsa = await buildEddsa();
  const F = eddsa.F;

  for (const c of doc.cases) {
    verifyCase(eddsa, F, c);
    console.log(`PASS  ${c.name}`);
  }
  console.log(
    `\nAll ${doc.cases.length} checkpoint-quorum (V2) vectors verified ` +
      `(JS re-derivation ↔ Rust producer, byte-for-byte).`,
  );
}

main().catch((e) => {
  console.error(e.stack || e.message || e);
  process.exit(1);
});
