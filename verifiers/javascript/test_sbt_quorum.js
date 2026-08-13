#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0
/**
 * Independent (cross-language) differential verifier for the SBT-credential
 * quorum golden vectors (audit R3-01 / L6, `OLY:SBT:QUORUM:V2`).
 *
 * `src-tauri/src/quorum/mod.rs` promises "anyone holding the N pubkeys can
 * re-verify the quorum offline". The sibling `test_checkpoint_quorum.js` gives
 * that for the *checkpoint* quorum; this closes the same gap for the
 * security-load-bearing *credential* quorum, whose satisfaction drives scope
 * elevation.
 *
 * It re-derives the FULL co-sign message from scratch (BLAKE3 over the
 * length-prefixed framing of `(commit_id_hex, threshold, signers)`, then an
 * `Fr_le` reduction) and verifies the M-of-N BabyJubJub EdDSA-Poseidon quorum
 * with local circom-compatible primitives, then asserts the result matches the
 * Rust-generated expectations in
 * `verifiers/test_vectors/sbt_quorum_vectors.json`. Any divergence in the
 * message byte layout or the signature scheme fails here.
 *
 * The vectors are emitted by the Rust producer + authoritative verifier
 * (`cargo run -p olympus-desktop --example gen_sbt_quorum_vectors`); this script
 * re-verifies them with a fully independent JS implementation.
 *
 * The verifier package deliberately avoids circomlibjs/ffjavascript here; see
 * `test_babyjubjub_parity.js` for the compatibility note.
 */

"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { blake3 } = require("@noble/hashes/blake3.js");
const { buildEddsa } = require("./circom_compat.js");

const DOMAIN = "OLY:SBT:QUORUM:V2";
const CHECKPOINT_DOMAIN = "OLY:CHECKPOINT:QUORUM:V2";
const enc = new (require("util").TextEncoder)();

function u32be(n) {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
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

// Length-prefixed byte string: u32be(byteLen) || utf8(str). Mirrors the Rust
// `h.update(&(s.len() as u32).to_be_bytes()); h.update(s.as_bytes());`. Used for
// both the commit_id HEX STRING (whose length is 64, not 32) and each signer
// coordinate decimal.
function lp(str) {
  const b = enc.encode(str);
  return concatBytes(u32be(b.length), b);
}

// BN254 scalar field modulus r. Decimals >= r (or negative) are non-canonical;
// Rust `parse_fr` (src-tauri/src/zk/proof.rs) REJECTS them outright rather than
// silently reducing mod r — by design, so an overlarge decimal can't masquerade
// as its reduced representative. The differential verifier must reject too, or a
// >= r input would diverge between the two implementations.
const BN254_SCALAR_R =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Canonical decimal of an in-field element given as a decimal string. Mirrors
// Rust `parse_fr -> fr_to_decimal`: normalises formatting ("007" -> "7") and
// rejects anything outside [0, r) — rejecting, NOT reducing, exactly like
// parse_fr. (Inside the cosignature loop the throw is caught and the entry
// skipped, matching Rust's fail-closed `parse_fr(..) else { continue }`.)
function canon(dec) {
  const v = BigInt(dec);
  if (v < 0n || v >= BN254_SCALAR_R) {
    throw new Error(`field element ${dec} is not in [0, r) (non-canonical)`);
  }
  return v.toString();
}

// Little-endian byte array -> BigInt. Mirrors `Fr::from_le_bytes_mod_order`
// (the mod-r reduction is then done by the local field wrapper `F.e`).
function leToBigInt(bytes) {
  let acc = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) acc = (acc << 8n) | BigInt(bytes[i]);
  return acc;
}

// Canonical, deduped, sorted (x,y) — matches Rust BTreeSet<(String, String)>
// ordering (lexicographic over the canonical decimal strings).
function canonicalSigners(signers) {
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
  canonical.sort((a, b) => (a.x < b.x ? -1 : a.x > b.x ? 1 : a.y < b.y ? -1 : a.y > b.y ? 1 : 0));
  return canonical;
}

// Build the co-sign message field element for (commit_id_hex, threshold, signers).
function messageField(F, commitIdHex, threshold, signers) {
  const canonical = canonicalSigners(signers);
  const parts = [
    enc.encode(DOMAIN),
    lp(commitIdHex), // the 64-char hex STRING, not the 32 raw bytes
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

// Verify one cosignature over `field`; returns true iff the BJJ-EdDSA signature
// authenticates. A malformed (non-canonical) field element throws inside canon
// and is treated as non-verifying, matching Rust's fail-closed skip.
function cosigVerifies(eddsa, F, field, cs) {
  try {
    canon(cs.x);
    canon(cs.y);
    const pub = [F.e(BigInt(cs.x)), F.e(BigInt(cs.y))];
    const sig = { R8: [F.e(BigInt(cs.r8x)), F.e(BigInt(cs.r8y))], S: BigInt(cs.s) };
    return eddsa.verifyPoseidon(field, sig, pub);
  } catch {
    return false;
  }
}

function cosigIsMember(allowed, cs) {
  try {
    return allowed.has(`${canon(cs.x)},${canon(cs.y)}`);
  } catch {
    return false;
  }
}

function verifyCase(eddsa, F, c) {
  const { field, canonical } = messageField(F, c.commit_id, c.threshold, c.signers);

  // (1) Message byte-layout parity — the core cross-impl assertion.
  assert.strictEqual(
    F.toObject(field).toString(),
    c.expected.message,
    `${c.name}: re-derived message diverges from the Rust vector`,
  );

  // (2) M-of-N counting with the same rules as `verify_generic_quorum`:
  //     member-only, dedup by canonical pubkey, BJJ-EdDSA verify, threshold floor.
  const allowed = new Set(canonical.map((s) => `${s.x},${s.y}`));
  const counted = new Set();
  for (const cs of c.cosignatures) {
    let id;
    try {
      id = `${canon(cs.x)},${canon(cs.y)}`;
    } catch {
      continue;
    }
    if (!allowed.has(id) || counted.has(id)) continue;
    if (cosigVerifies(eddsa, F, field, cs)) counted.add(id);
  }
  const valid = counted.size;
  const total = allowed.size;
  // Mirrors quorum::verify_generic_quorum: no >=2 floor (that policy lives in
  // the desktop acceptance path, not the core counting loop).
  const satisfied = c.threshold >= 1 && valid >= c.threshold;

  assert.strictEqual(valid, c.expected.valid_signatures, `${c.name}: valid_signatures`);
  assert.strictEqual(total, c.expected.total_signers, `${c.name}: total_signers`);
  assert.strictEqual(satisfied, c.expected.satisfied, `${c.name}: satisfied`);
}

// Per-negative *reason* assertions: each rejection is checked for its specific
// mechanism (equation vs. membership vs. distinctness vs. domain), not a bare
// "did not verify".
function assertNegativeReasons(eddsa, F, cases) {
  const byName = new Map(cases.map((c) => [c.name, c]));
  const get = (name) => {
    const c = byName.get(name);
    assert.ok(c, `missing case ${name}`);
    return c;
  };
  const ctx = (c) => {
    const { field, canonical } = messageField(F, c.commit_id, c.threshold, c.signers);
    return { field, allowed: new Set(canonical.map((s) => `${s.x},${s.y}`)) };
  };

  // R3-01 rebinding (threshold/signer-set/commit_id) — signer stays a pinned
  // member, so the failure must be the equation over the rebound message.
  for (const name of [
    "threshold_downgrade_breaks_quorum",
    "signer_set_tampered_rejected",
    "signer_set_dropped_rejected",
    "wrong_commit_id_rejected",
  ]) {
    const c = get(name);
    const { field, allowed } = ctx(c);
    for (const cs of c.cosignatures) {
      assert.ok(cosigIsMember(allowed, cs), `${name}: signer must remain a pinned member`);
      assert.strictEqual(
        cosigVerifies(eddsa, F, field, cs),
        false,
        `${name}: a rebound message must fail the verification equation`,
      );
    }
  }

  // Tampered S — still a member, fails the equation.
  {
    const c = get("tampered_signature_rejected");
    const { field, allowed } = ctx(c);
    const cs = c.cosignatures[0];
    assert.ok(cosigIsMember(allowed, cs), "tampered_signature_rejected: signer is pinned");
    assert.strictEqual(
      cosigVerifies(eddsa, F, field, cs),
      false,
      "tampered_signature_rejected: mutated S must not verify",
    );
  }

  // Non-member — the outsider's signature is genuinely valid over the message,
  // dropped only by the membership filter.
  {
    const c = get("non_member_ignored");
    const { field, allowed } = ctx(c);
    const outsider = c.cosignatures[1];
    assert.strictEqual(
      cosigVerifies(eddsa, F, field, outsider),
      true,
      "non_member_ignored: the outsider signature is valid over the message",
    );
    assert.strictEqual(
      cosigIsMember(allowed, outsider),
      false,
      "non_member_ignored: the outsider is not a pinned member",
    );
  }

  // Duplicate — both signatures individually valid members; collapse to one.
  {
    const c = get("duplicate_signer_counts_once");
    const { field, allowed } = ctx(c);
    for (const cs of c.cosignatures) {
      assert.ok(cosigIsMember(allowed, cs), "duplicate: signer is pinned");
      assert.strictEqual(
        cosigVerifies(eddsa, F, field, cs),
        true,
        "duplicate: each signature is individually valid",
      );
    }
    assert.strictEqual(c.expected.valid_signatures, 1, "duplicate: distinctness collapses to one");
  }

  // Cross-domain replay — the co-signer IS a pinned member, but a
  // checkpoint-domain signature yields a different message, so it fails the
  // equation. Prove the disjointness directly: the same signature verifies
  // under the checkpoint message the generator built it for, and NOT under the
  // SBT message.
  {
    const c = get("cross_domain_checkpoint_sig_rejected");
    const { field: sbtField, allowed } = ctx(c);
    const cs = c.cosignatures[0];
    assert.ok(
      cosigIsMember(allowed, cs),
      "cross_domain: the checkpoint co-signer is a pinned SBT member",
    );
    assert.strictEqual(
      cosigVerifies(eddsa, F, sbtField, cs),
      false,
      "cross_domain: a checkpoint-domain signature must fail the SBT equation",
    );
    assert.notStrictEqual(
      DOMAIN,
      CHECKPOINT_DOMAIN,
      "cross_domain: the two quorum domains must be distinct",
    );
  }
}

async function main() {
  const vectorsPath = path.join(__dirname, "..", "test_vectors", "sbt_quorum_vectors.json");
  if (!fs.existsSync(vectorsPath)) {
    throw new Error(
      `sbt_quorum_vectors.json missing. Regenerate with:\n` +
        `  cargo run -p olympus-desktop --example gen_sbt_quorum_vectors`,
    );
  }
  const doc = JSON.parse(fs.readFileSync(vectorsPath, "utf8"));
  assert.strictEqual(doc.domain, DOMAIN, "domain tag");
  assert.ok(Array.isArray(doc.cases) && doc.cases.length > 0, "cases must be non-empty");

  const eddsa = await buildEddsa();
  const F = eddsa.F;

  for (const c of doc.cases) {
    verifyCase(eddsa, F, c);
    console.log(`PASS  ${c.name}`);
  }
  assertNegativeReasons(eddsa, F, doc.cases);
  console.log(`PASS  negative-reason assertions`);
  console.log(
    `\nAll ${doc.cases.length} SBT-quorum (V2) vectors verified ` +
      `(JS re-derivation ↔ Rust producer, byte-for-byte).`,
  );
}

main().catch((e) => {
  console.error(e.stack || e.message || e);
  process.exit(1);
});
