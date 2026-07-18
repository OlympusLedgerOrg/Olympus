#!/usr/bin/env node
/**
 * Independent JavaScript verifier for Olympus checkpoint bundles.
 *
 * Implements the command documented in docs/court-evidence.md §3:
 *
 *   node verify.js verify-checkpoint --bundle <bundle.json>
 *
 * Bundle schema: docs/checkpoint-bundle-schema.md (v2).
 *
 * Runs three independent JS-side checks, then emits the exact command for the
 * separate Rust Groth16 check. Exit 0 covers only the checks performed here.
 *
 *   1. Anchor digest reconstruction (BLAKE3 over the domain-separated
 *      OLY:CHECKPOINT_ANCHOR:V2 field tuple).
 *   2. Ed25519 verify over `anchor_hash` bytes (RFC 8032 via @noble/curves).
 *   3. BJJ-EdDSA-Poseidon verify over the complete scoped v2 statement (local iden3-compatible
 *      primitives, byte-compatible with the Rust babyjubjub-permissive
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

"use strict";

const fs = require("fs");
const path = require("path");
const { blake3 } = require("@noble/hashes/blake3.js");
const { ed25519 } = require("@noble/curves/ed25519.js");
const { buildEddsa, buildPoseidon, bjjInPrimeSubgroup } = require("./circom_compat.js");

// ── small helpers ─────────────────────────────────────────────────────────────

function die(code, msg) {
  console.error(msg);
  process.exit(code);
}

function fromHex(hex) {
  if (typeof hex !== "string" || !/^[0-9a-fA-F]*$/.test(hex)) {
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
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
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

function u32ToBE4(n) {
  if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) {
    throw new Error(`value is not a u32: ${n}`);
  }
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function lp(bytes) {
  return concatBytes(u32ToBE4(bytes.length), bytes);
}

function littleEndianBigInt(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}

const BN254_SCALAR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BABYJUBJUB_SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const I64_MAX = 9223372036854775807n;
const FORMAT_VERSION = 2;
const STATEMENT_DOMAIN = new TextEncoder().encode("OLY:CHECKPOINT:STATEMENT:V2");

function requireObject(value, name) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function requireCanonicalUnsignedDecimal(value, name, maxInclusive) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxInclusive.toString().length ||
    !/^(0|[1-9][0-9]*)$/.test(value)
  ) {
    throw new Error(`${name} is not a canonical unsigned decimal`);
  }
  const parsed = BigInt(value);
  if (parsed > maxInclusive) {
    throw new Error(`${name} is out of range`);
  }
  return parsed;
}

function requireCanonicalFr(value, name) {
  return requireCanonicalUnsignedDecimal(value, name, BN254_SCALAR_MODULUS - 1n);
}

function requireLowerHex(value, name, length) {
  if (typeof value !== "string" || value.length !== length || !/^[0-9a-f]+$/.test(value)) {
    throw new Error(`${name} must be exactly ${length} lowercase hexadecimal characters`);
  }
}

function validateBundleEncoding(bundle) {
  requireObject(bundle, "bundle");
  const checkpoint = requireObject(bundle.checkpoint, "bundle.checkpoint");
  const bjj = requireObject(bundle.bjj_eddsa_poseidon, "bundle.bjj_eddsa_poseidon");
  const pubkey = requireObject(bjj.pubkey, "bundle.bjj_eddsa_poseidon.pubkey");
  const signature = requireObject(bjj.signature, "bundle.bjj_eddsa_poseidon.signature");
  const ed25519Block = requireObject(bundle.ed25519, "bundle.ed25519");
  const anchor = requireObject(bundle.anchor_hash, "bundle.anchor_hash");

  if (
    checkpoint.format_version !== "2" ||
    checkpoint.checkpoint_scope !== "shard" ||
    typeof checkpoint.shard_id !== "string" ||
    !/^[A-Za-z0-9:._-]{1,128}$/.test(checkpoint.shard_id)
  ) {
    throw new Error("bundle checkpoint is not a valid explicitly shard-scoped format-v2 statement");
  }
  requireCanonicalFr(checkpoint.ledger_root, "bundle.checkpoint.ledger_root");
  requireCanonicalUnsignedDecimal(checkpoint.tree_size, "bundle.checkpoint.tree_size", I64_MAX);
  requireCanonicalUnsignedDecimal(
    checkpoint.checkpoint_timestamp,
    "bundle.checkpoint.checkpoint_timestamp",
    I64_MAX,
  );
  requireCanonicalFr(checkpoint.authority_pubkey_hash, "bundle.checkpoint.authority_pubkey_hash");

  if (bjj.scheme !== "BabyJubJub-EdDSA-Poseidon") {
    throw new Error(`unsupported BJJ signature scheme: ${JSON.stringify(bjj.scheme)}`);
  }
  requireCanonicalFr(pubkey.x, "bundle.bjj_eddsa_poseidon.pubkey.x");
  requireCanonicalFr(pubkey.y, "bundle.bjj_eddsa_poseidon.pubkey.y");
  requireCanonicalFr(signature.r8x, "bundle.bjj_eddsa_poseidon.signature.r8x");
  requireCanonicalFr(signature.r8y, "bundle.bjj_eddsa_poseidon.signature.r8y");
  requireCanonicalUnsignedDecimal(
    signature.s,
    "bundle.bjj_eddsa_poseidon.signature.s",
    BABYJUBJUB_SUBGROUP_ORDER - 1n,
  );
  requireCanonicalFr(bjj.message, "bundle.bjj_eddsa_poseidon.message");

  if (ed25519Block.scheme !== "Ed25519 (RFC 8032)") {
    throw new Error(`unsupported Ed25519 scheme: ${JSON.stringify(ed25519Block.scheme)}`);
  }
  requireLowerHex(ed25519Block.pubkey_hex, "bundle.ed25519.pubkey_hex", 64);
  requireLowerHex(ed25519Block.signature_hex, "bundle.ed25519.signature_hex", 128);
  requireLowerHex(ed25519Block.message_hex, "bundle.ed25519.message_hex", 64);
  requireLowerHex(anchor.value_hex, "bundle.anchor_hash.value_hex", 64);
}

function checkpointSigningMessage(checkpoint) {
  const enc = new TextEncoder();
  const digest = blake3(
    concatBytes(
      STATEMENT_DOMAIN,
      new Uint8Array([FORMAT_VERSION]),
      lp(enc.encode(checkpoint.checkpoint_scope)),
      lp(enc.encode(checkpoint.shard_id)),
      lp(enc.encode(checkpoint.ledger_root)),
      i64ToBE8(checkpoint.tree_size),
      i64ToBE8(checkpoint.checkpoint_timestamp),
      lp(enc.encode(checkpoint.authority_pubkey_hash)),
    ),
  );
  return littleEndianBigInt(digest) % BN254_SCALAR_MODULUS;
}

// ── check #1: anchor digest reconstruction ────────────────────────────────────

const ANCHOR_DOMAIN = new TextEncoder().encode("OLY:CHECKPOINT_ANCHOR:V2");

function reconstructAnchorHash(checkpoint, bjjSig) {
  // Bytes must match src-tauri/src/anchoring/mod.rs::checkpoint_anchor_hash_v2.
  // Empty Optional<&str> serialises as an empty length-prefixed value; tree_size
  // and checkpoint_timestamp are i64 big-endian; all field elements are
  // UTF-8 of their decimal Fr representation.
  const enc = new TextEncoder();
  const parts = [
    ANCHOR_DOMAIN,
    new Uint8Array([FORMAT_VERSION]),
    lp(enc.encode(checkpoint.checkpoint_scope)),
    lp(enc.encode(checkpoint.shard_id)),
    lp(enc.encode(checkpoint.ledger_root)),
    i64ToBE8(checkpoint.tree_size),
    i64ToBE8(checkpoint.checkpoint_timestamp),
    lp(enc.encode(checkpoint.authority_pubkey_hash)),
    lp(enc.encode(bjjSig.signature.r8x)),
    lp(enc.encode(bjjSig.signature.r8y)),
    lp(enc.encode(bjjSig.signature.s)),
  ];
  return blake3(concatBytes(...parts));
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
  return ok ? { ok: true } : { ok: false, detail: "RFC 8032 verify returned false" };
}

// ── check #3: BJJ-EdDSA-Poseidon ──────────────────────────────────────────────

/** Normalize a decimal string into the BN254 field wrapper used by the verifier. */
function fieldFromString(F, decimal) {
  return F.e(BigInt(decimal));
}

async function verifyBjjEdDSAPoseidon(block, checkpoint) {
  const expectedMessage = checkpointSigningMessage(checkpoint).toString();
  if (block.message !== expectedMessage) {
    return {
      ok: false,
      detail: `bundle.bjj_eddsa_poseidon.message (${block.message}) does not match the reconstructed v2 checkpoint statement (${expectedMessage})`,
    };
  }
  const eddsa = await buildEddsa();
  const F = eddsa.F;

  // A = (Ax, Ay) on Baby Jubjub. verifyPoseidon checks curve membership and
  // the iden3 EdDSA equation.
  const A = [fieldFromString(F, block.pubkey.x), fieldFromString(F, block.pubkey.y)];
  const sig = {
    R8: [fieldFromString(F, block.signature.r8x), fieldFromString(F, block.signature.r8y)],
    S: BigInt(block.signature.s),
  };
  if (!bjjInPrimeSubgroup(A)) {
    return { ok: false, detail: "BJJ public key is not in the prime-order subgroup" };
  }
  if (!bjjInPrimeSubgroup(sig.R8)) {
    return { ok: false, detail: "BJJ signature R8 is not in the prime-order subgroup" };
  }
  const msg = fieldFromString(F, block.message);

  const ok = eddsa.verifyPoseidon(msg, sig, A);
  return ok ? { ok: true } : { ok: false, detail: "8·S·B != 8·R + 8·Poseidon(R,A,M)·A" };
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
  if (argv[0] !== "verify-checkpoint") {
    die(
      2,
      `usage: node verify.js verify-checkpoint --bundle <bundle.json>\n` +
        `unknown subcommand: ${argv[0] || "(none)"}`,
    );
  }
  let bundlePath = null;
  for (let i = 1; i < argv.length; i++) {
    if (argv[i] === "--bundle") {
      bundlePath = argv[++i];
    } else {
      die(2, `unknown argument: ${argv[i]}`);
    }
  }
  if (!bundlePath) die(2, "missing required --bundle <path>");
  return { bundlePath };
}

async function main() {
  const { bundlePath } = parseArgs(process.argv.slice(2));
  let bundle;
  try {
    bundle = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
  } catch (e) {
    die(2, `failed to read/parse bundle ${bundlePath}: ${e.message}`);
  }

  // Schema gate — refuse mixed versions.
  if (bundle.schema !== "olympus-checkpoint-bundle/v2") {
    die(2, `unsupported bundle schema: ${bundle.schema}`);
  }
  if (
    bundle.anchor_hash?.algorithm !== "BLAKE3" ||
    bundle.anchor_hash?.domain !== "OLY:CHECKPOINT_ANCHOR:V2"
  ) {
    die(2, "bundle anchor hash algorithm/domain is not the pinned v2 scheme");
  }
  try {
    validateBundleEncoding(bundle);
  } catch (e) {
    die(2, `malformed bundle encoding: ${e.message}`);
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
  console.log(
    `OK   [3a/4 authority hash] Poseidon(Ax,Ay) matches checkpoint.authority_pubkey_hash`,
  );

  // ── Check 3b: BJJ-EdDSA-Poseidon verify ──────────────────────────────────
  const bjj = await verifyBjjEdDSAPoseidon(bundle.bjj_eddsa_poseidon, bundle.checkpoint);
  if (!bjj.ok) {
    console.error(`FAIL [3b/4 BJJ-EdDSA-Poseidon]: ${bjj.detail}`);
    process.exit(1);
  }
  console.log(`OK   [3b/4 BJJ-EdDSA]      scoped checkpoint statement accepted`);

  // ── Check 4: print the Rust groth16 invocation ───────────────────────────
  // Deliberately delegated to the independent Rust verifier crate to
  // avoid pulling snarkjs at runtime. Writing the snapshot files lets
  // the operator run the cargo command verbatim.
  const tmpDir = fs.mkdtempSync(path.join(require("os").tmpdir(), "olympus-bundle-"));
  const proofPath = path.join(tmpDir, "proof.json");
  const signalsPath = path.join(tmpDir, "public.json");
  fs.writeFileSync(proofPath, JSON.stringify(bundle.groth16.proof));
  fs.writeFileSync(signalsPath, JSON.stringify(bundle.groth16.public_signals));

  // Bundle v2 is pinned to the document-existence circuit and vkey.
  const expectedCircuit = "document_existence";
  const expectedVkeyRef = "proofs/keys/verification_keys/document_existence_vkey.json";
  if (bundle.groth16.circuit !== expectedCircuit) {
    die(2, `unsupported bundle.groth16.circuit: ${JSON.stringify(bundle.groth16.circuit)}`);
  }
  if (bundle.groth16.vkey_ref !== expectedVkeyRef) {
    die(2, `unsupported bundle.groth16.vkey_ref: ${JSON.stringify(bundle.groth16.vkey_ref)}`);
  }

  // The guidance below is a POSIX-shell command. Quote every argument so
  // bundle data and temporary paths cannot alter its structure.
  function shellEscape(arg) {
    return "'" + arg.replace(/'/g, "'\\''") + "'";
  }

  console.log(`OK   [4/4 Groth16]         pending — run the independent Rust verifier:`);
  console.log("");
  console.log(`     ${shellEscape("cd")} ${shellEscape("verifiers/rust")}`);
  console.log(
    `     ${["cargo", "run", "--release", "--", "verify"].map(shellEscape).join(" ")} \\`,
  );
  console.log(`         ${shellEscape("--circuit")} ${shellEscape(expectedCircuit)} \\`);
  console.log(`         ${shellEscape("--vkey")} ${shellEscape(`../../${expectedVkeyRef}`)} \\`);
  console.log(`         ${shellEscape("--proof")} ${shellEscape(proofPath)} \\`);
  console.log(`         ${shellEscape("--public-signals")} ${shellEscape(signalsPath)}`);
  console.log("");
  console.log(`All JS-side checks passed. Run the Groth16 step above for the fourth proof.`);
  process.exit(0);
}

main().catch((e) => {
  console.error(`ERROR: ${e.stack || e.message || e}`);
  process.exit(2);
});
