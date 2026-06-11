/**
 * ⚠️ LEGACY — deprecated 16-chunk raw-byte redaction binding.
 *
 * This implements the OLD chunk-based `redaction_validity` scheme (16 leaves /
 * depth-4 fold, DOMAIN_LEAF=1, DOMAIN_REDACTION=3). Per ADR-0025/0026 the
 * production scheme is now PDF object-level commitment (1024 leaves / depth-10),
 * driven by object ids + the manifest endpoint (`issueRedaction` /
 * `getRedactionManifest` in api.ts) — NOT this module. It is retained ONLY to
 * verify pre-ADR-0025 sealed records.
 *
 * Do not feed object-scheme bundles here: the functions below hard-require a
 * `MAX_LEAVES` (16) entry `reveal_mask` and throw on any other shape, so an
 * object-scheme bundle (1024-wide mask) is rejected rather than silently
 * mis-bound — but new code should call the object-level path directly and
 * never reach this file.
 *
 * Browser-side file→commitment binding for `redaction_validity` audits.
 *
 * Mirrors `src-tauri/src/zk/chunk.rs::chunk_tree_from_bytes` +
 * `src-tauri/src/zk/poseidon.rs::redaction_commitment` byte-for-byte so a
 * remote auditor reading the read-only Tor public_router (where Tauri IPC
 * isn't available) can still bind a dropped file to the verified ZK proof.
 *
 * If you change any constant or step here, you MUST also update
 * `src-tauri/src/zk/chunk.rs::js_conformance_fixture_locked` and the
 * Vitest test `redactionBinding.conformance.test.ts` in the same commit.
 * The Rust fixture-emit test is the authoritative ground truth — pin both
 * sides to its value.
 *
 * Pipeline (exact mirror of the Rust path):
 *   1. chunkInto16(bytes) — split into 16 equal chunks, right-pad final
 *      chunk with NULs, BLAKE3 each, return 16 lowercase hex digests.
 *   2. blake3HexToPoseidonLeaf(hex) —
 *        raw  = hex_decode(hex)                         (32 bytes)
 *        seed = BLAKE3("OLY:FIELD-ELEMENT:V1" || raw)   (32 bytes)
 *        fld  = BigInt(seed_be) mod BN254               (BigInt)
 *        leaf = poseidon2([DOMAIN_LEAF=1, fld])         (BigInt)
 *   3. redactionCommitment(revealedCount, leaves, mask) —
 *        acc = BigInt(revealedCount)
 *        for each (leaf, m):
 *          val = m ? leaf : 0n
 *          acc = domainNode3(acc, val)
 *               = poseidon2([poseidon2([3n, acc]), val])
 *      Compare acc decimal string to publicSignals[2].
 */
import { poseidon2 } from "poseidon-lite";
import { hashBytes } from "./blake3";

/** BN254 scalar field modulus (matches `bn254_modulus()` in olympus-crypto). */
const BN254_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Domain tag for leaves (matches `DOMAIN_LEAF = 1` in olympus-crypto). */
const DOMAIN_LEAF = 1n;

/** Domain tag for the redaction commitment chain (matches Rust `domain_node(3, …)`). */
const DOMAIN_REDACTION = 3n;

/** Hardcoded in `src-tauri/src/zk/witness/redaction.rs` and the circuit. */
const MAX_LEAVES = 16;

/** Domain prefix for blake3→field mapping (matches `FIELD_ELEMENT_DOMAIN`). */
const FIELD_ELEMENT_DOMAIN = new TextEncoder().encode("OLY:FIELD-ELEMENT:V1");

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`hex length must be even, got ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at offset ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

function bytesBeToBigInt(b: Uint8Array): bigint {
  let n = 0n;
  for (const byte of b) {
    n = (n << 8n) | BigInt(byte);
  }
  return n;
}

/**
 * Right-pad-with-NULs split into 16 equal chunks, BLAKE3 each.
 * Mirrors `chunk_into_16` in `src-tauri/src/zk/chunk.rs`.
 *
 * `chunk_size = ceil(n / 16).max(1)`. For inputs shorter than 16 bytes the
 * trailing chunks are entirely NUL — exactly matching the Rust convention,
 * which produces 16 distinct BLAKE3 hashes (one of an all-zero chunk).
 */
async function chunkInto16(bytes: Uint8Array): Promise<string[]> {
  if (bytes.length === 0) {
    throw new Error("input bytes are empty");
  }
  const n = bytes.length;
  // ceilDiv(n, 16).max(1)
  const chunkSize = Math.max(1, Math.ceil(n / MAX_LEAVES));
  const out: string[] = [];
  for (let i = 0; i < MAX_LEAVES; i++) {
    const start = Math.min(i * chunkSize, n);
    const end = Math.min(start + chunkSize, n);
    const buf = new Uint8Array(chunkSize); // zero-filled
    buf.set(bytes.subarray(start, end), 0);
    // hashBytes returns a lowercase hex string (per lib/blake3.ts).
    out.push(await hashBytes(buf));
  }
  return out;
}

/**
 * Lift a 64-char BLAKE3 hex digest to a BN254 Poseidon leaf field element.
 * Mirrors `blake3_hex_to_poseidon_leaf` in `crates/olympus-crypto/src/poseidon.rs`.
 */
async function blake3HexToPoseidonLeaf(hexHash: string): Promise<bigint> {
  if (hexHash.length !== 64) {
    throw new Error(`expected 64-char hex digest, got ${hexHash.length}`);
  }
  const raw = hexToBytes(hexHash.toLowerCase());

  // seed = BLAKE3(FIELD_ELEMENT_DOMAIN || raw); hashBytes is BLAKE3.
  const seedInput = new Uint8Array(FIELD_ELEMENT_DOMAIN.length + raw.length);
  seedInput.set(FIELD_ELEMENT_DOMAIN, 0);
  seedInput.set(raw, FIELD_ELEMENT_DOMAIN.length);
  const seedHex = await hashBytes(seedInput);
  const seedBytes = hexToBytes(seedHex);

  const fld = bytesBeToBigInt(seedBytes) % BN254_MODULUS;
  return poseidon2([DOMAIN_LEAF, fld]);
}

/**
 * `domain_node(3, left, right)` from Rust.
 * = poseidon2(poseidon2(3, left), right).
 */
function domainNode3(left: bigint, right: bigint): bigint {
  const inner = poseidon2([DOMAIN_REDACTION, left]);
  return poseidon2([inner, right]);
}

/**
 * Recompute `redactedCommitment` from raw file bytes + reveal_mask.
 *
 * Returns the decimal string of the BN254 field element, ready for direct
 * `===` comparison with `publicSignals[2]` of a `redaction_validity` bundle.
 *
 * @param bytes      Raw bytes of the dropped redacted file.
 * @param revealMask 16-element array of 0/1 (matches the bundle's `reveal_mask`).
 */
export async function recomputeRedactionCommitment(
  bytes: Uint8Array,
  revealMask: number[],
): Promise<string> {
  if (revealMask.length !== MAX_LEAVES) {
    throw new Error(`reveal_mask must have ${MAX_LEAVES} entries; got ${revealMask.length}`);
  }
  for (let i = 0; i < MAX_LEAVES; i++) {
    if (revealMask[i] !== 0 && revealMask[i] !== 1) {
      throw new Error(`reveal_mask[${i}] = ${revealMask[i]} is not 0 or 1`);
    }
  }

  const chunkHashes = await chunkInto16(bytes);
  const leaves: bigint[] = [];
  for (const h of chunkHashes) {
    leaves.push(await blake3HexToPoseidonLeaf(h));
  }

  let revealedCount = 0n;
  for (const m of revealMask) if (m === 1) revealedCount++;

  let acc = revealedCount;
  for (let i = 0; i < MAX_LEAVES; i++) {
    const val = revealMask[i] === 1 ? leaves[i] : 0n;
    acc = domainNode3(acc, val);
  }
  return acc.toString();
}

/**
 * High-level: returns `true` iff re-deriving the commitment from the file
 * matches the bundle's expected value. Constant-time string comparison
 * (`===` on two equal-length decimal strings) is fine — both values are
 * the same length when equal, and a length difference is itself a fail.
 */
export async function verifyRedactionBindingJs(
  bytes: Uint8Array,
  revealMask: number[],
  expectedCommitmentDec: string,
): Promise<boolean> {
  const computed = await recomputeRedactionCommitment(bytes, revealMask);
  return computed === expectedCommitmentDec.trim();
}
