/**
 * Olympus Cryptographic Primitives — frontend library
 *
 * Provides all cryptographic operations required by the public verification
 * dashboard.  This module is the single source of truth for:
 *
 *  - BLAKE3 hashing (WASM-backed, browser-safe)
 *  - Canonical JSON encoding (JCS / RFC 8785)
 *  - Client-side Sparse Merkle Tree proof verification
 *
 * All hashing uses domain-separated BLAKE3 prefixes that match the server
 * implementation exactly:
 *   - Leaf nodes: OLY:LEAF:V1
 *   - Internal nodes: OLY:NODE:V1
 *
 * Required peer dependency:
 *   npm install blake3-wasm@^2.1.5
 *
 * The module is intentionally framework-agnostic so it can be consumed by any
 * JS/TS host (React, Vue, plain scripts, Node test runners).
 */

// ─── Exported types ───────────────────────────────────────────────────────────

/** Any value representable in a canonical JSON document. */
export type CanonicalJsonValue =
  | null
  | boolean
  | number
  | string
  | CanonicalJsonValue[]
  | { [key: string]: CanonicalJsonValue };

/**
 * Merkle inclusion proof as returned by the Olympus API.
 * Structure matches the JS reference verifier (verifiers/javascript/verifier.js).
 */
export interface OlympusMerkleProof {
  /** Hex-encoded BLAKE3 leaf hash (the content_hash value). */
  leafHash: string;
  /** Ordered sibling hashes required to reconstruct the root. */
  siblings: Array<{ hash: string; position: "left" | "right" }>;
  /** Expected Merkle root hex string. */
  rootHash: string;
}

export interface HashVerificationResponse {
  proof_id: string;
  record_id: string;
  shard_id: string;
  content_hash: string;
  merkle_root: string;
  merkle_proof: OlympusMerkleProof | null;
  merkle_proof_valid: boolean;
  ledger_entry_hash: string;
  timestamp: string;
  batch_id?: string;
  poseidon_root?: string;
}

export interface ProofVerificationRequest {
  proof_id?: string;
  content_hash: string;
  merkle_root: string;
  merkle_proof: OlympusMerkleProof;
}

export interface ProofVerificationResponse {
  proof_id?: string;
  content_hash: string;
  merkle_root: string;
  content_hash_matches_proof: boolean;
  merkle_proof_valid: boolean;
  known_to_server: boolean;
  poseidon_root?: string;
}

// ─── WASM BLAKE3 ──────────────────────────────────────────────────────────────

// Vite resolves blake3-wasm to the browser entry via the package.json "browser"
// field; this deep import addresses the `dist/wasm/web` build that ships an
// async `init` factory for proper browser initialisation.
import init, {
  hash as _wasmHash,
  create_hasher as _createHasher,
} from "blake3-wasm/dist/wasm/web/blake3_js";
import blake3WasmUrl from "blake3-wasm/dist/wasm/web/blake3_js_bg.wasm?url";

let _initPromise: ReturnType<typeof init> | null = null;

function _ensureBlake3(): ReturnType<typeof init> {
  if (!_initPromise) {
    _initPromise = init(blake3WasmUrl);
  }
  return _initPromise;
}

/**
 * Hash a `Uint8Array` with BLAKE3 and return the 64-char lowercase hex digest.
 */
export async function blake3Hex(data: Uint8Array): Promise<string> {
  await _ensureBlake3();
  const out = new Uint8Array(32);
  _wasmHash(data, out);
  return _toHex(out);
}

/**
 * Hash a `File` in 4 MiB chunks with progress reporting.
 * Returns the 64-char BLAKE3 hex digest.
 * Bytes never leave the browser.
 */
export async function hashFileBLAKE3(
  file: File,
  onProgress?: (pct: number) => void,
): Promise<string> {
  await _ensureBlake3();

  const CHUNK = 4 * 1024 * 1024;
  const total = file.size;

  if (total === 0) {
    const out = new Uint8Array(32);
    _wasmHash(new Uint8Array(0), out);
    onProgress?.(100);
    return _toHex(out);
  }

  const hasher = _createHasher();
  let offset = 0;

  while (offset < total) {
    const buf = await file.slice(offset, offset + CHUNK).arrayBuffer();
    hasher.update(new Uint8Array(buf));
    offset += buf.byteLength;
    onProgress?.(Math.round((offset / total) * 100));
  }

  const out = new Uint8Array(32);
  hasher.digest(out);
  hasher.free();

  return _toHex(out);
}

function _toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function _fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

// ─── Canonical JSON ───────────────────────────────────────────────────────────

/**
 * Encode a value as canonical JSON (JCS / RFC 8785).
 * Keys are sorted lexicographically; strings are NFC-normalised; no whitespace.
 */
export function canonicalJsonEncode(value: CanonicalJsonValue): string {
  return _encodeValue(value);
}

function _encodeValue(value: CanonicalJsonValue): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!isFinite(value)) throw new Error("Non-finite number in canonical JSON");
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value.normalize("NFC"));
  }
  if (Array.isArray(value)) {
    return "[" + value.map(_encodeValue).join(",") + "]";
  }
  const sortedKeys = Object.keys(value).sort();
  const pairs = sortedKeys.map(
    (k) =>
      `${JSON.stringify(k.normalize("NFC"))}:${_encodeValue((value as Record<string, CanonicalJsonValue>)[k])}`,
  );
  return "{" + pairs.join(",") + "}";
}

// ─── Client-side Merkle proof verification ────────────────────────────────────

const NODE_PREFIX = new TextEncoder().encode("OLY:NODE:V1");
const SEP = new TextEncoder().encode("|");

function _concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.byteLength;
  }
  return out;
}

/**
 * Compute the domain-separated BLAKE3 parent hash of two child hashes.
 * Mirrors `merkleParentHash()` in verifiers/javascript/verifier.js:
 *   BLAKE3(OLY:NODE:V1 || "|" || left || "|" || right)
 */
async function _parentHash(
  left: Uint8Array,
  right: Uint8Array,
): Promise<Uint8Array> {
  await _ensureBlake3();
  const data = _concat(NODE_PREFIX, SEP, left, SEP, right);
  const out = new Uint8Array(32);
  _wasmHash(data, out);
  return out;
}

/**
 * Re-verify a Merkle inclusion proof entirely in the browser.
 *
 * Starts from `proof.leafHash` (the leaf value already stored in the tree,
 * as returned by the Olympus API) and walks up the sibling path using
 * OLY:NODE:V1 domain-separated BLAKE3 parent hashing.  This mirrors the
 * reference implementation in verifiers/javascript/verifier.js.
 *
 * Returns `true` if the computed root matches `proof.rootHash`, `false`
 * otherwise.
 */
export async function verifyMerkleProof(
  proof: OlympusMerkleProof,
): Promise<boolean> {
  try {
    const leafBytes = _fromHex(proof.leafHash);
    // proof.leafHash is the leaf value as stored in the Merkle tree, returned
    // verbatim by the API.  We start from it directly and walk up the sibling
    // path — no additional prefix hashing is applied here.
    let current = leafBytes;

    for (const sibling of proof.siblings) {
      const sibBytes = _fromHex(sibling.hash);
      if (sibling.position === "left") {
        current = await _parentHash(sibBytes, current);
      } else {
        current = await _parentHash(current, sibBytes);
      }
    }

    return _toHex(current) === proof.rootHash.toLowerCase();
  } catch {
    return false;
  }
}
