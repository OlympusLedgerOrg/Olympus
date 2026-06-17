/**
 * ADR-0030 **V3 signed-Merkle redaction bundle** — in-app offline recipient verifier.
 *
 * Browser-pure port of the authoritative JavaScript reference
 * `verifiers/javascript/test_redaction.js` (`verifyV3` + helpers), which is in
 * turn a port of the canonical Rust `olympus_crypto::redaction` encoders the
 * producer uses. This module lets the in-app auditor (and the read-only Tor
 * public_router web auditor, where Tauri IPC isn't available) verify a delivered
 * redacted artifact against a V3 bundle + the issuer's Ed25519 pubkey, with NO
 * server round-trip:
 *
 *   - structural checks (N == len, 2 <= N <= 2^20, strictly-ascending-unique
 *     u32 ids, ooxml-part dense 0..N-1 + label per entry),
 *   - per-segment optional-field + canonical-form REJECTS (NO `% l` / `% r`
 *     reduction — hard reject any out-of-range leaf_hex / blinding_decimal /
 *     recipient_id / original_root),
 *   - per-format revealed-leaf reconstruction + the variable-depth fold
 *     (pad Fr(0) to 2^ceil(log2 N); domain_node(1, l, r)) == original_root,
 *   - recompute table_hash + the signing payload, verify the Ed25519 issuer
 *     signature, recompute + check the nullifier.
 *
 * The verifier needs ONLY poseidon / pedersen / blake3 / ed25519 + the issuer
 * pubkey — it does NOT need the server blind_secret or content_hash (revealed
 * segments carry their own `blinding_decimal`; blind derivation is producer-only).
 *
 * If you change ANY constant or step here, you MUST also update the canonical
 * Rust encoders, the JS reference `verifiers/javascript/test_redaction.js`, and
 * the Vitest `redactionBinding.conformance.test.ts` in the same commit. Drift
 * between the desktop, web, and reference auditors would silently invalidate
 * every redaction audit.
 */
import { blake3 } from "@noble/hashes/blake3.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { poseidon2 } from "poseidon-lite";

import { BJJ_L, bytesBEToBigInt, pedersenCommit } from "./babyJubjub";

/** Re-exported from babyJubjub.ts for parity with the JS reference helpers. */
export { bytesBEToBigInt };

// ── Domain tags (mirror olympus_crypto::redaction) ───────────────────────────
const OBJ_DOMAIN = "OLY:REDACTION:OBJ:V1";
const BLIND_PREFIX = "OLY:REDACTION:BLIND:V1";
const BUNDLE_V3_PREFIX = "OLY:REDACTION_BUNDLE:V3";
const TABLE_V3_PREFIX = "OLY:REDACTION:TABLE:V3";
const NULLIFIER_V1_PREFIX = "OLY:REDACTION:NULLIFIER:V1";

/** Re-export so the conformance test can pin the tags against the vectors. */
export const DOMAIN_TAGS = {
  obj: OBJ_DOMAIN,
  blind: BLIND_PREFIX,
  bundle: BUNDLE_V3_PREFIX,
  table: TABLE_V3_PREFIX,
  nullifier: NULLIFIER_V1_PREFIX,
} as const;

// Baby Jubjub prime-order subgroup order `l` (blinding scalars live in [0, l)).
// Re-exported from babyJubjub.ts; aliased here for parity with the JS reference.
export { BJJ_L };
// BN254 scalar field modulus `r` (leaf/recipient field elements live in [0, r)).
export const BN254_R =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const MAX_REDACTION_SEGMENTS = 1n << 20n;
const FORMAT_TAGS = new Set([
  "pdf-object",
  "pdf-xref-stream",
  "text-line",
  "ooxml-part",
]);
// pdf-xref-stream trim charset (ADR-0030 §3): SP, TAB, CR, LF, FF, NUL.
const PDF_WS = new Set([0x20, 0x09, 0x0d, 0x0a, 0x0c, 0x00]);

const TEXT_ENCODER = new TextEncoder();

// ── byte helpers ─────────────────────────────────────────────────────────────
export function isU32(n: number): boolean {
  return Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
}

/** u32 big-endian. MUST throw on a non-u32 — do NOT silently wrap with `>>>0`. */
export function u32be(n: number): Uint8Array {
  if (!isU32(n)) throw new RangeError(`u32be: not a uint32: ${n}`);
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

export function u64be(n: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false);
  return out;
}

/** u32be length prefix followed by the raw bytes. */
export function lp(buf: Uint8Array): Uint8Array {
  return concatBytes(u32be(buf.length), buf);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function ascii(s: string): Uint8Array {
  // ASCII-only domain tags / decimal strings — TextEncoder is UTF-8 but
  // identical for the ASCII subset used here.
  return TEXT_ENCODER.encode(s);
}

export function toHex32(x: bigint): string {
  return x.toString(16).padStart(64, "0");
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const byte of b) s += byte.toString(16).padStart(2, "0");
  return s;
}

// ── canonical-form validators (REJECT, do not reduce — ADR-0030 §2) ──────────
export function isCanonicalDecimal(s: unknown): boolean {
  if (typeof s !== "string" || s.length === 0) return false;
  if (!/^[0-9]+$/.test(s)) return false;
  if (s.length > 1 && s[0] === "0") return false; // no leading zero except "0"
  return true;
}

/** recipient_id: canonical decimal and < r. */
export function validRecipient(s: unknown): boolean {
  return isCanonicalDecimal(s) && BigInt(s as string) < BN254_R;
}

/** blinding_decimal: canonical decimal and in [0, l). */
export function validBlinding(s: unknown): boolean {
  return isCanonicalDecimal(s) && BigInt(s as string) < BJJ_L;
}

/** leaf_hex: exactly 64 lowercase-hex chars and < r. */
export function validLeafHex(s: unknown): boolean {
  if (typeof s !== "string" || s.length !== 64) return false;
  if (!/^[0-9a-f]{64}$/.test(s)) return false;
  return bytesBEToBigInt(hexToBytes(s)) < BN254_R;
}

/** original_root: exactly 64 lowercase-hex chars and < r. */
export function validRootHex(s: unknown): boolean {
  return validLeafHex(s);
}

// ── crypto core (mirrors olympus_crypto::redaction) ──────────────────────────

/**
 * content = reduce_l( BLAKE3_XOF(OBJ_DOMAIN || lp(u32_be(segId)) || contentBytes)[..64] ).
 */
export function contentScalar(segId: number, contentBytes: Uint8Array): bigint {
  const input = concatBytes(ascii(OBJ_DOMAIN), lp(u32be(segId)), contentBytes);
  return bytesBEToBigInt(blake3(input, { dkLen: 64 })) % BJJ_L;
}

/** leaf = Poseidon(C.x, C.y), C = content*G + blinding*H (Pedersen on BJJ). */
export function leafFrom(content: bigint, blinding: bigint): bigint {
  const c = pedersenCommit(content, blinding);
  return poseidon2([c.x, c.y]);
}

/** domain_node(d, l, r) = Poseidon(Poseidon(d, l), r). */
export function domainNode(d: number | bigint, left: bigint, right: bigint): bigint {
  const inner = poseidon2([BigInt(d), left]);
  return poseidon2([inner, right]);
}

/**
 * Variable-depth fold (ADR-0030 §1): pad Fr(0) to 2^ceil(log2 N), domain 1.
 * Requires N >= 2.
 */
export function variableDepthFold(leaves: bigint[]): bigint {
  const n = leaves.length;
  if (n < 2) throw new Error("N must be >= 2");
  let depth = 0;
  while (1 << depth < n) depth++;
  const width = 1 << depth;
  let level = leaves.slice();
  while (level.length < width) level.push(0n);
  for (let d = 0; d < depth; d++) {
    const next: bigint[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(domainNode(1, level[i], level[i + 1]));
    }
    level = next;
  }
  return level[0];
}

/**
 * Per-format content_bytes for a revealed segment (ADR-0030 §3 table). Returns
 * the bytes fed to `contentScalar`. ooxml-part binds `lp(label) || payload`.
 */
export function revealedContentBytes(
  format: string,
  slice: Uint8Array,
  label: string,
): Uint8Array {
  if (format === "pdf-object" || format === "text-line") {
    return slice; // plain slice (untrimmed; text keeps trailing \n)
  }
  if (format === "ooxml-part") {
    // committed = lp(label) || payload  (payload = the raw Stored slice)
    return concatBytes(lp(ascii(label)), slice);
  }
  if (format === "pdf-xref-stream") {
    // inner = slice[find("obj")+3 .. rfind("endobj")], trim with PDF_WS.
    const objIdx = indexOfBytes(slice, ascii("obj"));
    const endIdx = lastIndexOfBytes(slice, ascii("endobj"));
    if (objIdx < 0 || endIdx < 0 || endIdx < objIdx + 3) {
      throw new Error("pdf-xref-stream: obj/endobj framing not found");
    }
    let lo = objIdx + 3;
    let hi = endIdx; // exclusive
    while (lo < hi && PDF_WS.has(slice[lo])) lo++;
    while (hi > lo && PDF_WS.has(slice[hi - 1])) hi--;
    return slice.slice(lo, hi);
  }
  throw new Error("unknown format " + format);
}

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function lastIndexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = haystack.length - needle.length; i >= 0; i--) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

// ── encodings (ADR-0030 §2) ──────────────────────────────────────────────────

/**
 * table_hash = BLAKE3(TABLE_V3 || for each seg: u32(id) || u8(redacted) ||
 *   u64(offset) || u64(length) || lp(label) || lp(redacted?leaf_hex:blinding_decimal)).
 */
export function tableHash(segments: V3Segment[]): Uint8Array {
  const parts: Uint8Array[] = [ascii(TABLE_V3_PREFIX)];
  for (const s of segments) {
    parts.push(u32be(s.segment_id));
    parts.push(new Uint8Array([s.redacted ? 0x01 : 0x00]));
    parts.push(u64be(s.artifact_offset));
    parts.push(u64be(s.artifact_length));
    parts.push(lp(ascii(s.label ?? "")));
    const valueText = s.redacted ? (s.leaf_hex ?? "") : (s.blinding_decimal ?? "");
    parts.push(lp(ascii(valueText)));
  }
  return blake3(concatBytes(...parts));
}

export function signingPayload(
  rootHex: string,
  format: string,
  n: number,
  recipientDec: string,
  th: Uint8Array,
): Uint8Array {
  return concatBytes(
    ascii(BUNDLE_V3_PREFIX),
    lp(ascii(rootHex)),
    lp(ascii(format)),
    u32be(n),
    lp(ascii(recipientDec)),
    th, // un-length-prefixed terminal 32 bytes
  );
}

export function nullifier(
  rootRaw32: Uint8Array,
  th: Uint8Array,
  recipientDec: string,
): Uint8Array {
  return blake3(
    concatBytes(ascii(NULLIFIER_V1_PREFIX), rootRaw32, th, lp(ascii(recipientDec))),
  );
}

// ── bundle types (ADR-0030 §2; mirror the Rust serde shape) ──────────────────

/** One segment row of a V3 bundle. */
export interface V3Segment {
  segment_id: number;
  redacted: boolean;
  /** Byte range into the redacted artifact the recipient holds. */
  artifact_offset: number;
  artifact_length: number;
  /** Present (and bound into the leaf) for `ooxml-part`. */
  label?: string;
  /** Revealed segments only: decimal blinding so the recipient recomputes the leaf. */
  blinding_decimal?: string;
  /** Redacted segments only: the committed blinded leaf (64-char lowercase hex). */
  leaf_hex?: string;
}

/** A complete V3 redaction bundle. */
export interface V3Bundle {
  /** 64-char lowercase hex of the committed variable-depth fold root. */
  original_root: string;
  /** Frozen segment-format tag. */
  format: string;
  segment_count: number;
  /** Canonical decimal recipient field element. */
  recipient_id: string;
  segments: V3Segment[];
  /** 64-char lowercase hex BLAKE3 nullifier (derived; recompute-and-check). */
  nullifier: string;
  /** Ed25519 signature over the signing payload, hex. */
  signature_hex: string;
  /** Optional convenience hint — NOT authoritative; the signature is. */
  table_hash_hex?: string;
  /** Optional: hex of the redacted artifact the bundle binds (used when no
   *  artifact bytes are passed in to the verifier). */
  artifact_hex?: string;
}

export interface VerifyV3Options {
  /** Defaults true; set false for the byte-dump fixture whose original_root is a
   *  fixed layout anchor (NOT a fold of the segments). */
  verifyFold?: boolean;
  /** Override the artifact bytes used for revealed-segment reconstruction (else
   *  `bundle.artifact_hex`). */
  artifactBytes?: Uint8Array;
}

/**
 * Full V3 verification (ADR-0030 §3). Throws on the FIRST failed check with a
 * descriptive reason.
 */
export function verifyV3(
  bundle: V3Bundle,
  issuerPubkey: Uint8Array,
  format: string,
  opts: VerifyV3Options = {},
): void {
  const verifyFold = opts.verifyFold !== false;
  const segs = bundle.segments;
  const n = bundle.segment_count;

  // 1. Structural.
  if (!FORMAT_TAGS.has(format)) throw new Error("unknown format " + format);
  if (
    typeof n !== "number" ||
    BigInt(n) < 2n ||
    BigInt(n) > MAX_REDACTION_SEGMENTS
  ) {
    throw new Error("N out of [2, 2^20]: " + n);
  }
  if (!Array.isArray(segs) || segs.length !== n) {
    throw new Error("segment_count != segments.len()");
  }
  if (!validRootHex(bundle.original_root)) {
    throw new Error("non-canonical original_root");
  }
  if (!validRecipient(bundle.recipient_id)) {
    throw new Error("non-canonical recipient_id");
  }

  const ooxml = format === "ooxml-part";
  let prev: number | null = null;
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i];
    if (!isU32(s.segment_id)) throw new Error("segment_id not a uint32 at " + i);
    if (prev !== null && s.segment_id <= prev) {
      throw new Error("ids not strictly ascending at " + i);
    }
    prev = s.segment_id;
    if (ooxml && (s.segment_id !== i || !s.label || s.label.length === 0)) {
      throw new Error("ooxml-part requires dense 0..N-1 ids + label at " + i);
    }
    // optional-field correctness + canonical-form rejects
    if (s.redacted) {
      if (typeof s.leaf_hex !== "string") {
        throw new Error("redacted seg missing leaf_hex");
      }
      if (!validLeafHex(s.leaf_hex)) {
        throw new Error("non-canonical leaf_hex at seg " + s.segment_id);
      }
      if (s.blinding_decimal !== undefined) {
        throw new Error("redacted seg carries blinding");
      }
    } else {
      if (typeof s.blinding_decimal !== "string") {
        throw new Error("revealed seg missing blinding_decimal");
      }
      if (!validBlinding(s.blinding_decimal)) {
        throw new Error("non-canonical blinding at seg " + s.segment_id);
      }
      if (s.leaf_hex !== undefined) {
        throw new Error("revealed seg carries leaf_hex");
      }
    }
  }

  // 2/3. Reconstruct + fold.
  if (verifyFold) {
    const artifact = opts.artifactBytes
      ? opts.artifactBytes
      : bundle.artifact_hex !== undefined
        ? hexToBytes(bundle.artifact_hex)
        : undefined;
    if (artifact === undefined) {
      throw new Error("no artifact bytes available for fold reconstruction");
    }
    const leaves: bigint[] = [];
    for (const s of segs) {
      if (s.redacted) {
        leaves.push(bytesBEToBigInt(hexToBytes(s.leaf_hex as string)));
      } else {
        const off = Number(s.artifact_offset);
        const len = Number(s.artifact_length);
        if (off + len > artifact.length) {
          throw new Error("byte range outside artifact at seg " + s.segment_id);
        }
        const slice = artifact.slice(off, off + len);
        const cb = revealedContentBytes(format, slice, s.label ?? "");
        const content = contentScalar(s.segment_id, cb);
        const blinding = BigInt(s.blinding_decimal as string);
        leaves.push(leafFrom(content, blinding));
      }
    }
    const root = variableDepthFold(leaves);
    if (toHex32(root) !== bundle.original_root) {
      throw new Error("fold != original_root");
    }
  }

  // 4. table_hash + payload + signature + nullifier. table_hash is re-derived
  //    SOLELY from `segments`; the `table_hash_hex` field is a convenience hint,
  //    NOT authoritative — the signature over the recomputed payload is. So
  //    flipping a flag changes the recomputed table_hash and breaks the signature.
  const th = tableHash(segs);
  const payload = signingPayload(
    bundle.original_root,
    format,
    n,
    bundle.recipient_id,
    th,
  );
  const sig = hexToBytes(bundle.signature_hex);
  if (!ed25519.verify(sig, payload, issuerPubkey)) {
    throw new Error("Ed25519 signature invalid");
  }

  const rootRaw = hexToBytes(bundle.original_root);
  const nf = nullifier(rootRaw, th, bundle.recipient_id);
  if (bytesToHex(nf) !== bundle.nullifier) {
    throw new Error("nullifier mismatch");
  }
}

/**
 * High-level in-app verifier: verify a delivered redacted artifact against a V3
 * bundle + the issuer's Ed25519 pubkey (hex). Runs the FULL verifyV3 (structural
 * + per-segment canonical-form rejects + fold reconstruction + Ed25519 signature
 * + nullifier). When `bundle.artifact_hex` is absent, the passed `artifactBytes`
 * drive revealed-segment reconstruction. Errors are caught and returned as
 * `{ ok: false, reason }`.
 */
export function verifyRedactionBundleV3(
  bundle: V3Bundle,
  artifactBytes: Uint8Array,
  issuerPubkeyHex: string,
  format: string,
): { ok: boolean; reason?: string } {
  try {
    const issuerPubkey = hexToBytes(issuerPubkeyHex.trim());
    verifyV3(bundle, issuerPubkey, format, { artifactBytes });
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
}
