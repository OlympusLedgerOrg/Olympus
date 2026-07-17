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
 *   - structural checks (N == len, 2 <= N <= 2^16, strictly-ascending-unique
 *     u32 ids, ooxml-part dense 0..N-1 + label per entry),
 *   - per-segment optional-field + canonical-form REJECTS (NO `% l` / `% r`
 *     reduction — hard reject any out-of-range leaf_hex / blinding_decimal /
 *     recipient_id / original_root),
 *   - per-format revealed-leaf reconstruction + the variable-depth fold
 *     (pad Fr(0) to 2^ceil(log2 N); domain_node(2, l, r)) == original_root,
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

export const MAX_REDACTION_SEGMENTS = 1n << 16n;
const FORMAT_TAGS = new Set([
  "pdf-object",
  "pdf-xref-stream",
  "text-line",
  "ooxml-part",
  "pdf-textrun",
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

const U64_MAX = (1n << 64n) - 1n;

/** A non-negative JS-safe integer usable as a uint64 byte offset/length. */
export function isSafeU64(n: unknown): n is number {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
}

/** u64 big-endian. MUST throw on a non-uint64 — mirror `u32be`'s fail-closed contract. */
export function u64be(n: number | bigint): Uint8Array {
  const v = typeof n === "bigint" ? n : isSafeU64(n) ? BigInt(n) : null;
  if (v === null || v < 0n || v > U64_MAX) {
    throw new RangeError(`u64be: not a uint64: ${String(n)}`);
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, false);
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
  // Domain tags and decimal strings are ASCII; OOXML labels use the same helper
  // intentionally because TextEncoder produces their canonical UTF-8 bytes.
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
 * Variable-depth fold (ADR-0030 §1): pad Fr(0) to 2^ceil(log2 N), node domain 2
 * (audit L-4 — internal nodes use the Poseidon NODE tag, distinct from the
 * leaf-wrap LEAF=1 tag). Requires N >= 2.
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
      next.push(domainNode(2, level[i], level[i + 1]));
    }
    level = next;
  }
  return level[0];
}

/**
 * Per-format content_bytes for a revealed segment (ADR-0030 §3 table). Returns
 * the bytes fed to `contentScalar`. ooxml-part binds `lp(label) || payload`.
 */
export function revealedContentBytes(format: string, slice: Uint8Array, label: string): Uint8Array {
  if (format === "pdf-object" || format === "text-line" || format === "pdf-textrun") {
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

// ── artifact replay parsers ─────────────────────────────────────────────────

interface ArtifactSpan {
  segment_id: number;
  artifact_offset: number;
  artifact_length: number;
  label?: string;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function bytesAt(buf: Uint8Array, at: number, expected: Uint8Array): boolean {
  return (
    at >= 0 &&
    at + expected.length <= buf.length &&
    bytesEqual(buf.slice(at, at + expected.length), expected)
  );
}

function isAsciiWhitespace(b: number): boolean {
  return b === 0x20 || b === 0x09 || b === 0x0d || b === 0x0a || b === 0x0c;
}

function assertTile(artifactLength: number, spans: ArtifactSpan[]): void {
  let pos = 0;
  for (const span of spans) {
    if (span.artifact_offset !== pos) throw new Error("artifact bytes not fully covered");
    pos += span.artifact_length;
    if (!Number.isSafeInteger(pos)) throw new Error("artifact span overflow");
  }
  if (pos !== artifactLength) throw new Error("artifact bytes not fully covered");
}

function textArtifactSpans(artifact: Uint8Array, segments: V3Segment[]): ArtifactSpan[] {
  if (artifact.length === 0) throw new Error("empty text artifact");
  // Redacting a multi-line source block re-emits one fixed token, so the new
  // line count cannot reconstruct the original grouping. Replay the SIGNED
  // geometry and require exact, gap-free coverage; the fold pass validates the
  // token in every redacted range and binds all revealed bytes.
  const spans: ArtifactSpan[] = segments.map((segment) => ({
    segment_id: segment.segment_id,
    artifact_offset: segment.artifact_offset,
    artifact_length: segment.artifact_length,
  }));
  assertTile(artifact.length, spans);
  return spans;
}

function readPdfUint(buf: Uint8Array, at: number): [number, number] | undefined {
  let i = at;
  while (i < buf.length && isAsciiWhitespace(buf[i])) i++;
  const start = i;
  let value = 0;
  while (i < buf.length && buf[i] >= 0x30 && buf[i] <= 0x39) {
    value = value * 10 + (buf[i] - 0x30);
    if (!Number.isSafeInteger(value)) return undefined;
    i++;
  }
  return i === start ? undefined : [value, i];
}

function pdfObjectSpan(
  artifact: Uint8Array,
  offset: number,
  scanEnd: number,
  expectedId: number,
  expectedGeneration: number,
): [number, number] | undefined {
  if (offset < 0 || offset >= scanEnd || scanEnd > artifact.length) return undefined;
  let read = readPdfUint(artifact, offset);
  if (!read || read[0] !== expectedId) return undefined;
  read = readPdfUint(artifact, read[1]);
  if (!read || read[0] !== expectedGeneration) return undefined;
  let headerEnd = read[1];
  while (headerEnd < scanEnd && isAsciiWhitespace(artifact[headerEnd])) headerEnd++;
  if (
    !bytesAt(artifact, headerEnd, ascii("obj")) ||
    headerEnd + 3 >= scanEnd ||
    !isAsciiWhitespace(artifact[headerEnd + 3])
  ) return undefined;

  const region = artifact.slice(offset, scanEnd);
  const firstEnd = indexOfBytes(region, ascii("endobj"));
  if (firstEnd < 0) return undefined;
  const stream = indexOfBytes(region, ascii("stream"));
  let rel = firstEnd;
  if (stream >= 0 && stream < firstEnd) {
    const afterStream = stream + 6;
    const es = indexOfBytes(region.slice(afterStream), ascii("endstream"));
    if (es < 0) return undefined;
    const afterEndstream = afterStream + es + 9;
    const endAfter = indexOfBytes(region.slice(afterEndstream), ascii("endobj"));
    if (endAfter < 0) return undefined;
    rel = afterEndstream + endAfter;
  }
  return [offset, offset + rel + 6];
}

interface PdfEntry {
  off: number;
  generation: number;
}

function validateCanonicalPdfContainer(
  artifact: Uint8Array,
  entries: Map<number, PdfEntry>,
  spans: ArtifactSpan[],
  xrefOff: number,
  afterEof: number,
): void {
  const h17 = ascii("%PDF-1.7\n");
  const h14 = ascii("%PDF-1.4\n");
  const header = bytesAt(artifact, 0, h17) ? h17 : bytesAt(artifact, 0, h14) ? h14 : undefined;
  if (!header) throw new Error("non-canonical pdf container");

  const ordered = spans.slice().sort((a, b) => a.artifact_offset - b.artifact_offset);
  let pos = header.length;
  for (const span of ordered) {
    if (span.artifact_offset !== pos) throw new Error("non-canonical pdf container");
    pos += span.artifact_length;
    if (pos >= xrefOff || artifact[pos] !== 0x0a) throw new Error("non-canonical pdf container");
    pos++;
  }
  if (pos !== xrefOff) throw new Error("non-canonical pdf container");

  const ids = [...entries.keys()].sort((a, b) => a - b);
  if (ids.length === 0) throw new Error("artifact segment count mismatch");
  const maxId = ids[ids.length - 1];
  const chunks: Uint8Array[] = [ascii("xref\n0 1\n0000000000 65535 f \n")];
  let i = 0;
  while (i < ids.length) {
    let j = i;
    while (j + 1 < ids.length && ids[j + 1] === ids[j] + 1) j++;
    chunks.push(ascii(`${ids[i]} ${j - i + 1}\n`));
    for (const id of ids.slice(i, j + 1)) {
      const entry = entries.get(id) as PdfEntry;
      chunks.push(
        ascii(
          `${String(entry.off).padStart(10, "0")} ${String(entry.generation).padStart(5, "0")} n \n`,
        ),
      );
    }
    i = j + 1;
  }
  const expectedXref = concatBytes(...chunks);
  if (!bytesAt(artifact, xrefOff, expectedXref)) throw new Error("non-canonical pdf container");

  let tail = xrefOff + expectedXref.length;
  const prefix = ascii(`trailer\n<< /Size ${maxId + 1} /Root `);
  if (!bytesAt(artifact, tail, prefix)) throw new Error("non-canonical pdf container");
  tail += prefix.length;
  let read = readPdfUint(artifact, tail);
  if (!read) throw new Error("bad pdf root");
  const rootId = read[0];
  read = readPdfUint(artifact, read[1]);
  if (!read) throw new Error("bad pdf root");
  const rootGeneration = read[0];
  if (entries.get(rootId)?.generation !== rootGeneration) {
    throw new Error("pdf root is not an active object");
  }
  const suffix = ascii(` R >>\nstartxref\n${xrefOff}\n%%EOF\n`);
  if (
    !bytesAt(artifact, read[1], suffix) ||
    read[1] + suffix.length !== artifact.length ||
    afterEof + 1 !== artifact.length
  ) {
    throw new Error("non-canonical pdf container");
  }
}

function pdfArtifactSpans(artifact: Uint8Array, expectedN?: number): ArtifactSpan[] {
  const sx = lastIndexOfBytes(artifact, ascii("startxref"));
  if (sx < 0) throw new Error("pdf startxref missing");
  const startxref = readPdfUint(artifact, sx + 9);
  if (!startxref) throw new Error("bad startxref");
  const xrefOff = startxref[0];
  if (!bytesAt(artifact, xrefOff, ascii("xref"))) throw new Error("pdf xref table missing");

  let i = xrefOff + 4;
  let parsedRows = 0;
  const entries = new Map<number, PdfEntry>();
  for (;;) {
    while (i < artifact.length && isAsciiWhitespace(artifact[i])) i++;
    if (bytesAt(artifact, i, ascii("trailer"))) break;
    let read = readPdfUint(artifact, i);
    if (!read) throw new Error("bad xref subsection");
    const startObj = read[0];
    read = readPdfUint(artifact, read[1]);
    if (!read) throw new Error("bad xref subsection");
    const count = read[0];
    i = read[1];
    const cap = Number(MAX_REDACTION_SEGMENTS) + 1;
    if (count > cap || startObj + Math.max(0, count - 1) > 0xffffffff || parsedRows + count > cap) {
      throw new Error("pdf xref entry cap exceeded");
    }
    parsedRows += count;
    for (let k = 0; k < count; k++) {
      read = readPdfUint(artifact, i);
      if (!read) throw new Error("bad xref entry");
      const off = read[0];
      read = readPdfUint(artifact, read[1]);
      if (!read) throw new Error("bad xref entry");
      const generation = read[0];
      i = read[1];
      while (i < artifact.length && isAsciiWhitespace(artifact[i])) i++;
      const ty = artifact[i++];
      const id = startObj + k;
      if (ty === 0x6e) {
        if (generation > 0xffff || entries.has(id)) throw new Error("bad xref entry");
        entries.set(id, { off, generation });
      } else if (ty !== 0x66) {
        throw new Error("bad xref entry");
      }
    }
  }
  if (expectedN !== undefined && entries.size !== expectedN) {
    throw new Error("artifact segment count mismatch");
  }
  const offsets = [...entries.values()].map((e) => e.off).sort((a, b) => a - b);
  if (new Set(offsets).size !== offsets.length) throw new Error("overlapping pdf object offsets");
  const scanEnds = new Map(
    offsets.map((off, index) => [off, index + 1 < offsets.length ? offsets[index + 1] : xrefOff]),
  );

  const eof = lastIndexOfBytes(artifact, ascii("%%EOF"));
  if (eof < 0) throw new Error("pdf EOF marker missing");
  const afterEof = eof + 5;
  for (const b of artifact.slice(afterEof)) {
    if (!isAsciiWhitespace(b)) throw new Error("hidden bytes after pdf EOF");
  }
  const spans: ArtifactSpan[] = [];
  for (const [id, entry] of [...entries.entries()].sort((a, b) => a[0] - b[0])) {
    const scanEnd = scanEnds.get(entry.off);
    if (scanEnd === undefined) throw new Error("pdf object offset missing");
    const span = pdfObjectSpan(artifact, entry.off, scanEnd, id, entry.generation);
    if (!span) throw new Error("malformed pdf object");
    spans.push({ segment_id: id, artifact_offset: span[0], artifact_length: span[1] - span[0] });
  }
  validateCanonicalPdfContainer(artifact, entries, spans, xrefOff, afterEof);
  return spans;
}

function le16(buf: Uint8Array, i: number): number | undefined {
  if (i < 0 || i + 2 > buf.length) return undefined;
  return buf[i] | (buf[i + 1] << 8);
}

function le32(buf: Uint8Array, i: number): number | undefined {
  if (i < 0 || i + 4 > buf.length) return undefined;
  return (buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16) | (buf[i + 3] << 24)) >>> 0;
}

function crc32(buf: Uint8Array): number {
  let crc = 0xffffffff;
  for (const b of buf) {
    crc = (crc ^ b) >>> 0;
    for (let i = 0; i < 8; i++) {
      const mask = -(crc & 1);
      crc = ((crc >>> 1) ^ (0xedb88320 & mask)) >>> 0;
    }
  }
  return ~crc >>> 0;
}

interface OoxmlEntry {
  label: string;
  versionNeeded: number;
  flags: number;
  mtime: number;
  mdate: number;
  crc: number;
  size: number;
  localHeaderOffset: number;
}

function compareUtf8(a: string, b: string): number {
  const aa = ascii(a);
  const bb = ascii(b);
  const n = Math.min(aa.length, bb.length);
  for (let i = 0; i < n; i++) if (aa[i] !== bb[i]) return aa[i] - bb[i];
  return aa.length - bb.length;
}

function validateCanonicalOoxmlDirectory(
  artifact: Uint8Array,
  centralStart: number,
  entries: OoxmlEntry[],
): void {
  let i = centralStart;
  for (const entry of entries) {
    if (!bytesAt(artifact, i, new Uint8Array([0x50, 0x4b, 0x01, 0x02]))) {
      throw new Error("non-canonical ooxml zip entry");
    }
    const madeBy = le16(artifact, i + 4);
    const external = le32(artifact, i + 38);
    if (
      madeBy === undefined ||
      ![0, 3].includes(madeBy >>> 8) ||
      (madeBy & 0xff) < 10 ||
      (madeBy & 0xff) > 63 ||
      le16(artifact, i + 6) !== entry.versionNeeded ||
      le16(artifact, i + 8) !== entry.flags ||
      le16(artifact, i + 10) !== 0 ||
      le16(artifact, i + 12) !== entry.mtime ||
      le16(artifact, i + 14) !== entry.mdate ||
      le32(artifact, i + 16) !== entry.crc ||
      le32(artifact, i + 20) !== entry.size ||
      le32(artifact, i + 24) !== entry.size ||
      le16(artifact, i + 30) !== 0 ||
      le16(artifact, i + 32) !== 0 ||
      le16(artifact, i + 34) !== 0 ||
      le16(artifact, i + 36) !== 0 ||
      (external !== 0 && external !== 0x81a40000) ||
      le32(artifact, i + 42) !== entry.localHeaderOffset
    ) {
      throw new Error("non-canonical ooxml zip entry");
    }
    const nameLen = le16(artifact, i + 28);
    if (nameLen === undefined) throw new Error("non-canonical ooxml zip entry");
    const nameStart = i + 46;
    const nameEnd = nameStart + nameLen;
    if (
      !bytesAt(artifact, nameStart, ascii(entry.label)) ||
      nameEnd !== nameStart + ascii(entry.label).length
    ) {
      throw new Error("non-canonical ooxml zip entry");
    }
    i = nameEnd;
  }
  const centralSize = i - centralStart;
  const count = entries.length;
  if (
    !bytesAt(artifact, i, new Uint8Array([0x50, 0x4b, 0x05, 0x06])) ||
    le16(artifact, i + 4) !== 0 ||
    le16(artifact, i + 6) !== 0 ||
    le16(artifact, i + 8) !== count ||
    le16(artifact, i + 10) !== count ||
    le32(artifact, i + 12) !== centralSize ||
    le32(artifact, i + 16) !== centralStart ||
    le16(artifact, i + 20) !== 0 ||
    i + 22 !== artifact.length
  ) {
    throw new Error("hidden bytes after ooxml EOCD");
  }
}

function ooxmlArtifactSpans(artifact: Uint8Array, expectedN: number): ArtifactSpan[] {
  const local = new Uint8Array([0x50, 0x4b, 0x03, 0x04]);
  const central = new Uint8Array([0x50, 0x4b, 0x01, 0x02]);
  const eocd = new Uint8Array([0x50, 0x4b, 0x05, 0x06]);
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const spans: ArtifactSpan[] = [];
  const entries: OoxmlEntry[] = [];
  const seen = new Set<string>();
  let i = 0;
  while (i + 4 <= artifact.length) {
    if (bytesAt(artifact, i, central) || bytesAt(artifact, i, eocd)) break;
    if (!bytesAt(artifact, i, local)) throw new Error("malformed zip local header");
    const localHeaderOffset = i;
    const version = le16(artifact, i + 4);
    const flags = le16(artifact, i + 6);
    const method = le16(artifact, i + 8);
    const mtime = le16(artifact, i + 10);
    const mdate = le16(artifact, i + 12);
    const crc = le32(artifact, i + 14);
    const comp = le32(artifact, i + 18);
    const uncomp = le32(artifact, i + 22);
    const nameLen = le16(artifact, i + 26);
    const extraLen = le16(artifact, i + 28);
    if (
      version === undefined ||
      flags === undefined ||
      mtime === undefined ||
      mdate === undefined ||
      crc === undefined ||
      comp === undefined ||
      nameLen === undefined ||
      extraLen === undefined ||
      ![10, 20].includes(version) ||
      (flags & ~0x0800) !== 0 ||
      method !== 0 ||
      mtime !== 0 ||
      ![0, 33].includes(mdate) ||
      comp !== uncomp ||
      extraLen !== 0
    ) {
      throw new Error("non-canonical ooxml zip entry");
    }
    const nameStart = i + 30;
    const dataStart = nameStart + nameLen;
    const dataEnd = dataStart + comp;
    if (dataEnd > artifact.length) throw new Error("zip data outside artifact");
    const payload = artifact.slice(dataStart, dataEnd);
    if (crc !== crc32(payload)) throw new Error("non-canonical ooxml zip entry");
    let label: string;
    try {
      label = decoder.decode(artifact.slice(nameStart, nameStart + nameLen));
    } catch {
      throw new Error("zip part name not utf8");
    }
    if (seen.has(label)) throw new Error("duplicate ooxml part");
    seen.add(label);
    if (spans.length >= expectedN || BigInt(spans.length) >= MAX_REDACTION_SEGMENTS) {
      throw new Error("artifact segment count mismatch");
    }
    spans.push({
      segment_id: spans.length,
      artifact_offset: dataStart,
      artifact_length: comp,
      label,
    });
    entries.push({
      label,
      versionNeeded: version,
      flags,
      mtime,
      mdate,
      crc,
      size: comp,
      localHeaderOffset,
    });
    i = dataEnd;
  }
  if (spans.length !== expectedN) throw new Error("artifact segment count mismatch");
  const labels = spans.map((s) => s.label as string);
  const sorted = labels.slice().sort(compareUtf8);
  if (labels.some((label, index) => label !== sorted[index])) {
    throw new Error("ooxml parts not deterministically ordered");
  }
  validateCanonicalOoxmlDirectory(artifact, i, entries);
  return spans;
}

function scanPdfLiteralString(buf: Uint8Array, open: number): number {
  let i = open + 1;
  let depth = 1;
  while (i < buf.length) {
    if (buf[i] === 0x5c) i += 2;
    else if (buf[i] === 0x28) {
      depth++;
      i++;
    } else if (buf[i] === 0x29) {
      depth--;
      i++;
      if (depth === 0) return i;
    } else i++;
  }
  return i;
}

function pdfTextrunWordRanges(artifact: Uint8Array): Array<[number, number]> {
  const shows: Array<[number, number]> = [];
  const pending: Array<[number, number]> = [];
  let i = 0;
  while (i < artifact.length) {
    const c = artifact[i];
    if (PDF_WS.has(c)) i++;
    else if (c === 0x28) {
      const end = scanPdfLiteralString(artifact, i);
      pending.push([i, end]);
      i = end;
    } else if (c === 0x3c) {
      if (artifact[i + 1] === 0x3c) {
        let depth = 1;
        i += 2;
        while (i + 1 < artifact.length && depth > 0) {
          if (artifact[i] === 0x3c && artifact[i + 1] === 0x3c) {
            depth++;
            i += 2;
          } else if (artifact[i] === 0x3e && artifact[i + 1] === 0x3e) {
            depth--;
            i += 2;
          } else i++;
        }
      } else {
        i++;
        while (i < artifact.length && artifact[i] !== 0x3e) i++;
        i++;
      }
    } else if (c === 0x2f) {
      i++;
      while (
        i < artifact.length &&
        !PDF_WS.has(artifact[i]) &&
        ![0x28, 0x3c, 0x5b, 0x5d, 0x2f, 0x7b, 0x7d, 0x25].includes(artifact[i])
      ) i++;
    } else if ([0x5b, 0x5d, 0x7b, 0x7d, 0x29, 0x3e].includes(c)) i++;
    else if (c === 0x27 || c === 0x22) {
      shows.push(...pending.splice(0));
      i++;
    } else if ((c >= 0x30 && c <= 0x39) || c === 0x2b || c === 0x2d || c === 0x2e) {
      i++;
      while (
        i < artifact.length &&
        ((artifact[i] >= 0x30 && artifact[i] <= 0x39) ||
          [0x2b, 0x2d, 0x2e, 0x65, 0x45].includes(artifact[i]))
      ) i++;
    } else if ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a)) {
      const start = i;
      while (
        i < artifact.length &&
        ((artifact[i] >= 0x30 && artifact[i] <= 0x39) ||
          (artifact[i] >= 0x41 && artifact[i] <= 0x5a) ||
          (artifact[i] >= 0x61 && artifact[i] <= 0x7a) ||
          artifact[i] === 0x2a)
      ) i++;
      const op = new TextDecoder("ascii").decode(artifact.slice(start, i));
      if (op === "Tj" || op === "TJ") shows.push(...pending.splice(0));
      else pending.length = 0;
    } else i++;
  }

  const words: Array<[number, number]> = [];
  for (const [start, stop] of shows) {
    let cursor = start + 1;
    const end = Math.max(start + 1, stop - 1);
    while (cursor < end) {
      if (PDF_WS.has(artifact[cursor])) {
        cursor++;
        continue;
      }
      const wordStart = cursor;
      while (cursor < end && !PDF_WS.has(artifact[cursor])) cursor++;
      words.push([wordStart, cursor]);
    }
  }
  return words;
}

function pdfTextrunArtifactSpans(
  artifact: Uint8Array,
  segments: V3Segment[],
): ArtifactSpan[] {
  const words = pdfTextrunWordRanges(artifact);
  if (words.length !== segments.filter((segment) => !segment.redacted).length) {
    throw new Error("artifact segment count mismatch");
  }
  let wordIndex = 0;
  return segments.map((segment) => {
    if (segment.redacted) {
      return { segment_id: segment.segment_id, artifact_offset: 0, artifact_length: 0 };
    }
    const [start, end] = words[wordIndex++];
    return {
      segment_id: segment.segment_id,
      artifact_offset: start,
      artifact_length: end - start,
    };
  });
}

function artifactSpans(
  format: string,
  artifact: Uint8Array,
  segments: V3Segment[],
): ArtifactSpan[] {
  if (format === "text-line") return textArtifactSpans(artifact, segments);
  if (format === "pdf-object" || format === "pdf-xref-stream") {
    return pdfArtifactSpans(artifact, segments.length);
  }
  if (format === "ooxml-part") return ooxmlArtifactSpans(artifact, segments.length);
  if (format === "pdf-textrun") return pdfTextrunArtifactSpans(artifact, segments);
  throw new Error("unknown format " + format);
}

function validateRedactedBytes(format: string, slice: Uint8Array, label: string): void {
  if (format === "text-line") {
    if (!bytesEqual(slice, ascii("[REDACTED]\n")))
      throw new Error("redacted text bytes not destroyed");
    return;
  }
  if (format === "pdf-object" || format === "pdf-xref-stream") {
    const inner = revealedContentBytes("pdf-xref-stream", slice, "");
    if (!bytesEqual(inner, ascii("null"))) throw new Error("redacted pdf bytes not destroyed");
    return;
  }
  if (format === "ooxml-part") {
    const lower = label.toLowerCase();
    if (lower.endsWith(".xml") || lower.endsWith(".rels")) {
      throw new Error("structural ooxml part was redacted");
    }
    if (slice.length !== 0) throw new Error("redacted ooxml bytes not destroyed");
    return;
  }
  if (format === "pdf-textrun") {
    if (slice.length !== 0) throw new Error("redacted pdf text-run bytes not destroyed");
    return;
  }
  throw new Error("unknown format " + format);
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

export function nullifier(rootRaw32: Uint8Array, th: Uint8Array, recipientDec: string): Uint8Array {
  return blake3(concatBytes(ascii(NULLIFIER_V1_PREFIX), rootRaw32, th, lp(ascii(recipientDec))));
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
  // The caller-supplied format also drives the signed payload + the displayed
  // metadata; a bundle whose own `format` disagrees must NOT verify (else the UI
  // would show a different format than what was signed).
  if (bundle.format !== format) {
    throw new Error(`bundle format mismatch: ${bundle.format} != ${format}`);
  }
  if (typeof n !== "number" || BigInt(n) < 2n || BigInt(n) > MAX_REDACTION_SEGMENTS) {
    throw new Error("N out of [2, 2^16]: " + n);
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
    // Hard-reject non-canonical untyped JSON fields before they reach the
    // cryptographic serialization (u64be) or byte-slicing, so the JS verifier
    // cannot diverge from the Rust V3 wire contract on precision/type coercion.
    if (typeof s.redacted !== "boolean") {
      throw new Error("redacted flag not a boolean at " + i);
    }
    if (!isSafeU64(s.artifact_offset) || !isSafeU64(s.artifact_length)) {
      throw new Error("artifact byte range not a safe uint64 at " + i);
    }
    if (s.label !== undefined && typeof s.label !== "string") {
      throw new Error("label not a string at " + i);
    }
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
    const derived = new Map(
      artifactSpans(format, artifact, segs).map((span) => [span.segment_id, span]),
    );
    const leaves: bigint[] = [];
    for (const s of segs) {
      const span = derived.get(s.segment_id);
      if (!span) throw new Error("bundle segment absent from artifact");
      if (
        s.artifact_offset !== span.artifact_offset ||
        s.artifact_length !== span.artifact_length
      ) {
        throw new Error("bundle offset/length != artifact-derived span");
      }
      if (format === "ooxml-part" && (s.label ?? "") !== (span.label ?? "")) {
        throw new Error("bundle label != artifact-derived label");
      }
      const off = span.artifact_offset;
      const len = span.artifact_length;
      const slice = artifact.slice(off, off + len);
      if (s.redacted) {
        validateRedactedBytes(format, slice, s.label ?? "");
        leaves.push(bytesBEToBigInt(hexToBytes(s.leaf_hex as string)));
      } else {
        const end = off + len;
        if (!Number.isSafeInteger(end) || end > artifact.length) {
          throw new Error("byte range outside artifact at seg " + s.segment_id);
        }
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
  const payload = signingPayload(bundle.original_root, format, n, bundle.recipient_id, th);
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
