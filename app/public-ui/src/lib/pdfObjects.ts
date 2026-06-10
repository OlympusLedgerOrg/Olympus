/**
 * Browser-side PDF traditional-xref parser for the redaction auditor (ADR-0026).
 *
 * Mirrors `src-tauri/src/zk/pdf_objects.rs::extract_objects` byte-for-byte for
 * the auditor-relevant slice: parse the trailing `startxref` → traditional xref
 * table (+ `/Prev` chain), enumerate every in-use indirect object in
 * obj-id-ascending order, and return each object's `(obj_id, byteOffset,
 * byteLength)`. The auditor uses those byte ranges to extract object contents
 * for revealed-leaf recomputation; redacted leaves contribute zero to the
 * commitment chain (mask=0), so their contents are irrelevant.
 *
 * Scope (v1): traditional xref tables only — PDF 1.5+ cross-reference
 * **streams** surface as a typed error so the auditor can show a clean
 * "unsupported PDF" message. This matches the Rust path's `NotTraditionalXref`.
 *
 * Lockstep with Rust: every byte-offset / byte-length value here MUST match
 * what `extract_objects` records, because the bundle's `revealedSegments`
 * blindings were derived against THIS object segmentation. Drift means the
 * conformance test fails — that is the intended tripwire.
 */

export class PdfParseError extends Error {
  readonly kind:
    | "not_traditional_xref"
    | "malformed_xref"
    | "object_out_of_bounds";
  readonly objId?: number;
  constructor(
    kind: PdfParseError["kind"],
    message: string,
    objId?: number,
  ) {
    super(message);
    this.name = "PdfParseError";
    this.kind = kind;
    this.objId = objId;
  }
}

export interface PdfObjectSpan {
  /** Indirect object number (the `N` in `N G obj`). */
  objId: number;
  /** Generation (almost always 0). */
  generation: number;
  /** Byte offset of the object header `N G obj` in the original file. */
  byteOffset: number;
  /** End-exclusive byte offset just past the closing `endobj` keyword. */
  byteEnd: number;
}

const ENC = new TextEncoder();
const KW_STARTXREF = ENC.encode("startxref");
const KW_XREF = ENC.encode("xref");
const KW_TRAILER = ENC.encode("trailer");
const KW_PREV = ENC.encode("/Prev");
const KW_OBJ = ENC.encode("obj");
const KW_ENDOBJ = ENC.encode("endobj");
const KW_STREAM = ENC.encode("stream");
const KW_ENDSTREAM = ENC.encode("endstream");

function isAsciiDigit(b: number): boolean {
  return b >= 0x30 && b <= 0x39;
}

function isAsciiWs(b: number): boolean {
  // PDF spec: NUL, HT, LF, FF, CR, SP — match Rust `u8::is_ascii_whitespace()`
  // (NUL excluded by Rust's impl; safer to mirror exactly).
  return b === 0x09 || b === 0x0a || b === 0x0b || b === 0x0c || b === 0x0d || b === 0x20;
}

function lastIndexOf(haystack: Uint8Array, needle: Uint8Array, from?: number): number {
  const end = (from ?? haystack.length) - needle.length;
  outer: for (let i = end; i >= 0; i--) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function indexOf(haystack: Uint8Array, needle: Uint8Array, from = 0): number {
  const end = haystack.length - needle.length;
  outer: for (let i = from; i <= end; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function startsWith(buf: Uint8Array, at: number, needle: Uint8Array): boolean {
  if (at + needle.length > buf.length) return false;
  for (let j = 0; j < needle.length; j++) {
    if (buf[at + j] !== needle[j]) return false;
  }
  return true;
}

interface Cursor {
  i: number;
}

function skipWs(b: Uint8Array, c: Cursor): void {
  while (c.i < b.length && isAsciiWs(b[c.i])) c.i++;
}

function readU64(b: Uint8Array, c: Cursor): number | null {
  skipWs(b, c);
  const start = c.i;
  while (c.i < b.length && isAsciiDigit(b[c.i])) c.i++;
  if (c.i === start) return null;
  // Safe: PDF offsets fit in 53 bits (Number.MAX_SAFE_INTEGER) for any
  // realistically auditable file. Validate to surface attempts at overflow.
  const n = Number(new TextDecoder().decode(b.subarray(start, c.i)));
  if (!Number.isFinite(n) || n < 0 || !Number.isSafeInteger(n)) return null;
  return n;
}

function readType(b: Uint8Array, c: Cursor): number | null {
  skipWs(b, c);
  if (c.i >= b.length) return null;
  const v = b[c.i];
  c.i++;
  return v;
}

function looksLikeObjHeader(b: Uint8Array, at: number): boolean {
  const c: Cursor = { i: at };
  if (readU64(b, c) === null) return false;
  if (readU64(b, c) === null) return false;
  skipWs(b, c);
  return startsWith(b, c.i, KW_OBJ);
}

function parseTrailerPrev(b: Uint8Array, from: number): number | null {
  const pos = indexOf(b, KW_PREV, Math.min(from, b.length));
  if (pos < 0) return null;
  const c: Cursor = { i: pos + KW_PREV.length };
  return readU64(b, c);
}

function parseXrefSection(
  b: Uint8Array,
  offset: number,
  entries: Map<number, { offset: number; generation: number }>,
): number | null {
  if (offset >= b.length) {
    throw new PdfParseError(
      "malformed_xref",
      `xref offset ${offset} is past end of file`,
    );
  }
  const c: Cursor = { i: offset };
  skipWs(b, c);
  if (!startsWith(b, c.i, KW_XREF)) {
    if (looksLikeObjHeader(b, c.i)) {
      throw new PdfParseError(
        "not_traditional_xref",
        "PDF uses a cross-reference stream (PDF 1.5+), unsupported by the auditor.",
      );
    }
    throw new PdfParseError(
      "malformed_xref",
      "expected `xref` keyword at startxref offset",
    );
  }
  c.i += KW_XREF.length;

  for (;;) {
    skipWs(b, c);
    if (startsWith(b, c.i, KW_TRAILER)) {
      c.i += KW_TRAILER.length;
      break;
    }
    const start = readU64(b, c);
    if (start === null) {
      throw new PdfParseError("malformed_xref", "missing subsection start");
    }
    const count = readU64(b, c);
    if (count === null) {
      throw new PdfParseError("malformed_xref", "missing subsection count");
    }
    for (let k = 0; k < count; k++) {
      const off = readU64(b, c);
      if (off === null) {
        throw new PdfParseError("malformed_xref", `missing offset for entry ${k}`);
      }
      const gen = readU64(b, c);
      if (gen === null) {
        throw new PdfParseError("malformed_xref", `missing generation for entry ${k}`);
      }
      const ty = readType(b, c);
      if (ty === null) {
        throw new PdfParseError("malformed_xref", "missing entry type");
      }
      const objId = start + k;
      if (ty === 0x6e /* 'n' */ && !entries.has(objId)) {
        // first-seen wins → newer section's entries take precedence
        entries.set(objId, { offset: off, generation: gen });
      }
    }
  }
  return parseTrailerPrev(b, c.i);
}

function objectSpan(b: Uint8Array, objId: number, offset: number): { start: number; end: number } {
  if (offset >= b.length) {
    throw new PdfParseError(
      "object_out_of_bounds",
      `object ${objId} xref offset ${offset} is past end of file`,
      objId,
    );
  }
  const region = b.subarray(offset);
  const firstEndobj = indexOf(region, KW_ENDOBJ);
  const streamKw = indexOf(region, KW_STREAM);
  // A content stream payload may contain the bytes `endobj`. If a `stream`
  // token precedes the first `endobj`, find the *real* end-of-object via the
  // matching `endstream`. Mirrors `pdf_objects::object_span` exactly.
  let relEnd: number;
  if (
    streamKw >= 0 &&
    firstEndobj >= 0 &&
    streamKw < firstEndobj
  ) {
    const afterStream = streamKw + KW_STREAM.length;
    const es = indexOf(region, KW_ENDSTREAM, afterStream);
    if (es < 0) {
      throw new PdfParseError(
        "object_out_of_bounds",
        `object ${objId} has \`stream\` but no \`endstream\``,
        objId,
      );
    }
    const afterEndstream = es + KW_ENDSTREAM.length;
    const e = indexOf(region, KW_ENDOBJ, afterEndstream);
    if (e < 0) {
      throw new PdfParseError(
        "object_out_of_bounds",
        `object ${objId} has no \`endobj\` after \`endstream\``,
        objId,
      );
    }
    relEnd = e;
  } else if (firstEndobj >= 0) {
    relEnd = firstEndobj;
  } else {
    throw new PdfParseError(
      "object_out_of_bounds",
      `object ${objId} has no \`endobj\``,
      objId,
    );
  }
  return { start: offset, end: offset + relEnd + KW_ENDOBJ.length };
}

/**
 * Parse a PDF's traditional xref table + `/Prev` chain, return every in-use
 * indirect object as `{ objId, generation, byteOffset, byteEnd }` in
 * obj-id-ascending order. Throws [`PdfParseError`] for cross-reference
 * streams or malformed tables.
 *
 * Does NOT compute leaves — that's the auditor's job once it has the bytes
 * and the per-revealed-object blindings from the bundle.
 */
export function extractObjectSpans(pdfBytes: Uint8Array): PdfObjectSpan[] {
  const sx = lastIndexOf(pdfBytes, KW_STARTXREF);
  if (sx < 0) {
    throw new PdfParseError("malformed_xref", "no `startxref` marker");
  }
  const c: Cursor = { i: sx + KW_STARTXREF.length };
  const xrefOff = readU64(pdfBytes, c);
  if (xrefOff === null) {
    throw new PdfParseError("malformed_xref", "no offset after `startxref`");
  }

  const entries = new Map<number, { offset: number; generation: number }>();
  const visited = new Set<number>();
  let next: number | null = xrefOff;
  while (next !== null) {
    if (visited.has(next)) break; // /Prev cycle guard
    visited.add(next);
    next = parseXrefSection(pdfBytes, next, entries);
  }

  const sortedIds = Array.from(entries.keys()).sort((a, b) => a - b);
  const spans: PdfObjectSpan[] = [];
  for (const objId of sortedIds) {
    const e = entries.get(objId)!;
    const { start, end } = objectSpan(pdfBytes, objId, e.offset);
    spans.push({
      objId,
      generation: e.generation,
      byteOffset: start,
      byteEnd: end,
    });
  }
  return spans;
}
