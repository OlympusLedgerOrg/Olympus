// SPDX-License-Identifier: Apache-2.0

/** Segment-level redaction (ADR-0026/0028), object manifest, ADR-0029 object
 * classification + previews, and Olympus-owned redaction (producer side). */

import type { V3Bundle } from "../redactionBinding";
import { apiFetch } from "./core";

// ─── Segment-level redaction (ADR-0026 / ADR-0028) ────────────────────────────
//
// The producer selects SEGMENTS to hide by id — a segment is one PDF object
// (traditional or modern), one text line-block, or one OOXML package part. The
// original is committed with one Poseidon hiding leaf per segment. The redacted
// artifact's byte shape is FORMAT-DEPENDENT: in-place NUL-fill (length preserved)
// for traditional PDF and text; a canonically re-emitted container (Stored ZIP)
// for OOXML and modern PDFs (rebuilt traditional-xref) — those differ in bytes
// and length from the upload. In every case the committed leaf binds logical
// content (not a file offset), so each revealed segment's leaf still recomputes
// from the artifact. See `src-tauri/src/api/redaction/` + `src-tauri/src/zk/segment/`.

// ─── Object manifest (drives the producer object checklist) ────────────────────

/** One committed segment in a document's redaction manifest. */
export interface ManifestObject {
  /** Segment id (== `segmentId` in `revealedSegments`). PDF: the indirect-object
   *  id; text: the 0-based line-block index. */
  segmentId: number;
  /** Length in bytes of the segment's span in the original artifact. */
  byteLength: number;
  /** Producer-facing label — a text block's `"lines 12-18"`; `null` for PDF
   *  (the `segmentId` is itself the object's label there). */
  label: string | null;
}

/**
 * Commitment format of a redaction manifest (drives the selection UI).
 *
 * `pdf-textrun` has been reachable since the segmenter became a default feature,
 * so the server can return it here; it was missing from this union until the
 * describe support landed.
 */
export type RedactionFormat =
  "pdf-object" | "pdf-xref-stream" | "pdf-textrun" | "text-line" | "ooxml-part";

/**
 * Whether the producer UI calls `POST /redaction/describe` for this format.
 * Both PDF *object* schemes are supported since ADR-0029 A.5-1, and
 * `pdf-textrun` since B-3 — the last returns `segments[]` rather than
 * `objects[]`, so a caller must read the format before picking a field.
 * `text-line` and `ooxml-part` have no PDF structure to describe and the
 * endpoint fails closed on them.
 *
 * Mirrors the server-side match in `api::redaction::describe` — keep the two in
 * step, and prefer this over open-coding a format check at each call site.
 */
export function supportsDescribe(format: RedactionFormat): boolean {
  return format === "pdf-object" || format === "pdf-xref-stream" || format === "pdf-textrun";
}

/**
 * Whether describe returns a **word** listing (`segments[]`) rather than an
 * object listing (`objects[]`) for this format. The two drive different
 * selection affordances, and the id spaces are unrelated: an object id is a PDF
 * indirect-object number, a segment id is a position in the committed word ⧺
 * container sequence.
 */
export function describesWords(format: RedactionFormat): boolean {
  return format === "pdf-textrun";
}

/**
 * Whether the drag-box page renderer (ADR-0029 A.5-4) can display this format.
 *
 * Coextensive with [`supportsDescribe`] today — both PDF schemes, nothing else —
 * but deliberately a separate predicate, because the two answer different
 * questions. `supportsDescribe` asks whether the *server* can enumerate indirect
 * objects; this asks whether **pdf.js** can draw the bytes. Collapsing them into
 * one check would silently hand a `.docx` or a `.txt` to a PDF renderer the day
 * `describe` grows a non-PDF format, and the failure would surface as a broken
 * viewer rather than as the checklist fallback it should be.
 */
export function supportsRender(format: RedactionFormat): boolean {
  return format === "pdf-object" || format === "pdf-xref-stream";
}

/**
 * Response from GET /redaction/manifest/{contentHash}.
 * Server-side `#[serde(rename_all = "camelCase")]`.
 */
export interface RedactionManifestResponse {
  contentHash: string;
  /** Commitment format tag so the UI can render the right selection affordance. */
  format: RedactionFormat;
  originalRoot: string;
  objectCount: number;
  objects: ManifestObject[];
}

export interface RedactionManifestSelector {
  originalRoot?: string;
  shardId?: string;
}

/**
 * Fetch the committed segment manifest for an already-committed document so the
 * producer can pick which segments (PDF objects / text line-blocks) to hide.
 *
 * GET /redaction/manifest/{contentHash}
 *
 * 404 if the document is not on-ledger, or was committed as an unsupported /
 * opaque-binary (chunk) record that isn't object-redactable. Requires `redact`,
 * `write`, `ingest`, or `admin` scope.
 */
export function getRedactionManifest(
  contentHash: string,
  apiKey?: string,
  selector: RedactionManifestSelector = {},
): Promise<RedactionManifestResponse> {
  const headers: Record<string, string> = {};
  if (apiKey?.trim()) headers["X-API-Key"] = apiKey.trim();
  const params = new URLSearchParams();
  if (selector.originalRoot?.trim()) params.set("original_root", selector.originalRoot.trim());
  if (selector.shardId?.trim()) params.set("shard_id", selector.shardId.trim());
  const query = params.toString();
  return apiFetch<RedactionManifestResponse>(
    `/redaction/manifest/${contentHash}${query ? `?${query}` : ""}`,
    { headers, cache: "no-store" },
  );
}

/** One entry in `RedactionIssuerKeyResponse.history` (docs/key-rotation.md). */
export interface RedactionIssuerKeyHistoryEntry {
  ed25519PubkeyHex: string;
  /** RFC 3339 timestamp, or null if unbounded (the earliest recorded key). */
  validFrom: string | null;
  /** RFC 3339 timestamp, or null if this is the currently active key. */
  validUntil: string | null;
}

/** Response from GET /redaction/issuer-key (ADR-0030). */
export interface RedactionIssuerKeyResponse {
  /** Ed25519 verifying key (32-byte lowercase hex) that signs this instance's
   *  V3 redaction bundles. */
  ed25519PubkeyHex: string;
  /** Every ingest signing pubkey this instance has successfully
   *  *registered*, oldest first — not a guaranteed-complete record.
   *  Registration is best-effort at server startup, so even the current key
   *  (`ed25519PubkeyHex` above) can be absent here if its own registration
   *  hit a transient error. Treat a missing entry or an empty array as
   *  "unknown", never as "no prior keys existed" or "this cannot be the
   *  active key". Not yet surfaced in the audit UI. */
  history: RedactionIssuerKeyHistoryEntry[];
}

/**
 * Fetch this instance's Ed25519 bundle-signing public key so the audit UI can
 * pre-fill the trust anchor.
 *
 * GET /redaction/issuer-key (unauthenticated — the key is public by design).
 *
 * Convenience anchor only: it is self-reported by the producing instance, so an
 * auditor verifying a bundle from an untrusted source should still supply the
 * issuer key out-of-band rather than trust this value.
 */
export function getRedactionIssuerKey(): Promise<RedactionIssuerKeyResponse> {
  return apiFetch<RedactionIssuerKeyResponse>("/redaction/issuer-key", {
    cache: "no-store",
  });
}

// ─── ADR-0029 Phase A1/A2: object classification + previews ───────────────────

/** Stable classification tag from `POST /redaction/describe` (ADR-0029 §A). */
export type RedactionObjectKind =
  | "catalog"
  | "pages"
  | "page"
  | "content_stream"
  | "image"
  | "font"
  | "metadata"
  | "annotation"
  | "xobject_form"
  | "other";

/**
 * Where a committed object paints, in **PDF user space**: origin bottom-left,
 * y upwards, in points — NOT screen space. A canvas overlay must flip y against
 * the page height before hit-testing. Mirrors the Rust
 * `zk::pdf_placement::Placement` (ADR-0029 A.5-2).
 */
export interface RedactionPlacement {
  /** 1-based page this rectangle is on. */
  page: number;
  /** Left edge, in points from the page's left. */
  x: number;
  /** **Bottom** edge, in points from the page's bottom. */
  y: number;
  w: number;
  h: number;
}

/**
 * One classified, human-presentable committed object. Mirrors the Rust
 * `zk::pdf_describe::ObjectDescription` (`#[serde(rename_all = "camelCase")]`).
 * Presentation only — never part of the commitment (ADR-0029 §A).
 */
export interface RedactionObjectDescription {
  objId: number;
  byteLength: number;
  kind: RedactionObjectKind;
  /** Human label, e.g. "Page 1 — text", "Image 800×600 (DCTDecode)", "Font: Helvetica". */
  label: string;
  /** 1-based page number, if resolvable; else null. */
  page: number | null;
  /** Short extracted-text preview for content streams; else null. */
  preview: string | null;
  width: number | null;
  height: number | null;
  filter: string | null;
  baseFont: string | null;
  typeName: string | null;
  /**
   * Where this object paints — the input to the drag-box hit-test. Empty for
   * document-level objects with no position on any page, and for objects whose
   * geometry could not be resolved (fall back to the object checklist). An
   * image painted more than once has one entry per paint.
   */
  placements: RedactionPlacement[];
}

/**
 * One committed `pdf-textrun` segment. Mirrors the Rust
 * `zk::pdf_describe::SegmentDescription` (`#[serde(rename_all = "camelCase")]`).
 * Presentation only — never part of the commitment (ADR-0029 §A).
 *
 * The word format commits a partition of the artifact (RFC-0001), so both
 * hideable words and the container leaves that bind them are listed. Use
 * `redactable` rather than re-deriving the `segmentId < wordCount` boundary
 * here — the server owns that rule and the redact call enforces it.
 */
export interface RedactionSegmentDescription {
  segmentId: number;
  /** `word` — hideable text; `skeleton` / `object` — container, not hideable. */
  kind: "word" | "skeleton" | "object";
  redactable: boolean;
  /** The indirect object this segment lives in. */
  objId: number;
  /** 1-based page number, if resolvable; else null. */
  page: number | null;
  /** The word's decoded text (capped server-side); null for containers, and for
   * a word whose bytes do not decode to printable text — show the id alone. */
  text: string | null;
  byteLength: number;
}

/** Response from POST /redaction/describe (ADR-0029 Phase A1 + A.5 + B-3). */
export interface RedactionDescribeResponse {
  contentHash: string;
  format: RedactionFormat;
  /** Object listing — populated for the two object schemes, empty for `pdf-textrun`. */
  objectCount: number;
  objects: RedactionObjectDescription[];
  /** Segment listing — populated for `pdf-textrun`, empty for the object schemes. */
  segmentCount: number;
  segments: RedactionSegmentDescription[];
}

/**
 * Classify an already-committed PDF's objects into human labels + previews for
 * the producer UI (ADR-0029 Phase A1 endpoint; consumed by Phase A2).
 *
 * POST /redaction/describe — takes the original bytes (base64) + content_hash;
 * the server requires `BLAKE3(bytes) == content_hash` and an on-ledger manifest.
 * Only supported for the `pdf-object` commitment format. Presentation only:
 * nothing here is persisted or part of the commitment. Requires `redact`,
 * `write`, `ingest`, or `admin` scope.
 */
export function describeRedaction(
  originalBase64: string,
  contentHash: string,
  apiKey?: string,
  selector: RedactionManifestSelector = {},
): Promise<RedactionDescribeResponse> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey?.trim()) headers["X-API-Key"] = apiKey.trim();
  return apiFetch<RedactionDescribeResponse>("/redaction/describe", {
    method: "POST",
    headers,
    body: JSON.stringify({
      content_hash: contentHash,
      original_base64: originalBase64,
      ...(selector.originalRoot?.trim() ? { original_root: selector.originalRoot.trim() } : {}),
      ...(selector.shardId?.trim() ? { shard_id: selector.shardId.trim() } : {}),
    }),
  });
}

// ─── Olympus-owned redaction (producer side) ──────────────────────────────────

/**
 * Response from POST /redaction/redact (ADR-0030 V3). The server
 * `#[serde(rename_all = "camelCase")]`s the wrapper (`redactedBase64`,
 * `bundle`); `bundle` is the V3 signed-Merkle bundle, whose own fields are
 * snake_case (the `V3Bundle` type has no `rename_all`).
 */
export interface RedactDocumentResponse {
  /** Base64 of the redacted artifact. Byte shape is format-dependent: same length
   *  as the original (in-place NUL-fill) for traditional PDF and text; a
   *  canonically re-emitted container (different bytes/length) for OOXML and
   *  modern (xref-stream) PDFs. Revealed segments still recompute from it. */
  redactedBase64: string;
  /** The ADR-0030 V3 signed-Merkle bundle bound to the redacted artifact. */
  bundle: V3Bundle;
}

/**
 * Produce a binding-compatible redacted artifact from an already-committed
 * ORIGINAL document plus the segment ids to hide, and the matching ADR-0030 V3
 * signed-Merkle bundle.
 *
 * POST /redaction/redact
 *
 * The server owns the byte transformation, dispatched on the committed format:
 * in-place NUL-fill for traditional PDF / text (length + offsets preserved), or a
 * canonical re-emit for OOXML (Stored ZIP) and modern PDFs (rebuilt
 * traditional-xref). Either way the artifact binds to the committed original via
 * per-segment logical-content leaves — an unrelated re-saved document would not.
 *
 * The original MUST already be on-ledger: the server BLAKE3-hashes the uploaded
 * bytes and the bundle build fails if no committed manifest matches.
 * `recipientId` is an opaque field element (decimal string). Requires `redact`,
 * `write`, `ingest`, or `admin` scope.
 */
export function redactDocument(
  originalBase64: string,
  redactedObjIds: number[],
  recipientId: string,
  apiKey?: string,
  originalRoot?: string,
): Promise<RedactDocumentResponse> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey?.trim()) headers["X-API-Key"] = apiKey.trim();
  return apiFetch<RedactDocumentResponse>("/redaction/redact", {
    method: "POST",
    headers,
    body: JSON.stringify({
      original_base64: originalBase64,
      ...(originalRoot?.trim() ? { original_root: originalRoot.trim() } : {}),
      redacted_obj_ids: redactedObjIds,
      recipient_id: recipientId,
    }),
    cache: "no-store",
  });
}
