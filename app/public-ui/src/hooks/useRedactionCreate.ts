/**
 * useRedactionCreate — producer side of the redaction flow.
 *
 * Mirror image of `useRedactionAudit` (the recipient/verifier): here the
 * *issuer* uploads the ORIGINAL (already-committed) document, marks byte ranges
 * to hide, and gets back a binding-compatible redacted artifact + the
 * `redaction_validity` bundle.
 *
 * Why the server owns the byte transformation: the chunk circuit binds a
 * redacted file to the committed original only when every revealed chunk is
 * byte-identical at the same offset. That holds only for an in-place, same-
 * length blank — exactly what `POST /redaction/redact` produces. An externally
 * re-saved document re-serializes and never binds, which is the whole reason
 * "redaction didn't work" before this path existed. Text-oriented by design
 * (text / CSV / JSON / logs).
 *
 * The mask is computed client-side too (`computeRevealMask`, pinned to the Rust
 * `redact_chunk_aligned`) so the operator sees the whole-chunk over-redaction
 * (≈ 1/16 of the file per touched chunk) BEFORE submitting.
 */
import { useCallback, useRef, useState } from "react";
import { redactDocument, type RedactDocumentResponse, type RedactByteRange } from "../lib/api";
import { bytesToBase64, base64ToBytes } from "../lib/bytes";
import { verifyRedactionBindingJs } from "../lib/redactionBinding";
import { getStoredApiKey } from "../lib/storage";

/** Circuit-fixed chunk count — must match `crate::zk::witness::redaction::MAX_LEAVES`. */
export const MAX_LEAVES = 16;

export type RedactionCreateStage = "idle" | "redacting" | "done" | "error";

/**
 * Reveal mask the server would compute for `n` bytes and `ranges`, mirroring
 * `crate::zk::redact::redact_chunk_aligned` exactly: `chunk_size = ceil(n/16)`,
 * a chunk is hidden (`0`) iff it overlaps any redacted byte.
 *
 * Exported for the conformance test that pins it to the Rust reference.
 */
export function computeRevealMask(n: number, ranges: RedactByteRange[]): number[] {
  const mask = new Array<number>(MAX_LEAVES).fill(1);
  if (n <= 0) return mask;
  const chunkSize = Math.max(Math.ceil(n / MAX_LEAVES), 1);
  for (let i = 0; i < MAX_LEAVES; i++) {
    const cstart = Math.min(i * chunkSize, n);
    const cend = Math.min(cstart + chunkSize, n);
    const touched =
      cstart < cend && ranges.some((r) => r.start < cend && cstart < r.end);
    if (touched) mask[i] = 0;
  }
  return mask;
}

/** Chunks holding real bytes (the rest are zero-padding when n < 16). */
export function populatedChunks(n: number): number {
  if (n <= 0) return 0;
  const chunkSize = Math.max(Math.ceil(n / MAX_LEAVES), 1);
  return Math.ceil(n / chunkSize);
}

/**
 * Per-chunk disclosure status — finer than the reveal mask.
 *
 * The circuit attests at *chunk* granularity but the redactor blanks at *range*
 * granularity, so a chunk that overlaps a redacted range can still contain
 * surviving bytes the recipient can read but the proof does NOT vouch for:
 *   - `"revealed"`  — untouched; bytes present AND attested.
 *   - `"full"`      — every byte in the chunk falls inside a redacted range; blanked.
 *   - `"partial"`   — touched, but some bytes survive (shown to the recipient,
 *                     not bound by the proof). Surfaced in the UI so the issuer
 *                     understands what's actually disclosed vs attested.
 */
export type ChunkStatus = "revealed" | "full" | "partial";

/**
 * Classify each of the 16 chunks as revealed / fully-blanked / partially-blanked
 * for the given byte length and ranges. Mirrors the same `ceil(n/16)` geometry
 * as {@link computeRevealMask}; a chunk is `full` only when the union of ranges
 * covers its entire byte span.
 */
export function computeChunkStatus(n: number, ranges: RedactByteRange[]): ChunkStatus[] {
  const status = new Array<ChunkStatus>(MAX_LEAVES).fill("revealed");
  if (n <= 0) return status;
  const chunkSize = Math.max(Math.ceil(n / MAX_LEAVES), 1);
  const sorted = [...ranges].sort((a, b) => a.start - b.start);
  for (let i = 0; i < MAX_LEAVES; i++) {
    const cstart = Math.min(i * chunkSize, n);
    const cend = Math.min(cstart + chunkSize, n);
    if (cstart >= cend) continue; // empty padding chunk stays revealed
    const touched = sorted.some((r) => r.start < cend && cstart < r.end);
    if (!touched) continue;
    // Walk the sorted ranges to see if they cover [cstart, cend) with no gap.
    let pos = cstart;
    for (const r of sorted) {
      if (r.start > pos) break; // gap before pos — not fully covered
      if (r.end > pos) pos = r.end;
      if (pos >= cend) break;
    }
    status[i] = pos >= cend ? "full" : "partial";
  }
  return status;
}

export interface RedactionCreateState {
  stage: RedactionCreateStage;
  fileName: string | null;
  fileSize: number;
  /** UTF-8 decode of the file for the preview; `null` if it isn't valid text. */
  fileText: string | null;
  ranges: RedactByteRange[];
  recipientId: string;
  /** Fill byte 0–255 as a string; empty = server default (0x00). */
  fill: string;
  result: RedactDocumentResponse | null;
  /**
   * Self-check after issuance: does the returned redacted artifact actually
   * re-derive the bundle's `redactedCommitment`? `null` until a redact runs (or
   * if the check couldn't complete); `true`/`false` is the verify-before-send
   * result. Lets the issuer confirm the bundle binds before handing it off.
   */
  bindingValid: boolean | null;
  error: string | null;
}

const INITIAL: RedactionCreateState = {
  stage: "idle",
  fileName: null,
  fileSize: 0,
  fileText: null,
  ranges: [],
  recipientId: "",
  fill: "",
  result: null,
  bindingValid: null,
  error: null,
};

export function useRedactionCreate() {
  const [state, setState] = useState<RedactionCreateState>(INITIAL);
  // Raw original bytes kept in a ref — they can be multi-MB and never need to
  // trigger a re-render. Read on submit + for download.
  const bytesRef = useRef<Uint8Array | null>(null);
  // Always-current snapshot of state so async callbacks read fresh values
  // without listing every field as a dep.
  const stateRef = useRef(state);
  stateRef.current = state;
  const fileReqId = useRef(0);

  const reset = useCallback(() => {
    bytesRef.current = null;
    fileReqId.current += 1;
    setState(INITIAL);
  }, []);

  const onFile = useCallback(async (file: File) => {
    const myReq = ++fileReqId.current;
    // Operator-level settings persist across a file swap.
    const recipientId = stateRef.current.recipientId;
    const fill = stateRef.current.fill;
    try {
      const buf = new Uint8Array(await file.arrayBuffer());
      if (fileReqId.current !== myReq) return;
      bytesRef.current = buf;
      // Decode as UTF-8 for the preview; `fatal` makes invalid bytes throw so
      // binary files fall back to "no preview" instead of mojibake. The byte
      // ranges are still computed against the raw bytes either way.
      let text: string | null = null;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(buf);
      } catch {
        text = null;
      }
      setState({
        ...INITIAL,
        fileName: file.name,
        fileSize: buf.length,
        fileText: text,
        recipientId,
        fill,
      });
    } catch (e) {
      if (fileReqId.current !== myReq) return;
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, []);

  const addRange = useCallback((start: number, end: number) => {
    setState((prev) => {
      const n = prev.fileSize;
      if (!Number.isInteger(start) || !Number.isInteger(end)) {
        return { ...prev, error: "Range bounds must be whole numbers." };
      }
      if (start < 0 || end > n) {
        return { ...prev, error: `Range [${start}, ${end}) is out of bounds for ${n} bytes.` };
      }
      if (start >= end) {
        return { ...prev, error: `Range [${start}, ${end}) is empty (start ≥ end).` };
      }
      // Skip exact duplicates; otherwise append (server tolerates overlap).
      if (prev.ranges.some((r) => r.start === start && r.end === end)) {
        return { ...prev, error: null };
      }
      const ranges = [...prev.ranges, { start, end }].sort((a, b) => a.start - b.start);
      return { ...prev, ranges, error: null, result: null, stage: "idle" };
    });
  }, []);

  const removeRange = useCallback((idx: number) => {
    setState((prev) => ({
      ...prev,
      ranges: prev.ranges.filter((_, i) => i !== idx),
      result: null,
      stage: prev.stage === "done" ? "idle" : prev.stage,
    }));
  }, []);

  const clearRanges = useCallback(() => {
    setState((prev) => ({ ...prev, ranges: [], result: null, error: null, stage: "idle" }));
  }, []);

  const setRecipientId = useCallback((recipientId: string) => {
    setState((prev) => ({ ...prev, recipientId, error: null }));
  }, []);

  const setFill = useCallback((fill: string) => {
    setState((prev) => ({ ...prev, fill, error: null }));
  }, []);

  const redact = useCallback(async () => {
    const bytes = bytesRef.current;
    const s = stateRef.current;

    // Synchronous validation against the live state.
    if (!bytes || s.fileSize === 0) {
      setState((prev) => ({ ...prev, stage: "error", error: "Load an original document first." }));
      return;
    }
    if (s.ranges.length === 0) {
      setState((prev) => ({ ...prev, stage: "error", error: "Add at least one byte range to redact." }));
      return;
    }
    if (!s.recipientId.trim()) {
      setState((prev) => ({ ...prev, stage: "error", error: "Recipient ID is required." }));
      return;
    }
    // AllRedacted guard mirroring the server: every populated chunk hidden ⇒
    // nothing is revealed.
    const mask = computeRevealMask(s.fileSize, s.ranges);
    const pop = populatedChunks(s.fileSize);
    if (pop > 0 && mask.slice(0, pop).every((m) => m === 0)) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: "Every chunk is redacted — nothing would be revealed. Hide less of the file.",
      }));
      return;
    }
    let fill: number | undefined;
    if (s.fill.trim() !== "") {
      const f = Number(s.fill);
      if (!Number.isInteger(f) || f < 0 || f > 255) {
        setState((prev) => ({ ...prev, stage: "error", error: "Fill byte must be an integer 0–255." }));
        return;
      }
      fill = f;
    }

    setState((prev) => ({ ...prev, stage: "redacting", error: null, result: null, bindingValid: null }));
    try {
      const apiKey = getStoredApiKey() || undefined;
      const originalBase64 = bytesToBase64(bytes);
      const result = await redactDocument(
        originalBase64,
        s.ranges,
        s.recipientId.trim(),
        fill,
        apiKey,
      );

      // Verify-before-send: re-derive the bundle's redactedCommitment from the
      // returned artifact (same pure-JS path the recipient/auditor uses) so the
      // issuer never ships a bundle that doesn't bind. A null result (e.g. the
      // binding helper threw) is reported as "unchecked", not a failure.
      let bindingValid: boolean | null = null;
      try {
        const redactedBytes = base64ToBytes(result.redactedBase64);
        const expectedCommitment = result.bundle.publicSignals[2]; // redactedCommitment
        bindingValid = await verifyRedactionBindingJs(
          redactedBytes,
          result.bundle.revealMask,
          expectedCommitment,
        );
      } catch {
        bindingValid = null;
      }

      setState((prev) => ({ ...prev, stage: "done", result, bindingValid, error: null }));
    } catch (e) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, []);

  /** Trigger a browser download of the redacted artifact (original filename). */
  const downloadRedacted = useCallback(() => {
    const s = stateRef.current;
    if (!s.result) return;
    const bytes = base64ToBytes(s.result.redactedBase64);
    const name = s.fileName ? `redacted-${s.fileName}` : "redacted.bin";
    triggerDownload(new Blob([bytes], { type: "application/octet-stream" }), name);
  }, []);

  /** Trigger a browser download of the redaction bundle JSON. */
  const downloadBundle = useCallback(() => {
    const s = stateRef.current;
    if (!s.result) return;
    const json = JSON.stringify(s.result.bundle, null, 2);
    const base = s.fileName ? s.fileName.replace(/\.[^.]+$/, "") : "redaction";
    triggerDownload(new Blob([json], { type: "application/json" }), `${base}.redaction.json`);
  }, []);

  /** Live preview of which chunks the current ranges would hide. */
  const previewMask = computeRevealMask(state.fileSize, state.ranges);
  /** Live per-chunk disclosure status (revealed / full / partial) for the strip. */
  const previewStatus = computeChunkStatus(state.fileSize, state.ranges);

  return {
    ...state,
    previewMask,
    previewStatus,
    onFile,
    addRange,
    removeRange,
    clearRanges,
    setRecipientId,
    setFill,
    redact,
    downloadRedacted,
    downloadBundle,
    reset,
  };
}

/** Save a Blob to disk via a transient object-URL anchor click. */
function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke on the next tick so the click's navigation has consumed the URL.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
