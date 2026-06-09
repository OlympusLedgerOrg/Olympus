/**
 * useRedactionCreate — producer side of the object-level redaction flow (ADR-0026).
 *
 * Mirror image of `useRedactionAudit` (the recipient/verifier): here the
 * *issuer* uploads the ORIGINAL (already-committed) PDF, fetches its committed
 * object manifest, checks the indirect objects to hide, and gets back a
 * binding-compatible redacted artifact + the `redaction_validity` bundle.
 *
 * Why the server owns the byte transformation: the object circuit binds a
 * redacted file to the committed original only when the non-redacted objects
 * are byte-identical and the redacted objects are zero-filled in place. That
 * holds exactly for what `POST /redaction/redact` produces — an externally
 * re-saved document re-serializes and never binds. The object scheme is for
 * PDFs (binary); the producer hashes the uploaded bytes client-side only to
 * look up the committed manifest (`GET /redaction/manifest/{contentHash}`).
 *
 * The pre-send binding self-check that the chunk path ran is intentionally
 * dropped here: an object-level recompute needs the FE-4 TS Pedersen path, and
 * the server proof + `/zk/verify` are authoritative until then. Wiring the old
 * chunk recompute against object bundles would always fail.
 */
import { useCallback, useRef, useState } from "react";
import {
  getRedactionManifest,
  redactDocument,
  type RedactDocumentResponse,
  type RedactionManifestResponse,
} from "../lib/api";
import { bytesToBase64, base64ToBytes } from "../lib/bytes";
import { hashBytes } from "../lib/blake3";
import { getStoredApiKey } from "../lib/storage";

export type RedactionCreateStage =
  | "idle"
  | "loading_manifest"
  | "redacting"
  | "done"
  | "error";

export interface RedactionCreateState {
  stage: RedactionCreateStage;
  fileName: string | null;
  fileSize: number;
  /** BLAKE3 content hash of the uploaded bytes (== the on-ledger content_hash). */
  contentHash: string | null;
  /** Committed object manifest for the loaded document; `null` until fetched. */
  manifest: RedactionManifestResponse | null;
  /** Indirect-object ids the operator has checked to hide. */
  selectedIds: number[];
  recipientId: string;
  result: RedactDocumentResponse | null;
  error: string | null;
}

const INITIAL: RedactionCreateState = {
  stage: "idle",
  fileName: null,
  fileSize: 0,
  contentHash: null,
  manifest: null,
  selectedIds: [],
  recipientId: "",
  result: null,
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
  // Separate token for in-flight redact() calls: a reset or a new file
  // invalidates a pending response so a stale result/error can't overwrite the
  // current session's state (the network round-trip outlives the click).
  const redactReqId = useRef(0);

  const reset = useCallback(() => {
    bytesRef.current = null;
    fileReqId.current += 1;
    redactReqId.current += 1;
    setState(INITIAL);
  }, []);

  const onFile = useCallback(async (file: File) => {
    const myReq = ++fileReqId.current;
    // A new file invalidates any redact response still in flight.
    redactReqId.current += 1;
    // Operator-level settings persist across a file swap.
    const recipientId = stateRef.current.recipientId;
    try {
      const buf = new Uint8Array(await file.arrayBuffer());
      if (fileReqId.current !== myReq) return;
      bytesRef.current = buf;
      // Plain BLAKE3 of the raw bytes — matches the server's content_hash
      // (blake3::hash(bytes)) so the manifest lookup resolves the same record.
      setState({
        ...INITIAL,
        stage: "loading_manifest",
        fileName: file.name,
        fileSize: buf.length,
        recipientId,
      });
      const contentHash = await hashBytes(buf);
      if (fileReqId.current !== myReq) return;
      const apiKey = getStoredApiKey() || undefined;
      const manifest = await getRedactionManifest(contentHash, apiKey);
      if (fileReqId.current !== myReq) return;
      setState((prev) => ({
        ...prev,
        stage: "idle",
        contentHash,
        manifest,
        selectedIds: [],
        error: null,
      }));
    } catch (e) {
      if (fileReqId.current !== myReq) return;
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, []);

  /** Toggle whether an object id is in the redacted (hidden) set. */
  const toggleId = useCallback((id: number) => {
    setState((prev) => {
      const has = prev.selectedIds.includes(id);
      const selectedIds = has
        ? prev.selectedIds.filter((x) => x !== id)
        : [...prev.selectedIds, id].sort((a, b) => a - b);
      // Mutating the selection invalidates a previous result.
      return {
        ...prev,
        selectedIds,
        error: null,
        result: null,
        stage: prev.stage === "done" ? "idle" : prev.stage,
      };
    });
  }, []);

  const clearSelection = useCallback(() => {
    setState((prev) => ({
      ...prev,
      selectedIds: [],
      result: null,
      error: null,
      stage: prev.stage === "done" ? "idle" : prev.stage,
    }));
  }, []);

  const setRecipientId = useCallback((recipientId: string) => {
    setState((prev) => ({ ...prev, recipientId, error: null }));
  }, []);

  const redact = useCallback(async () => {
    const bytes = bytesRef.current;
    const s = stateRef.current;

    // Synchronous validation against the live state.
    if (!bytes || s.fileSize === 0 || !s.manifest) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: "Load an original document and wait for its object manifest first.",
      }));
      return;
    }
    if (s.selectedIds.length === 0) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: "Select at least one object to redact.",
      }));
      return;
    }
    if (s.selectedIds.length >= s.manifest.objectCount) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: "Every object is selected — nothing would be revealed. Hide fewer objects.",
      }));
      return;
    }
    if (!s.recipientId.trim()) {
      setState((prev) => ({ ...prev, stage: "error", error: "Recipient ID is required." }));
      return;
    }

    const myReq = ++redactReqId.current;
    setState((prev) => ({ ...prev, stage: "redacting", error: null, result: null }));
    try {
      const apiKey = getStoredApiKey() || undefined;
      const originalBase64 = bytesToBase64(bytes);
      const result = await redactDocument(
        originalBase64,
        [...s.selectedIds],
        s.recipientId.trim(),
        apiKey,
      );
      // A reset or new file during the round-trip supersedes this response.
      if (redactReqId.current !== myReq) return;
      setState((prev) => ({ ...prev, stage: "done", result, error: null }));
    } catch (e) {
      // Drop the error too if this call was superseded.
      if (redactReqId.current !== myReq) return;
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

  return {
    ...state,
    onFile,
    toggleId,
    clearSelection,
    setRecipientId,
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
