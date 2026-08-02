/**
 * useRedactionCreate — producer side of the object-level redaction flow (ADR-0026).
 *
 * Mirror image of `useRedactionAudit` (the recipient/verifier): here the
 * *issuer* uploads the ORIGINAL (already-committed) PDF, fetches its committed
 * object manifest, checks the indirect objects to hide, and gets back a
 * binding-compatible redacted artifact + the ADR-0030 V3 signed-Merkle bundle.
 *
 * Two code paths:
 *
 *  • **Tauri (desktop)** — path-based: the file path is handed to Rust via
 *    `pick_file_path` or `file-dropped` native drag-drop event. Rust reads the
 *    file directly, hashes it, calls Axum, saves the redacted artifact via a
 *    native save dialog, and streams real-percent progress via an IPC Channel.
 *    No base64 encoding ever happens in JavaScript.
 *
 *  • **Browser fallback** — the original byte-based flow: `<input type="file">`
 *    reads bytes into JS, BLAKE3 hashes client-side, `bytesToBase64` encodes
 *    before POSTing, and `triggerDownload` saves the result. Used by vitest +
 *    Vite dev preview.
 */
import { useCallback, useRef, useState } from "react";
import {
  getRedactionManifest,
  describeRedaction,
  redactDocument,
  isTauri,
  tauriInvoke,
  supportsDescribe,
  supportsRender,
  type RedactDocumentResponse,
  type RedactionDescribeResponse,
  type RedactionManifestResponse,
  type RedactionObjectDescription,
} from "../lib/api";
import type { V3Bundle } from "../lib/redactionBinding";
import { bytesToBase64, base64ToBytes } from "../lib/bytes";
import { hashBytes } from "../lib/blake3";
import { getStoredApiKey } from "../lib/storage";

export type RedactionCreateStage = "idle" | "loading_manifest" | "redacting" | "done" | "error";

export interface RedactionCreateState {
  stage: RedactionCreateStage;
  fileName: string | null;
  fileSize: number;
  /** BLAKE3 content hash of the uploaded bytes (== the on-ledger content_hash). */
  contentHash: string | null;
  /** Committed object manifest for the loaded document; `null` until fetched. */
  manifest: RedactionManifestResponse | null;
  /** ADR-0029 A2: per-object classifications/labels/previews/placements for the
   *  producer checklist (from `POST /redaction/describe`, reached natively via
   *  `describe_by_path` on the Tauri path). `null` when unavailable — a format
   *  the endpoint does not describe (see `supportsDescribe`) or a describe
   *  failure — in which case the UI falls back to the plain id/size listing. */
  descriptions: RedactionObjectDescription[] | null;
  /** Indirect-object ids the operator has checked to hide. */
  selectedIds: number[];
  recipientId: string;
  result: RedactDocumentResponse | null;
  error: string | null;
  /** Tauri path: 0-100 during redact_by_path, null otherwise. */
  progress: number | null;
  /** Tauri path: filesystem path where the redacted file was saved. */
  savedRedactedPath: string | null;
  /** Tauri path: full native path of the loaded file (used by redact_by_path). */
  filePath: string | null;
}

const INITIAL: RedactionCreateState = {
  stage: "idle",
  fileName: null,
  fileSize: 0,
  contentHash: null,
  manifest: null,
  descriptions: null,
  selectedIds: [],
  recipientId: "",
  result: null,
  error: null,
  progress: null,
  savedRedactedPath: null,
  filePath: null,
};

export function useRedactionCreate() {
  const [state, setState] = useState<RedactionCreateState>(INITIAL);
  // Raw original bytes kept in a ref — they can be multi-MB and never need to
  // trigger a re-render. Read on submit + for download (browser path only).
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

  // ── Browser path: file comes in as a JS File object ────────────────────────

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
      // ADR-0029 A2: enrich the checklist with object classifications + labels +
      // previews + placements. Best-effort — a failure leaves `descriptions`
      // null so the UI falls back to the plain id/size listing. The bytes are
      // already in hand on this (browser) path, so no extra round-trip to disk.
      let descriptions: RedactionObjectDescription[] | null = null;
      if (supportsDescribe(manifest.format)) {
        try {
          const desc = await describeRedaction(bytesToBase64(buf), contentHash, apiKey, {
            originalRoot: manifest.originalRoot,
          });
          if (fileReqId.current !== myReq) return;
          descriptions = desc.objects;
        } catch {
          descriptions = null; // non-fatal — plain listing remains available
        }
      }
      if (fileReqId.current !== myReq) return;
      setState((prev) => ({
        ...prev,
        stage: "idle",
        contentHash,
        manifest,
        descriptions,
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

  // ── Tauri path: file comes in as a native path ──────────────────────────────
  // Called by the native drag-drop listener in RedactTab and by the
  // pick_file_path Tauri command. No bytes cross the JS boundary; hashing is
  // done in Rust via hash_file_for_manifest.

  const onFilePath = useCallback(async (path: string, name: string) => {
    const myReq = ++fileReqId.current;
    redactReqId.current += 1;
    // This path owns `bytesRef` for the rest of the load (see the
    // read_file_for_render step below). Drop any previous buffer up front so a
    // failure part-way through leaves no stale bytes behind — `isTauri()` keeps
    // the browser and desktop entry points mutually exclusive today, so this is
    // defence in depth rather than a fix for a reachable bug.
    bytesRef.current = null;
    const recipientId = stateRef.current.recipientId;
    try {
      setState({
        ...INITIAL,
        stage: "loading_manifest",
        fileName: name,
        filePath: path,
        recipientId,
      });
      const contentHash = await tauriInvoke<string>("hash_file_for_manifest", { path });
      if (!contentHash || fileReqId.current !== myReq) return;
      const apiKey = getStoredApiKey() || undefined;
      const manifest = await getRedactionManifest(contentHash, apiKey);
      if (fileReqId.current !== myReq) return;
      // ADR-0029 A.5-3: the desktop path has no bytes in JS, so it used to get
      // no labels at all. `describe_by_path` reads and encodes the file in Rust
      // and calls the endpoint natively, giving this path the same classifications
      // + previews + placements the browser path has. Best-effort, exactly as
      // there: a failure leaves the plain id/size listing intact.
      let descriptions: RedactionObjectDescription[] | null = null;
      if (supportsDescribe(manifest.format)) {
        try {
          const desc = await tauriInvoke<RedactionDescribeResponse>("describe_by_path", {
            path,
            originalRoot: manifest.originalRoot ?? null,
            shardId: null,
            apiKey: apiKey ?? null,
          });
          if (fileReqId.current !== myReq) return;
          descriptions = desc?.objects ?? null;
        } catch {
          descriptions = null; // non-fatal — plain listing remains available
        }
      }
      // ADR-0029 A.5-4 (desktop): pdf.js runs in the webview, so the page render
      // is the one thing on this path that genuinely needs the bytes in JS.
      // `read_file_for_render` hands them over as raw binary under its own
      // display-only cap. Only worth the copy when there is something to draw a
      // box *over*, hence the `descriptions` guard — and best-effort like
      // `describe_by_path`: on failure `documentBytes` stays null and the UI
      // falls back to the checklist, which works on the same document.
      if (descriptions && supportsRender(manifest.format)) {
        try {
          const buf = await tauriInvoke<ArrayBuffer>("read_file_for_render", { path });
          if (fileReqId.current !== myReq) return;
          // `tauriInvoke` resolves to null outside the webview; this path only
          // runs inside it, but the type is honest so handle it rather than
          // constructing a Uint8Array from null.
          bytesRef.current = buf ? new Uint8Array(buf) : null;
        } catch {
          bytesRef.current = null; // non-fatal — checklist remains available
        }
      }
      if (fileReqId.current !== myReq) return;
      // `bytesRef` is written before this setState on purpose: `documentBytes`
      // is a ref read at render time, so any render that observes this new
      // `contentHash` must already observe the matching buffer.
      setState((prev) => ({
        ...prev,
        stage: "idle",
        contentHash,
        manifest,
        descriptions,
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
        savedRedactedPath: null,
        stage: prev.stage === "done" ? "idle" : prev.stage,
      };
    });
  }, []);

  const clearSelection = useCallback(() => {
    setState((prev) => ({
      ...prev,
      selectedIds: [],
      result: null,
      savedRedactedPath: null,
      error: null,
      stage: prev.stage === "done" ? "idle" : prev.stage,
    }));
  }, []);

  const setRecipientId = useCallback((recipientId: string) => {
    setState((prev) => ({ ...prev, recipientId, error: null }));
  }, []);

  const redact = useCallback(async () => {
    const s = stateRef.current;

    // Synchronous validation against the live state.
    if (!s.manifest || (s.fileSize === 0 && !s.filePath)) {
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
    // Determinate progress (0→100 via the IPC channel) only on the Tauri path;
    // the browser path has no progress signal, so leave progress null to render
    // the indeterminate "Redacting…" state instead of a bar frozen at 0%.
    const useTauri = isTauri() && !!s.filePath;
    setState((prev) => ({
      ...prev,
      stage: "redacting",
      progress: useTauri ? 0 : null,
      error: null,
      result: null,
      savedRedactedPath: null,
    }));

    try {
      const apiKey = getStoredApiKey() || undefined;

      if (useTauri) {
        // ── Tauri path: Rust reads file, saves result, emits progress ──────
        const { invoke, Channel } = await import("@tauri-apps/api/core");
        const channel = new Channel<{ percent: number; label: string }>();
        channel.onmessage = (msg) => {
          if (redactReqId.current !== myReq) return;
          setState((prev) => ({ ...prev, progress: msg.percent }));
        };

        const tauriResult = await invoke<{
          bundle: V3Bundle;
          savedPath: string | null;
        }>("redact_by_path", {
          path: s.filePath,
          redactedObjIds: [...s.selectedIds],
          recipientId: s.recipientId.trim(),
          originalRoot: s.manifest?.originalRoot ?? null,
          apiKey: apiKey ?? null,
          onProgress: channel,
        });

        if (redactReqId.current !== myReq) return;
        // Synthesise a RedactDocumentResponse with an empty redactedBase64
        // (the artifact is already on disk at savedPath, not in JS memory).
        const result: RedactDocumentResponse = {
          redactedBase64: "",
          bundle: tauriResult.bundle,
        };
        setState((prev) => ({
          ...prev,
          stage: "done",
          progress: 100,
          result,
          savedRedactedPath: tauriResult.savedPath,
          error: null,
        }));
      } else {
        // ── Browser fallback path: encode bytes in JS, triggerDownload ─────
        const bytes = bytesRef.current;
        if (!bytes || s.fileSize === 0) {
          setState((prev) => ({
            ...prev,
            stage: "error",
            progress: null,
            error: "No file loaded.",
          }));
          return;
        }
        const originalBase64 = bytesToBase64(bytes);
        const result = await redactDocument(
          originalBase64,
          [...s.selectedIds],
          s.recipientId.trim(),
          apiKey,
          s.manifest?.originalRoot,
        );
        if (redactReqId.current !== myReq) return;
        setState((prev) => ({ ...prev, stage: "done", progress: null, result, error: null }));
      }
    } catch (e) {
      if (redactReqId.current !== myReq) return;
      setState((prev) => ({
        ...prev,
        stage: "error",
        progress: null,
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, []);

  /** Download the redacted artifact.
   *  Tauri: no-op (already saved to disk by Rust).
   *  Browser: `<a download>` blob-URL trick. */
  const downloadRedacted = useCallback(() => {
    const s = stateRef.current;
    if (!s.result) return;
    if (isTauri()) return; // file already on disk at savedRedactedPath
    const bytes = base64ToBytes(s.result.redactedBase64);
    const name = s.fileName ? `redacted-${s.fileName}` : "redacted.bin";
    triggerDownload(new Blob([bytes], { type: "application/octet-stream" }), name);
  }, []);

  /** Download the redaction bundle JSON.
   *  Tauri: native save dialog via save_text_to_disk.
   *  Browser: `<a download>` blob-URL trick. */
  const downloadBundle = useCallback(async () => {
    const s = stateRef.current;
    if (!s.result) return;
    const json = JSON.stringify(s.result.bundle, null, 2);
    const base = s.fileName ? s.fileName.replace(/\.[^.]+$/, "") : "redaction";
    const hint = `${base}.redaction.json`;
    if (isTauri()) {
      await tauriInvoke("save_text_to_disk", { content: json, filenameHint: hint });
    } else {
      triggerDownload(new Blob([json], { type: "application/json" }), hint);
    }
  }, []);

  return {
    ...state,
    /** The loaded document's bytes, for **display only** (ADR-0029 A.5-4 page
     *  render). Populated on both paths: the browser path already holds them for
     *  hashing, and the Tauri path fetches them through `read_file_for_render`
     *  once there are descriptions to draw a box over. `null` when the format is
     *  not renderable, when that read failed, or before a file is loaded — all of
     *  which fall back to the object checklist. Read through the ref rather than
     *  state: every path that sets it calls `setState` immediately after, so the
     *  render that observes a new `contentHash` also observes the matching
     *  buffer. */
    documentBytes: bytesRef.current,
    onFile,
    onFilePath,
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
