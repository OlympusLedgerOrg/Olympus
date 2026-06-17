/**
 * useRedactionAudit — in-app offline verifier for the ADR-0030 V3 signed-Merkle
 * redaction bundle (Phase 3).
 *
 * The recipient holds three things, all delivered out-of-band by the issuer:
 *   1. The redacted artifact file — its raw bytes drive revealed-segment
 *      reconstruction. (Also BLAKE3-hashed in-browser so the operator can see
 *      they loaded the file they think they did.)
 *   2. A V3 bundle JSON — `{original_root, format, segment_count, recipient_id,
 *      segments, nullifier, signature_hex, ...}`.
 *   3. The issuer's Ed25519 public key (hex) — the trust anchor the signature
 *      is checked against.
 *
 * The audit is a SINGLE local cryptographic check — `verifyRedactionBundleV3`
 * (`lib/redactionBinding.ts`, a byte-for-byte port of the canonical Rust
 * encoders / the JS reference verifier): structural rules + per-segment
 * canonical-form rejects + variable-depth fold == original_root + Ed25519
 * signature + nullifier. No server round-trip and no Tauri IPC — the same code
 * runs in the desktop webview and the read-only Tor public_router web auditor.
 */
import { useCallback, useRef, useState } from "react";
import { hashFile } from "../lib/blake3";
import {
  verifyRedactionBundleV3,
  type V3Bundle,
  type V3Segment,
} from "../lib/redactionBinding";

export type RedactionAuditStage =
  | "idle"
  | "hashing"
  | "ready"
  | "verifying"
  | "done"
  | "error";

const FORMAT_TAGS = new Set([
  "pdf-object",
  "pdf-xref-stream",
  "text-line",
  "ooxml-part",
]);

/**
 * Parse + minimally shape-check a dropped JSON object into a `V3Bundle`. The
 * heavy cryptographic + canonical-form validation lives in
 * `verifyRedactionBundleV3`; this only rejects obviously-malformed JSON early so
 * the operator gets a clear message before the audit runs.
 */
function parseV3Bundle(raw: unknown): V3Bundle {
  if (!raw || typeof raw !== "object") {
    throw new Error("Bundle must be a JSON object.");
  }
  const obj = raw as Record<string, unknown>;

  // Reject obvious legacy (V2 redaction_validity) bundles with a clear message.
  if (obj.circuit === "redaction_validity" || obj.proof_json || obj.proofJson) {
    throw new Error(
      "This looks like a legacy redaction_validity (V2) proof bundle. The " +
        "redaction scheme is now ADR-0030 V3 signed-Merkle — re-issue the bundle.",
    );
  }

  const format = obj.format;
  if (typeof format !== "string" || !FORMAT_TAGS.has(format)) {
    throw new Error(
      "Bundle is missing a valid 'format' tag (one of: pdf-object, " +
        "pdf-xref-stream, text-line, ooxml-part).",
    );
  }
  if (typeof obj.original_root !== "string") {
    throw new Error("Bundle is missing an 'original_root' string.");
  }
  if (typeof obj.recipient_id !== "string") {
    throw new Error("Bundle is missing a 'recipient_id' string.");
  }
  if (typeof obj.segment_count !== "number") {
    throw new Error("Bundle is missing a numeric 'segment_count'.");
  }
  if (!Array.isArray(obj.segments)) {
    throw new Error("Bundle is missing a 'segments' array.");
  }
  if (typeof obj.signature_hex !== "string") {
    throw new Error("Bundle is missing a 'signature_hex' string.");
  }
  if (typeof obj.nullifier !== "string") {
    throw new Error("Bundle is missing a 'nullifier' string.");
  }

  return {
    original_root: obj.original_root,
    format,
    segment_count: obj.segment_count,
    recipient_id: obj.recipient_id,
    segments: obj.segments as V3Segment[],
    nullifier: obj.nullifier,
    signature_hex: obj.signature_hex,
    table_hash_hex:
      typeof obj.table_hash_hex === "string" ? obj.table_hash_hex : undefined,
    artifact_hex:
      typeof obj.artifact_hex === "string" ? obj.artifact_hex : undefined,
  };
}

export interface RedactionAuditState {
  stage: RedactionAuditStage;
  fileName: string | null;
  fileHash: string | null;
  fileProgress: number;
  bundleName: string | null;
  parsed: V3Bundle | null;
  /** Issuer Ed25519 verifying key (hex) the signature is checked against. */
  issuerPubkeyHex: string;
  /** `true` iff `verifyRedactionBundleV3` accepted the (artifact, bundle, key). */
  verified: boolean | null;
  /** Failure reason from the verifier (when `verified === false`). */
  verifyReason: string | null;
  error: string | null;
}

const INITIAL: RedactionAuditState = {
  stage: "idle",
  fileName: null,
  fileHash: null,
  fileProgress: 0,
  bundleName: null,
  parsed: null,
  issuerPubkeyHex: "",
  verified: null,
  verifyReason: null,
  error: null,
};

function resolveStage(
  fileHash: string | null,
  parsed: V3Bundle | null,
  current: RedactionAuditStage,
): RedactionAuditStage {
  if (current === "hashing" || current === "verifying" || current === "done") {
    return current;
  }
  if (fileHash && parsed) return "ready";
  return "idle";
}

export function useRedactionAudit() {
  const [state, setState] = useState<RedactionAuditState>(INITIAL);
  const parsedRef = useRef<V3Bundle | null>(null);
  // Keep the dropped File handle so audit() can re-read its bytes without
  // holding ~MB of ArrayBuffer in component state.
  const fileRef = useRef<File | null>(null);
  const issuerKeyRef = useRef<string>("");
  // Per-slot request tokens — each new selection increments the counter, and
  // async completions check the token they started with before writing state.
  const fileReqId = useRef(0);
  const bundleReqId = useRef(0);

  const reset = useCallback(() => {
    parsedRef.current = null;
    fileRef.current = null;
    issuerKeyRef.current = "";
    fileReqId.current += 1;
    bundleReqId.current += 1;
    setState(INITIAL);
  }, []);

  const onFile = useCallback(async (file: File) => {
    fileRef.current = file;
    const myReq = ++fileReqId.current;
    setState((prev) => ({
      ...prev,
      stage: "hashing",
      fileName: file.name,
      fileHash: null,
      fileProgress: 0,
      // A new file must not carry a stale verdict.
      verified: null,
      verifyReason: null,
      error: null,
    }));
    try {
      const hash = await hashFile(file, (pct) => {
        if (fileReqId.current === myReq) {
          setState((prev) => ({ ...prev, fileProgress: pct }));
        }
      });
      if (fileReqId.current !== myReq) return;
      setState((prev) => ({
        ...prev,
        fileHash: hash,
        fileProgress: 100,
        stage: resolveStage(hash, parsedRef.current, "idle"),
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

  const onBundleFile = useCallback(async (file: File) => {
    parsedRef.current = null;
    const myReq = ++bundleReqId.current;
    setState((prev) => ({
      ...prev,
      bundleName: file.name,
      parsed: null,
      verified: null,
      verifyReason: null,
      error: null,
    }));
    try {
      const text = await file.text();
      if (bundleReqId.current !== myReq) return;
      const parsed = parseV3Bundle(JSON.parse(text));
      parsedRef.current = parsed;
      setState((prev) => ({
        ...prev,
        parsed,
        stage: resolveStage(prev.fileHash, parsed, "idle"),
      }));
    } catch (e) {
      if (bundleReqId.current !== myReq) return;
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, []);

  const setIssuerPubkey = useCallback((hex: string) => {
    issuerKeyRef.current = hex;
    setState((prev) => ({
      ...prev,
      issuerPubkeyHex: hex,
      // Changing the trust anchor invalidates any prior verdict.
      verified: null,
      verifyReason: null,
      error: null,
    }));
  }, []);

  const audit = useCallback(async () => {
    const parsed = parsedRef.current;
    const file = fileRef.current;
    const issuerHex = issuerKeyRef.current.trim();
    if (!parsed) return;
    if (!file) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: "Load the redacted artifact file first.",
      }));
      return;
    }
    if (!issuerHex) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: "Provide the issuer's Ed25519 public key (hex) to verify the signature.",
      }));
      return;
    }
    setState((prev) => ({
      ...prev,
      stage: "verifying",
      error: null,
      verified: null,
      verifyReason: null,
    }));
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const { ok, reason } = verifyRedactionBundleV3(
        parsed,
        bytes,
        issuerHex,
        parsed.format,
      );
      setState((prev) => ({
        ...prev,
        stage: "done",
        verified: ok,
        verifyReason: ok ? null : (reason ?? "verification failed"),
      }));
    } catch (e) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, []);

  return {
    ...state,
    onFile,
    onBundleFile,
    setIssuerPubkey,
    audit,
    reset,
  };
}
