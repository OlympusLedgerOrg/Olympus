/**
 * useZkDrop — drag-and-drop ZK proof verification hook.
 *
 * Accepts two inputs in any order:
 *   1. A document file (any type) — hashed with BLAKE3 in-browser.
 *   2. A proof bundle JSON file — parsed and validated.
 *
 * When both are present the hook computes whether the file's BLAKE3 hash
 * matches the content_hash embedded in the proof bundle, then submits the
 * bundle to POST /ingest/proofs/verify.  The computed file hash always wins
 * over whatever content_hash was in the bundle, so the server re-checks
 * against the actual file rather than a value the user typed.
 *
 * Files are classified automatically on drop:
 *   - .json / application/json  → proof bundle slot
 *   - anything else             → document slot
 */

import { useCallback, useState } from "react";
import { hashFile } from "../lib/blake3";
import { verifyProofBundle } from "../lib/api";
import { addRecentVerification } from "../lib/storage";
import type {
  ProofVerificationRequest,
  ProofVerificationResponse,
  VerdictState,
} from "../lib/types";
import { proofVerificationToVerdict } from "../lib/verdictHelpers";

export type ZkDropStage =
  | "idle"       // nothing dropped yet
  | "hashing"    // computing BLAKE3 of the document file
  | "ready"      // both file hash + proof bundle present; can verify
  | "verifying"  // API call in flight
  | "done"       // verification result received
  | "error";     // something went wrong

export interface ZkDropState {
  stage: ZkDropStage;
  /** BLAKE3 hex digest of the dropped document file. */
  fileHash: string | null;
  /** Original filename of the document. */
  fileName: string | null;
  /** 0-100 hashing progress for the document file. */
  fileProgress: number;
  /** Parsed proof bundle, ready to submit. */
  proofBundle: ProofVerificationRequest | null;
  /** Original filename of the proof JSON. */
  proofFileName: string | null;
  /**
   * Whether the computed file hash matches the content_hash in the proof
   * bundle.  null = one or both inputs not yet present.
   */
  hashMatch: boolean | null;
  error: string | null;
  result: ProofVerificationResponse | null;
}

const INITIAL_STATE: ZkDropState = {
  stage: "idle",
  fileHash: null,
  fileName: null,
  fileProgress: 0,
  proofBundle: null,
  proofFileName: null,
  hashMatch: null,
  error: null,
  result: null,
};

function resolveStage(
  fileHash: string | null,
  proofBundle: ProofVerificationRequest | null,
  current: ZkDropStage,
): ZkDropStage {
  // Don't exit terminal states here — caller does that explicitly.
  if (current === "hashing" || current === "verifying" || current === "done") {
    return current;
  }
  if (fileHash && proofBundle) return "ready";
  return "idle";
}

function computeHashMatch(
  fileHash: string | null,
  proofBundle: ProofVerificationRequest | null,
): boolean | null {
  if (!fileHash || !proofBundle || !proofBundle.content_hash) return null;
  return fileHash === proofBundle.content_hash;
}

export function useZkDrop(setVerdictResult: (r: VerdictState | null) => void) {
  const [state, setState] = useState<ZkDropState>(INITIAL_STATE);

  const reset = useCallback(() => {
    setState(INITIAL_STATE);
  }, []);

  // ── Document file handler ──────────────────────────────────────────────────

  const onDocumentFile = useCallback(async (file: File) => {
    setState((prev) => ({
      ...prev,
      stage: "hashing",
      fileName: file.name,
      fileProgress: 0,
      fileHash: null,
      hashMatch: null,
      error: null,
    }));

    try {
      const hash = await hashFile(file, (pct) => {
        setState((prev) => ({ ...prev, fileProgress: pct }));
      });

      setState((prev) => {
        const hashMatch = computeHashMatch(hash, prev.proofBundle);
        return {
          ...prev,
          fileHash: hash,
          fileProgress: 100,
          hashMatch,
          stage: resolveStage(hash, prev.proofBundle, "idle"),
        };
      });
    } catch (e) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, []);

  // ── Proof bundle JSON handler ──────────────────────────────────────────────

  const onProofFile = useCallback(async (file: File) => {
    setState((prev) => ({
      ...prev,
      proofFileName: file.name,
      proofBundle: null,
      hashMatch: null,
      error: null,
    }));

    try {
      const text = await file.text();
      const raw = JSON.parse(text) as Record<string, unknown>;

      if (!raw.merkle_root || !raw.merkle_proof) {
        throw new Error(
          "Not a valid proof bundle — must have merkle_root and merkle_proof fields.",
        );
      }

      const bundle: ProofVerificationRequest = {
        ...(typeof raw.proof_id === "string" ? { proof_id: raw.proof_id } : {}),
        content_hash: typeof raw.content_hash === "string" ? raw.content_hash : "",
        merkle_root: raw.merkle_root as string,
        merkle_proof: raw.merkle_proof as Record<string, unknown>,
      };

      setState((prev) => {
        const hashMatch = computeHashMatch(prev.fileHash, bundle);
        return {
          ...prev,
          proofBundle: bundle,
          hashMatch,
          stage: resolveStage(prev.fileHash, bundle, prev.stage === "hashing" ? "hashing" : "idle"),
        };
      });
    } catch (e) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        proofFileName: null,
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, []);

  // ── Smart multi-file dispatcher (used by the drop zone) ───────────────────

  const onFiles = useCallback(
    (files: File[]) => {
      for (const file of files) {
        if (file.type === "application/json" || file.name.endsWith(".json")) {
          void onProofFile(file);
        } else {
          void onDocumentFile(file);
        }
      }
    },
    [onDocumentFile, onProofFile],
  );

  // ── Load proof from raw JSON text (paste / textarea path) ─────────────────

  const onProofText = useCallback((text: string) => {
    if (!text.trim()) {
      setState((prev) => ({
        ...prev,
        proofBundle: null,
        proofFileName: null,
        hashMatch: null,
        error: null,
        stage: resolveStage(prev.fileHash, null, "idle"),
      }));
      return;
    }
    try {
      const raw = JSON.parse(text) as Record<string, unknown>;
      if (!raw.merkle_root || !raw.merkle_proof) {
        throw new Error("Bundle must include merkle_root and merkle_proof");
      }
      const bundle: ProofVerificationRequest = {
        ...(typeof raw.proof_id === "string" ? { proof_id: raw.proof_id } : {}),
        content_hash: typeof raw.content_hash === "string" ? raw.content_hash : "",
        merkle_root: raw.merkle_root as string,
        merkle_proof: raw.merkle_proof as Record<string, unknown>,
      };
      setState((prev) => {
        const hashMatch = computeHashMatch(prev.fileHash, bundle);
        return {
          ...prev,
          proofBundle: bundle,
          proofFileName: null,
          hashMatch,
          error: null,
          stage: resolveStage(prev.fileHash, bundle, prev.stage === "hashing" ? "hashing" : "idle"),
        };
      });
    } catch (e) {
      setState((prev) => ({
        ...prev,
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, []);

  // ── Verification ───────────────────────────────────────────────────────────

  const verify = useCallback(async () => {
    const { proofBundle } = state;
    if (!proofBundle) return;

    setState((prev) => ({ ...prev, stage: "verifying", error: null }));
    setVerdictResult(null);

    try {
      // Verify the bundle as-is — content_hash is what's committed to the ledger.
      // The file hash comparison (hashMatch) is purely informational: a mismatch
      // means the dropped file is a redacted or modified version of the original.
      const result = await verifyProofBundle(proofBundle);
      const isRedacted = state.hashMatch === false;
      const verdict = proofVerificationToVerdict(result, isRedacted);

      setVerdictResult({
        ...verdict,
        displayHash: result.content_hash,
        raw: result,
      });

      addRecentVerification({
        hash: result.content_hash,
        type: "proof",
        verdict: verdict.verdict,
        timestamp: Date.now(),
      });

      setState((prev) => ({ ...prev, stage: "done", result }));
    } catch (e) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, [state, setVerdictResult]);

  return {
    ...state,
    onFiles,
    onDocumentFile,
    onProofFile,
    onProofText,
    verify,
    reset,
  };
}
