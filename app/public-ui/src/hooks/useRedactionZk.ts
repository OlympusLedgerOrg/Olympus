/**
 * useRedactionZk — hook for generating and verifying ZK redaction proofs.
 *
 * GENERATE mode: prover supplies both files + commit ID → server returns bundle.
 * VERIFY mode: verifier supplies redacted file + bundle JSON → server confirms.
 *
 * The original file is never needed at verify time.
 */

import { useCallback, useState } from "react";
import { proveRedaction, verifyRedactionZk } from "../lib/api";
import type { RedactionProofBundle, RedactionZkVerifyResponse } from "../lib/types";

export type RedactionZkMode = "generate" | "verify";
export type RedactionZkStage = "idle" | "proving" | "verifying" | "done" | "error";

export interface RedactionZkState {
  mode: RedactionZkMode;
  stage: RedactionZkStage;
  // GENERATE inputs
  originalFile: File | null;
  redactedFile: File | null;
  commitId: string;
  // VERIFY inputs
  verifyRedactedFile: File | null;
  bundleFile: File | null;
  parsedBundle: RedactionProofBundle | null;
  // Outputs
  proofBundle: RedactionProofBundle | null;
  verifyResult: RedactionZkVerifyResponse | null;
  error: string | null;
}

const INITIAL: RedactionZkState = {
  mode: "generate",
  stage: "idle",
  originalFile: null,
  redactedFile: null,
  commitId: "",
  verifyRedactedFile: null,
  bundleFile: null,
  parsedBundle: null,
  proofBundle: null,
  verifyResult: null,
  error: null,
};

export function useRedactionZk(apiKey?: string) {
  const [state, setState] = useState<RedactionZkState>(INITIAL);

  const setMode = useCallback((mode: RedactionZkMode) => {
    setState((_s) => ({ ...INITIAL, mode }));
  }, []);

  const setCommitId = useCallback((commitId: string) => {
    setState((s) => ({ ...s, commitId }));
  }, []);

  const setOriginalFile = useCallback((file: File | null) => {
    setState((s) => ({ ...s, originalFile: file, proofBundle: null, error: null, stage: "idle" }));
  }, []);

  const setRedactedFile = useCallback((file: File | null) => {
    setState((s) => ({ ...s, redactedFile: file, proofBundle: null, error: null, stage: "idle" }));
  }, []);

  const setVerifyRedactedFile = useCallback((file: File | null) => {
    setState((s) => ({ ...s, verifyRedactedFile: file, verifyResult: null, error: null, stage: "idle" }));
  }, []);

  const setBundleFile = useCallback((file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const parsed = JSON.parse(e.target?.result as string) as RedactionProofBundle;
        setState((s) => ({ ...s, bundleFile: file, parsedBundle: parsed, error: null }));
      } catch {
        setState((s) => ({ ...s, bundleFile: file, parsedBundle: null, error: "Invalid proof bundle JSON" }));
      }
    };
    reader.readAsText(file);
  }, []);

  const prove = useCallback(async () => {
    const { originalFile, redactedFile, commitId } = state;
    if (!originalFile || !redactedFile || !commitId.trim()) return;
    setState((s) => ({ ...s, stage: "proving", error: null, proofBundle: null }));
    try {
      const bundle = await proveRedaction(originalFile, redactedFile, commitId.trim(), apiKey);
      setState((s) => ({ ...s, stage: "done", proofBundle: bundle }));
    } catch (err) {
      setState((s) => ({
        ...s,
        stage: "error",
        error: err instanceof Error ? err.message : String(err),
      }));
    }
  }, [state, apiKey]);

  const verifyZk = useCallback(async () => {
    const { verifyRedactedFile, parsedBundle } = state;
    if (!verifyRedactedFile || !parsedBundle) return;
    setState((s) => ({ ...s, stage: "verifying", error: null, verifyResult: null }));
    try {
      const result = await verifyRedactionZk(verifyRedactedFile, parsedBundle, apiKey);
      setState((s) => ({ ...s, stage: "done", verifyResult: result }));
    } catch (err) {
      setState((s) => ({
        ...s,
        stage: "error",
        error: err instanceof Error ? err.message : String(err),
      }));
    }
  }, [state, apiKey]);

  const reset = useCallback(() => {
    setState((s) => ({ ...INITIAL, mode: s.mode }));
  }, []);

  const downloadBundle = useCallback(() => {
    if (!state.proofBundle) return;
    const blob = new Blob([JSON.stringify(state.proofBundle, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "redaction_proof_bundle.json";
    a.click();
    URL.revokeObjectURL(url);
  }, [state.proofBundle]);

  return { state, setMode, setCommitId, setOriginalFile, setRedactedFile, setVerifyRedactedFile, setBundleFile, prove, verifyZk, reset, downloadBundle };
}
