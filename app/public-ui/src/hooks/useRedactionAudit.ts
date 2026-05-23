/**
 * useRedactionAudit — file + bundle ZK audit for the redaction_validity circuit.
 *
 * Two inputs:
 *   1. The redacted document file (any type) — BLAKE3-hashed in-browser so the
 *      operator can see they've loaded the right file.
 *   2. A `redaction_validity` proof bundle JSON — parsed into the canonical
 *      {circuit, proofJson, publicSignals} triple.
 *
 * The submit posts the bundle to /zk/verify.  The Groth16 verifier confirms
 * the proof is internally consistent against (originalRoot, redactedCommitment,
 * revealedCount, nullifier).  Binding the verified `redactedCommitment` to the
 * dropped file's actual bytes requires Poseidon-in-browser; that step is
 * marked TODO in the UI for now — the file is displayed for context only.
 */
import { useCallback, useRef, useState } from "react";
import { hashFile } from "../lib/blake3";
import {
  verifyZkProof,
  type ZkCircuit,
  type ZkVerifyResponse,
} from "../lib/api";
import { getStoredApiKey } from "../lib/storage";

export type RedactionAuditStage =
  | "idle"
  | "hashing"
  | "ready"
  | "verifying"
  | "done"
  | "error";

interface ParsedBundle {
  circuit: ZkCircuit;
  proofJson: string;
  publicSignals: string[];
}

function parseRedactionBundle(raw: unknown): ParsedBundle {
  if (!raw || typeof raw !== "object") {
    throw new Error("Bundle must be a JSON object.");
  }
  const obj = raw as Record<string, unknown>;

  const circuitRaw = obj.circuit ?? obj.circuit_type ?? "redaction_validity";
  if (circuitRaw !== "redaction_validity") {
    throw new Error(
      `Wrong circuit: expected 'redaction_validity', got '${String(circuitRaw)}'. ` +
      `Use the AUDIT_PROOF tab for existence / non-existence bundles.`,
    );
  }

  const proofRaw = obj.proof_json ?? obj.proofJson ?? obj.proof;
  if (proofRaw === undefined || proofRaw === null) {
    throw new Error("Bundle is missing a 'proof_json' / 'proof' field.");
  }
  const proofJson = typeof proofRaw === "string" ? proofRaw : JSON.stringify(proofRaw);

  const signalsRaw = obj.public_signals ?? obj.publicSignals;
  if (!Array.isArray(signalsRaw)) {
    throw new Error("Bundle is missing a 'public_signals' array.");
  }
  const publicSignals = signalsRaw.map((s, i) => {
    if (typeof s === "string") return s;
    if (typeof s === "number" || typeof s === "bigint") return String(s);
    throw new Error(`public_signals[${i}] must be a string or number.`);
  });
  // redaction_validity public signal order: [nullifier, originalRoot, redactedCommitment, revealedCount]
  if (publicSignals.length !== 4) {
    throw new Error(
      `redaction_validity expects 4 public signals; got ${publicSignals.length}.`,
    );
  }

  return { circuit: "redaction_validity", proofJson, publicSignals };
}

export interface RedactionAuditState {
  stage: RedactionAuditStage;
  fileName: string | null;
  fileHash: string | null;
  fileProgress: number;
  bundleName: string | null;
  parsed: ParsedBundle | null;
  result: ZkVerifyResponse | null;
  error: string | null;
}

const INITIAL: RedactionAuditState = {
  stage: "idle",
  fileName: null,
  fileHash: null,
  fileProgress: 0,
  bundleName: null,
  parsed: null,
  result: null,
  error: null,
};

function resolveStage(
  fileHash: string | null,
  parsed: ParsedBundle | null,
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
  const parsedRef = useRef<ParsedBundle | null>(null);

  const reset = useCallback(() => {
    parsedRef.current = null;
    setState(INITIAL);
  }, []);

  const onFile = useCallback(async (file: File) => {
    setState((prev) => ({
      ...prev,
      stage: "hashing",
      fileName: file.name,
      fileHash: null,
      fileProgress: 0,
      error: null,
    }));
    try {
      const hash = await hashFile(file, (pct) => {
        setState((prev) => ({ ...prev, fileProgress: pct }));
      });
      setState((prev) => ({
        ...prev,
        fileHash: hash,
        fileProgress: 100,
        stage: resolveStage(hash, parsedRef.current, "idle"),
      }));
    } catch (e) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, []);

  const onBundleFile = useCallback(async (file: File) => {
    parsedRef.current = null;
    setState((prev) => ({
      ...prev,
      bundleName: file.name,
      parsed: null,
      error: null,
    }));
    try {
      const text = await file.text();
      const parsed = parseRedactionBundle(JSON.parse(text));
      parsedRef.current = parsed;
      setState((prev) => ({
        ...prev,
        parsed,
        stage: resolveStage(prev.fileHash, parsed, prev.stage),
      }));
    } catch (e) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, []);

  const audit = useCallback(async () => {
    const parsed = parsedRef.current;
    if (!parsed) return;
    setState((prev) => ({ ...prev, stage: "verifying", error: null, result: null }));
    try {
      const apiKey = getStoredApiKey() || undefined;
      const result = await verifyZkProof(parsed, apiKey);
      setState((prev) => ({ ...prev, stage: "done", result }));
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
    audit,
    reset,
  };
}
