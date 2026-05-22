/**
 * useAuditProof — bundle-only ZK verification hook.
 *
 * Audits a Groth16 proof bundle against the server's embedded verification
 * keys.  No document file is required: the proof + public signals fully
 * determine validity.  Handles all three circuits the backend exposes:
 *   - document_existence  → "leaf X is in Merkle root Y at index N"
 *   - non_existence       → "key K is NOT in Sparse Merkle root R"
 *   - redaction_validity  → "redacted commitment binds to original root R"
 *
 * The hook parses the dropped JSON into `{circuit, proofJson, publicSignals}`
 * and submits to POST /zk/verify via `verifyZkProof`.  Bundles produced by
 * the existing ZK_PROOF download button on ProofResultPanel are recognised
 * automatically (they embed the same field names with snake_case keys).
 */
import { useCallback, useRef, useState } from "react";
import {
  verifyZkProof,
  type ZkCircuit,
  type ZkVerifyResponse,
} from "../lib/api";
import { getStoredApiKey } from "../lib/storage";

export type AuditStage =
  | "idle"
  | "ready"
  | "verifying"
  | "done"
  | "error";

interface ParsedBundle {
  circuit: ZkCircuit;
  proofJson: string;
  publicSignals: string[];
}

const KNOWN_CIRCUITS: readonly ZkCircuit[] = [
  "document_existence",
  "non_existence",
  "redaction_validity",
] as const;

function isCircuit(s: unknown): s is ZkCircuit {
  return typeof s === "string" && (KNOWN_CIRCUITS as readonly string[]).includes(s);
}

/// Parse a dropped JSON bundle into the canonical {circuit, proofJson,
/// publicSignals} triple.  Accepts both snake_case (server output) and
/// camelCase (snarkjs-style) keys.  `proof` may be either a string or an
/// object — the verify endpoint wants a JSON string, so objects are
/// re-serialised here.
function parseBundle(raw: unknown): ParsedBundle {
  if (!raw || typeof raw !== "object") {
    throw new Error("Bundle must be a JSON object.");
  }
  const obj = raw as Record<string, unknown>;

  const circuitRaw = obj.circuit ?? obj.circuit_type ?? obj.circuitName;
  if (!isCircuit(circuitRaw)) {
    throw new Error(
      `Bundle is missing a 'circuit' field, or names an unknown circuit. ` +
      `Expected one of: ${KNOWN_CIRCUITS.join(", ")}.`,
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

  return { circuit: circuitRaw, proofJson, publicSignals };
}

export interface AuditProofState {
  stage: AuditStage;
  bundleName: string | null;
  parsed: ParsedBundle | null;
  result: ZkVerifyResponse | null;
  error: string | null;
}

const INITIAL: AuditProofState = {
  stage: "idle",
  bundleName: null,
  parsed: null,
  result: null,
  error: null,
};

export function useAuditProof() {
  const [state, setState] = useState<AuditProofState>(INITIAL);
  // `audit()` is invoked from a button click; the parsed bundle lives in
  // state for rendering, but we mirror it in a ref so the callback can read
  // the latest value without depending on a stale closure.
  const parsedRef = useRef<ParsedBundle | null>(null);

  const reset = useCallback(() => {
    parsedRef.current = null;
    setState(INITIAL);
  }, []);

  const onBundleFile = useCallback(async (file: File) => {
    parsedRef.current = null;
    setState({ ...INITIAL, bundleName: file.name });
    try {
      const text = await file.text();
      const parsed = parseBundle(JSON.parse(text));
      parsedRef.current = parsed;
      setState({
        stage: "ready",
        bundleName: file.name,
        parsed,
        result: null,
        error: null,
      });
    } catch (e) {
      setState((prev) => ({
        ...prev,
        stage: "error",
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, []);

  const onBundleText = useCallback((text: string) => {
    if (!text.trim()) {
      parsedRef.current = null;
      setState(INITIAL);
      return;
    }
    try {
      const parsed = parseBundle(JSON.parse(text));
      parsedRef.current = parsed;
      setState((prev) => ({
        stage: "ready",
        bundleName: prev.bundleName,
        parsed,
        result: null,
        error: null,
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
    onBundleFile,
    onBundleText,
    audit,
    reset,
  };
}
