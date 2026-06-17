/**
 * useAuditProof — bundle-only ZK verification hook.
 *
 * Audits a Groth16 proof bundle against the server's embedded verification
 * keys.  No document file is required: the proof + public signals fully
 * determine validity.  Handles the two Groth16 circuits the backend exposes
 * (redaction excluded — see below):
 *   - document_existence  → "leaf X is in Merkle root Y at index N"
 *   - non_existence       → "key K is NOT in Sparse Merkle root R"
 *
 * Redaction is no longer a Groth16 circuit (ADR-0030 V3 is signed-Merkle); the
 * Redaction tab verifies V3 bundles in-app via `verifyRedactionBundleV3`.
 *
 * The hook parses the dropped JSON into `{circuit, proofJson, publicSignals}`
 * and submits to POST /zk/verify via `verifyZkProof`.  Bundles produced by
 * the existing ZK_PROOF download button on ProofResultPanel are recognised
 * automatically (they embed the same field names with snake_case keys).
 */
import { useCallback, useRef, useState } from "react";
import {
  verifyAnchoredExistence,
  verifyZkProof,
  type AnchoredVerifyResult,
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
  /** Anchoring metadata, present in bundles produced by `GENERATE_ZK_PROOF`.
   *  When set on a `document_existence` bundle, the audit auto-runs the
   *  trust-anchored verify path that binds the proof's public signals to a
   *  server-side signed snapshot. */
  contentHash?: string;
  snapshotRoot?: string;
  snapshotIndex?: number;
  snapshotSize?: number;
}

const KNOWN_CIRCUITS: readonly ZkCircuit[] = [
  "document_existence",
  "non_existence",
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

  // Optional anchoring metadata. Accept snake_case (downloaded bundles) and
  // camelCase (raw server responses). None of these are required — their
  // absence just means anchored verify can't run.
  const asStr = (v: unknown): string | undefined =>
    typeof v === "string" && v.trim() ? v : undefined;
  const asNum = (v: unknown): number | undefined =>
    typeof v === "number" ? v : undefined;
  const contentHash = asStr(obj.content_hash) ?? asStr(obj.contentHash);
  const snapshotRoot = asStr(obj.snapshot_root) ?? asStr(obj.snapshotRoot);
  const snapshotIndex = asNum(obj.snapshot_index) ?? asNum(obj.snapshotIndex);
  const snapshotSize = asNum(obj.snapshot_size) ?? asNum(obj.snapshotSize);

  return {
    circuit: circuitRaw,
    proofJson,
    publicSignals,
    contentHash,
    snapshotRoot,
    snapshotIndex,
    snapshotSize,
  };
}

export interface AuditProofState {
  stage: AuditStage;
  bundleName: string | null;
  parsed: ParsedBundle | null;
  result: ZkVerifyResponse | null;
  /** Anchored-verify outcome, populated only for `document_existence`
   *  bundles carrying a `content_hash`. `null` otherwise. The `valid` field
   *  here is the strict overall verdict — proof math AND signal binding AND
   *  trusted-issuer snapshot must all pass. */
  anchor: AnchoredVerifyResult | null;
  error: string | null;
}

const INITIAL: AuditProofState = {
  stage: "idle",
  bundleName: null,
  parsed: null,
  result: null,
  anchor: null,
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
        anchor: null,
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
        anchor: null,
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
    setState((prev) => ({
      ...prev,
      stage: "verifying",
      error: null,
      result: null,
      anchor: null,
    }));
    try {
      const apiKey = getStoredApiKey() || undefined;
      const result = await verifyZkProof(parsed, apiKey);

      // Auto-run anchored verify for document_existence when the bundle
      // carries a content_hash. Bundles emitted by GENERATE_ZK_PROOF always
      // include it; older hand-rolled or partial bundles won't, and the UI
      // will surface that as "anchor: unchecked".
      let anchor: AnchoredVerifyResult | null = null;
      if (
        result.valid &&
        parsed.circuit === "document_existence" &&
        parsed.contentHash
      ) {
        try {
          anchor = await verifyAnchoredExistence(
            {
              circuit: parsed.circuit,
              proofJson: parsed.proofJson,
              publicSignals: parsed.publicSignals,
              contentHash: parsed.contentHash,
              snapshotRoot: parsed.snapshotRoot,
              snapshotIndex: parsed.snapshotIndex,
              snapshotSize: parsed.snapshotSize,
            },
            apiKey,
          );
        } catch (e) {
          // Anchored-verify failure is surfaced as part of the result
          // panel, not as a hard error — the proof math result is still
          // meaningful on its own.
          anchor = {
            valid: false,
            proofMathValid: result.valid,
            signalsBindToSnapshot: false,
            snapshotTrusted: false,
            detail: `anchored verify failed: ${e instanceof Error ? e.message : String(e)}`,
          };
        }
      }

      setState((prev) => ({ ...prev, stage: "done", result, anchor }));
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
