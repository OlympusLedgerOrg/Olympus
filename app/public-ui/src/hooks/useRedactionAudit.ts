/**
 * useRedactionAudit — file + bundle ZK audit for the redaction_validity circuit.
 *
 * Two inputs:
 *   1. The redacted document file (any type) — BLAKE3-hashed in-browser so the
 *      operator can see they've loaded the right file, and IPC-forwarded to
 *      the Rust hot path for the file→commitment binding check.
 *   2. A `redaction_validity` proof bundle JSON — parsed into the canonical
 *      {circuit, proofJson, publicSignals, revealMask} record.
 *
 * The submit does two things in order:
 *   a. POST /zk/verify — the Groth16 verifier confirms the proof is
 *      internally consistent.
 *   b. invoke('verify_redaction_binding') — the Rust path re-chunks the
 *      dropped file, masks it with `revealMask`, and recomputes
 *      `redactedCommitment`. If it equals `publicSignals[2]`, the dropped
 *      file is the one the proof commits to. If not, the proof is valid
 *      but the file is wrong (or vice-versa) — either way the audit fails.
 *
 * Both must succeed for the audit to pass.
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
  /** 16-element 0/1 mask from the issued bundle — required to recompute
   *  `redactedCommitment` from the dropped file. */
  revealMask: number[];
}

const EXPECTED_MASK_LEN = 16;

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
  // redaction_validity public signal order (post-audit M-2):
  //   [nullifier, originalRoot, redactedCommitment, revealedCount, issuerAx, issuerAy]
  // Older bundles (pre-M-2) had 4 signals — accept those too so a recipient
  // holding a historical bundle can still verify the proof math, even though
  // the binding check needs an originalRoot it can trust independently.
  if (publicSignals.length !== 4 && publicSignals.length !== 6) {
    throw new Error(
      `redaction_validity expects 4 or 6 public signals; got ${publicSignals.length}.`,
    );
  }

  const maskRaw = obj.reveal_mask ?? obj.revealMask;
  if (!Array.isArray(maskRaw)) {
    throw new Error(
      "Bundle is missing a 'reveal_mask' array (required for the file-binding check).",
    );
  }
  if (maskRaw.length !== EXPECTED_MASK_LEN) {
    throw new Error(
      `reveal_mask must have ${EXPECTED_MASK_LEN} entries; got ${maskRaw.length}.`,
    );
  }
  const revealMask = maskRaw.map((b, i) => {
    if (b === 0 || b === 1) return b as number;
    if (b === true) return 1;
    if (b === false) return 0;
    throw new Error(`reveal_mask[${i}] = ${String(b)} is not 0 or 1.`);
  });

  return { circuit: "redaction_validity", proofJson, publicSignals, revealMask };
}

export interface RedactionAuditState {
  stage: RedactionAuditStage;
  fileName: string | null;
  fileHash: string | null;
  fileProgress: number;
  bundleName: string | null;
  parsed: ParsedBundle | null;
  result: ZkVerifyResponse | null;
  /** File→commitment binding result. `null` until audit runs; `true` iff the
   *  Rust path re-derives the bundle's `redactedCommitment` from the dropped
   *  file. A passing ZK proof with `bindingValid: false` means the proof
   *  math is fine but the file is wrong (or the bundle is). */
  bindingValid: boolean | null;
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
  bindingValid: null,
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
  // Keep the dropped File handle around so audit() can re-read its bytes for
  // the IPC binding check without holding ~MB of ArrayBuffer in component
  // state. File.arrayBuffer() is cheap on a freshly-picked file.
  const fileRef = useRef<File | null>(null);

  const reset = useCallback(() => {
    parsedRef.current = null;
    fileRef.current = null;
    setState(INITIAL);
  }, []);

  const onFile = useCallback(async (file: File) => {
    fileRef.current = file;
    setState((prev) => ({
      ...prev,
      stage: "hashing",
      fileName: file.name,
      fileHash: null,
      fileProgress: 0,
      bindingValid: null,
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
    const file = fileRef.current;
    if (!parsed) return;
    setState((prev) => ({
      ...prev,
      stage: "verifying",
      error: null,
      result: null,
      bindingValid: null,
    }));
    try {
      const apiKey = getStoredApiKey() || undefined;
      // Step 1: proof math (Groth16 against embedded vkey).
      const result = await verifyZkProof(parsed, apiKey);

      // Step 2: file→commitment binding.
      //
      // Two execution paths, byte-identical outcomes by construction
      // (the JS path is pinned to the Rust impl via
      // `redactionBinding.conformance.test.ts`):
      //   a. Desktop (Tauri shell present): invoke the Rust hot path
      //      `verify_redaction_binding` — fastest, no JS BLAKE3/Poseidon
      //      in the critical path.
      //   b. Web auditor (no Tauri): fall back to the in-browser pure-JS
      //      implementation in `lib/redactionBinding.ts`.
      //
      // If the proof math failed there's nothing meaningful to bind, so
      // skip. If the file handle was somehow lost, report unchecked.
      let bindingValid: boolean | null = null;
      let bindingError: string | null = null;
      if (result.valid && file) {
        const expectedCommitment = parsed.publicSignals[2]; // redactedCommitment
        const bytes = new Uint8Array(await file.arrayBuffer());
        try {
          // Probe Tauri IPC; fall through to JS on import or invoke failure.
          let bindingDone = false;
          try {
            const { invoke } = await import("@tauri-apps/api/core");
            bindingValid = await invoke<boolean>("verify_redaction_binding", {
              fileBytes: Array.from(bytes),
              revealMask: parsed.revealMask,
              expectedCommitmentDec: expectedCommitment,
            });
            bindingDone = true;
          } catch {
            // IPC unavailable — quietly fall through to JS path.
          }
          if (!bindingDone) {
            const { verifyRedactionBindingJs } = await import("../lib/redactionBinding");
            bindingValid = await verifyRedactionBindingJs(
              bytes,
              parsed.revealMask,
              expectedCommitment,
            );
          }
        } catch (e) {
          // Both paths failed — surface the JS-path error since IPC was
          // already established as unavailable.
          bindingError = e instanceof Error ? e.message : String(e);
        }
      }

      setState((prev) => ({
        ...prev,
        stage: "done",
        result,
        bindingValid,
        error: bindingError,
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
    audit,
    reset,
  };
}
