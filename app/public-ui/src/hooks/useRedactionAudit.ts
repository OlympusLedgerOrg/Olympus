/**
 * useRedactionAudit — file + bundle ZK audit for the redaction_validity circuit.
 *
 * **ADR-0026 object-level redaction.** Bundles carry `redactedObjIds` (the
 * indirect-object ids the issuer redacted) + `revealedSegments` (per-revealed-
 * object `{segmentId, blindingDecimal}` pairs) instead of the chunk-era
 * `reveal_mask`.
 *
 * Two inputs:
 *   1. The redacted PDF file — BLAKE3-hashed in-browser so the operator can see
 *      they've loaded the right file, and IPC-forwarded to the Rust hot path
 *      (or the JS fallback) for the file→commitment binding check.
 *   2. A `redaction_validity` proof bundle JSON — parsed into the canonical
 *      `{circuit, proofJson, publicSignals, redactedObjIds, revealedSegments}`
 *      record.
 *
 * The submit does two things in order:
 *   a. POST /zk/verify — the Groth16 verifier confirms the proof is
 *      internally consistent.
 *   b. invoke('verify_redaction_binding') — the Rust path re-parses the PDF,
 *      recomputes the hiding object leaves for revealed objects, folds the
 *      depth-10 chain over a 1024-slot padded array, and checks whether the
 *      result equals `publicSignals[2]`. If not, the proof is valid but the
 *      file is wrong (or the bundle is) — either way the audit fails.
 *      Falls through to a pure-JS implementation in `lib/redactionBinding.ts`
 *      when Tauri IPC isn't available (Tor public_router web auditor path).
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

/** Per-revealed-object blinding the issuer disclosed in the bundle. */
export interface RevealedSegment {
  segmentId: number;
  blindingDecimal: string;
}

interface ParsedBundle {
  circuit: ZkCircuit;
  proofJson: string;
  publicSignals: string[];
  /** Indirect-object ids the issuer redacted (ADR-0026). */
  redactedObjIds: number[];
  /** Per-revealed-object `{segmentId, blindingDecimal}` (ADR-0026). */
  revealedSegments: RevealedSegment[];
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
  const proofJson =
    typeof proofRaw === "string" ? proofRaw : JSON.stringify(proofRaw);

  const signalsRaw = obj.public_signals ?? obj.publicSignals;
  if (!Array.isArray(signalsRaw)) {
    throw new Error("Bundle is missing a 'public_signals' array.");
  }
  const publicSignals = signalsRaw.map((s, i) => {
    if (typeof s === "string") return s;
    if (typeof s === "number" || typeof s === "bigint") return String(s);
    throw new Error(`public_signals[${i}] must be a string or number.`);
  });
  // ADR-0026 / audit-M2 public signal order:
  //   [nullifier, originalRoot, redactedCommitment, revealedCount, issuerAx, issuerAy]
  if (publicSignals.length !== 6) {
    throw new Error(
      `redaction_validity expects 6 public signals (ADR-0026); got ${publicSignals.length}.`,
    );
  }

  const idsRaw = obj.redacted_obj_ids ?? obj.redactedObjIds;
  if (!Array.isArray(idsRaw)) {
    throw new Error(
      "Bundle is missing a 'redacted_obj_ids' array (ADR-0026 object-level scheme).",
    );
  }
  const redactedObjIds = idsRaw.map((v, i) => {
    // The Rust verifier (`verify_redaction_binding`) types object ids as u32,
    // so reject anything outside 0..=0xffffffff up front with a clear message
    // rather than letting Tauri's deserializer fail opaquely.
    if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && v <= 0xffffffff) {
      return v;
    }
    throw new Error(
      `redacted_obj_ids[${i}] must be a non-negative safe integer within the u32 range (0..=4294967295).`,
    );
  });

  const segsRaw = obj.revealed_segments ?? obj.revealedSegments;
  if (!Array.isArray(segsRaw)) {
    throw new Error(
      "Bundle is missing a 'revealed_segments' array (ADR-0026 object-level scheme).",
    );
  }
  const revealedSegments: RevealedSegment[] = segsRaw.map((s, i) => {
    if (!s || typeof s !== "object") {
      throw new Error(`revealed_segments[${i}] must be an object.`);
    }
    const seg = s as Record<string, unknown>;
    const idRaw = seg.segment_id ?? seg.segmentId;
    const blRaw = seg.blinding_decimal ?? seg.blindingDecimal;
    if (
      typeof idRaw !== "number" ||
      !Number.isSafeInteger(idRaw) ||
      idRaw < 0 ||
      idRaw > 0xffffffff
    ) {
      throw new Error(
        `revealed_segments[${i}].segment_id must be a non-negative safe integer within the u32 range (0..=4294967295).`,
      );
    }
    if (typeof blRaw !== "string" || blRaw.length === 0) {
      throw new Error(
        `revealed_segments[${i}].blinding_decimal must be a non-empty decimal string.`,
      );
    }
    return { segmentId: idRaw, blindingDecimal: blRaw };
  });

  return {
    circuit: "redaction_validity",
    proofJson,
    publicSignals,
    redactedObjIds,
    revealedSegments,
  };
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
   *  Rust path (or JS fallback) re-derives `redactedCommitment` from the
   *  dropped file + bundle. A passing ZK proof with `bindingValid: false`
   *  means the proof math is fine but the file is wrong (or the bundle is). */
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
  // Per-slot request tokens — each new selection increments the counter,
  // and async completions check the token they were started with before
  // writing state. Stale completions for superseded selections become
  // no-ops instead of overwriting the current slot. See review thread on
  // PR #1088 (rapid re-drop race).
  const fileReqId = useRef(0);
  const bundleReqId = useRef(0);

  const reset = useCallback(() => {
    parsedRef.current = null;
    fileRef.current = null;
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
      // Stale audit verdict from the previous file must not survive a new
      // selection — otherwise the UI keeps showing PROOF_MATH_VALID for the
      // old (file, bundle) pair while the user is loading a new one.
      result: null,
      bindingValid: null,
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
        // Force re-evaluation from "idle" — don't feed prev.stage back in,
        // since a prior "done" would otherwise keep us pinned to "done"
        // until the user clicks audit again.
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
      // Stale audit verdict from the previous bundle must not survive a
      // new selection — see onFile comment.
      result: null,
      bindingValid: null,
      error: null,
    }));
    try {
      const text = await file.text();
      if (bundleReqId.current !== myReq) return;
      const parsed = parseRedactionBundle(JSON.parse(text));
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
      // Two execution paths, byte-identical outcomes by construction (the JS
      // path is pinned to the Rust impl via `redactionBinding.conformance.test.ts`
      // and Rust's `pdf_objects::js_conformance_fixture_locked`):
      //   a. Desktop (Tauri shell present): `verify_redaction_binding` —
      //      fastest, no JS Pedersen/Poseidon in the critical path.
      //   b. Web auditor (no Tauri): pure-JS in `lib/redactionBinding.ts`.
      let bindingValid: boolean | null = null;
      let bindingError: string | null = null;
      if (result.valid && file) {
        const expectedCommitment = parsed.publicSignals[2]; // redactedCommitment
        const bytes = new Uint8Array(await file.arrayBuffer());
        try {
          // Decide the path by the genuine Tauri-runtime marker, NOT by whether
          // `@tauri-apps/api/core` imports: that module loads fine in a plain
          // browser and its `invoke` only throws at call time, so catching the
          // call would conflate "no Tauri shell" with a real verifier error.
          // Tauri 2 sets `window.__TAURI_INTERNALS__` on the webview (same probe
          // as lib/api.ts and useFileCommit.ts).
          const isTauri =
            typeof window !== "undefined" &&
            typeof (window as { __TAURI_INTERNALS__?: unknown })
              .__TAURI_INTERNALS__ !== "undefined";

          if (isTauri) {
            // Native path: let a genuine error from the verifier (bad
            // blinding_decimal, malformed PDF, …) propagate to the outer catch
            // rather than swallowing it and silently re-running in JS.
            const { invoke } = await import("@tauri-apps/api/core");
            bindingValid = await invoke<boolean>("verify_redaction_binding", {
              fileBytes: Array.from(bytes),
              redactedObjIds: parsed.redactedObjIds,
              revealedSegments: parsed.revealedSegments.map((s) => ({
                segment_id: s.segmentId,
                blinding_decimal: s.blindingDecimal,
              })),
              expectedCommitmentDec: expectedCommitment,
            });
          } else {
            const { verifyRedactionBindingJs } = await import(
              "../lib/redactionBinding"
            );
            bindingValid = await verifyRedactionBindingJs(
              bytes,
              parsed.redactedObjIds,
              parsed.revealedSegments,
              expectedCommitment,
            );
          }
        } catch (e) {
          // Surface the error from whichever binding path actually ran (native
          // verifier or JS fallback) instead of masking it.
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
