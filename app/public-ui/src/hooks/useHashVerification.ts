import { useCallback, useMemo, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { verifyHash, verifyProofBundle } from "../lib/api";
import { addRecentVerification, getStoredApiKey, setStoredApiKey } from "../lib/storage";
import type { HashVerificationResponse, VerdictState } from "../lib/types";
import { hashVerificationToVerdict, proofVerificationToVerdict } from "../lib/verdictHelpers";
import { HASH_RE } from "../lib/constants";

export type HashVerificationSource = "hash" | "file";

export function useHashVerification(setVerdictResult: (r: VerdictState | null) => void) {
  const [hashInput, setHashInput] = useState("");
  const [hashError, setHashError] = useState<string | null>(null);
  const [apiKey, setApiKeyState] = useState(() => getStoredApiKey());
  const setApiKey = useCallback((k: string) => {
    setApiKeyState(k);
    setStoredApiKey(k);
  }, []);

  // Tracks the most recent hash submitted so the onError callback always has
  // the correct value regardless of React's re-render timing.
  const pendingHashRef = useRef<string>("");
  const pendingSourceRef = useRef<HashVerificationSource>("hash");
  // Monotonic submission counter. Each submitHash bumps it; async work
  // captures the value it was scheduled under and aborts (returns silently)
  // if a newer submission has fired since. Prevents stale snapshot-verify
  // responses from an older hash overwriting the result of a newer one.
  const requestIdRef = useRef<number>(0);

  const normalizedHash = hashInput.trim().toLowerCase();
  const hashStatus = useMemo(() => {
    if (!normalizedHash) return { label: "WAITING", tone: "neutral" as const };
    if (normalizedHash.length !== 64) {
      return { label: `${normalizedHash.length}/64`, tone: "warn" as const };
    }
    if (!HASH_RE.test(normalizedHash)) {
      return { label: "BAD_HEX", tone: "err" as const };
    }
    return { label: "READY", tone: "ok" as const };
  }, [normalizedHash]);

  // Two-step verification: GET /ingest/records/hash/.../verify returns the
  // record metadata (proof_id, record_id, timestamps, etc.); POST
  // /ingest/proofs/verify returns the authoritative four-state status
  // (verified / pending / invalid / unknown) by reconstructing the stored
  // Poseidon snapshot. The card shows the GET metadata first, then upgrades
  // the verdict the moment the snapshot result arrives. This avoids the
  // earlier UX where a freshly-committed record with no snapshot yet rendered
  // as "PROOF_FAILED" — pending is not failure.
  const reconcileVerdict = useCallback(
    async (data: HashVerificationResponse, requestId: number) => {
      // Drop the entire update if a newer submission has fired — applies to
      // the immediate baseline render too, since even the GET response of a
      // superseded submission shouldn't clobber the newer hash's state.
      const isCurrent = () => requestIdRef.current === requestId;
      if (!isCurrent()) return;

      const baseline = hashVerificationToVerdict(data);
      setVerdictResult({ ...baseline, displayHash: data.content_hash, raw: data });

      try {
        const snapshot = await verifyProofBundle({
          proof_id: data.proof_id,
          content_hash: data.content_hash,
          // The snapshot endpoint reconstructs root + path from server-stored
          // fields keyed by content_hash; the request body is required by
          // the schema but the values aren't trusted.
          merkle_root: data.merkle_root,
          merkle_proof: data.merkle_proof ?? {},
        });
        if (!isCurrent()) return;
        const upgraded = proofVerificationToVerdict(snapshot);
        setVerdictResult({
          ...upgraded,
          // Merge GET metadata details after the snapshot status so the
          // status line stays prominent at the top.
          details: [...upgraded.details, ...baseline.details],
          displayHash: data.content_hash,
          raw: data,
        });
        addRecentVerification({
          hash: data.content_hash,
          type: pendingSourceRef.current,
          verdict: upgraded.verdict,
          timestamp: Date.now(),
        });
      } catch {
        // Snapshot endpoint failed (network, 5xx, etc.) — fall back to the
        // GET-only verdict so we don't blank the panel, but still respect the
        // staleness check so we don't overwrite a newer submission's history.
        if (!isCurrent()) return;
        addRecentVerification({
          hash: data.content_hash,
          type: pendingSourceRef.current,
          verdict: baseline.verdict,
          timestamp: Date.now(),
        });
      }
    },
    [setVerdictResult],
  );

  const hashMutation = useMutation({
    mutationFn: ({ hash }: { hash: string; requestId: number }) =>
      verifyHash(hash, apiKey),
    onSuccess: (data, variables) => {
      // Use the requestId captured at submit time, not the live counter —
      // a newer submission may have bumped it while this mutation was in
      // flight, and we want that newer submission to win.
      void reconcileVerdict(data, variables.requestId);
    },
    onError: (err, variables) => {
      // Same staleness guard as the success path: an older submission's
      // error must not overwrite a newer submission's verdict / error
      // surface. Use variables.hash too, so the rendered "Queried Hash"
      // is the one this mutation actually ran against, not whatever
      // pendingHashRef happens to point at by the time onError fires.
      if (variables.requestId !== requestIdRef.current) return;
      if (err instanceof Error && err.message.includes("404")) {
        const qHash = variables.hash;
        setVerdictResult({
          verdict: "unknown",
          details: [{ key: "Queried Hash", value: qHash, status: "warn", copyable: true }],
          displayHash: qHash || undefined,
        });
        addRecentVerification({
          hash: qHash,
          type: pendingSourceRef.current,
          verdict: "unknown",
          timestamp: Date.now(),
        });
      } else {
        setHashError(err instanceof Error ? err.message : "Verification failed");
      }
    },
  });

  const submitHash = useCallback(
    (hash: string, source: HashVerificationSource = "hash") => {
      setHashError(null);
      setVerdictResult(null);
      const normalized = hash.trim().toLowerCase();
      if (!HASH_RE.test(normalized)) {
        setHashError("Enter a valid 64-character hexadecimal BLAKE3 hash");
        return;
      }
      pendingHashRef.current = normalized;
      pendingSourceRef.current = source;
      // Bump the submission id so any in-flight reconcileVerdict from a
      // previous submission aborts before touching state. The new id is
      // captured into the mutation variables so onSuccess sees the value
      // it was *scheduled* under, not whatever the counter is when the
      // network response lands.
      requestIdRef.current += 1;
      const requestId = requestIdRef.current;
      setHashInput(normalized);
      hashMutation.mutate({ hash: normalized, requestId });
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [hashMutation],
  );

  const pasteHash = useCallback(async () => {
    try {
      const text = await navigator.clipboard.readText();
      setHashInput(text.trim());
      setHashError(null);
    } catch {
      setHashError("Clipboard read was blocked by the browser");
    }
  }, []);

  const reset = useCallback(() => {
    setHashInput("");
    setHashError(null);
  }, []);

  return {
    hashInput,
    setHashInput,
    hashError,
    setHashError,
    hashStatus,
    hashMutation,
    apiKey,
    setApiKey,
    submitHash,
    pasteHash,
    reset,
  };
}
