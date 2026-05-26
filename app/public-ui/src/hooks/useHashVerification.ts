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
    async (data: HashVerificationResponse) => {
      const baseline = hashVerificationToVerdict(data);
      // Render baseline immediately so the user sees record metadata while
      // the snapshot verify is in flight.
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
        // GET-only verdict so we don't blank the panel.
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
    mutationFn: (hash: string) => verifyHash(hash, apiKey),
    onSuccess: (data) => {
      void reconcileVerdict(data);
    },
    onError: (err) => {
      if (err instanceof Error && err.message.includes("404")) {
        const qHash = pendingHashRef.current;
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
      setHashInput(normalized);
      hashMutation.mutate(normalized);
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
