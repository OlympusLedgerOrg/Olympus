import { useCallback, useMemo, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { verifyHash } from "../lib/api";
import { addRecentVerification } from "../lib/storage";
import type { Tab, VerdictState } from "../lib/types";
import { hashVerificationToVerdict } from "../lib/verdictHelpers";
import { HASH_RE } from "../lib/constants";

export function useHashVerification(
  setVerdictResult: (r: VerdictState | null) => void,
  activeTab: Tab,
) {
  const [hashInput, setHashInput] = useState("");
  const [hashError, setHashError] = useState<string | null>(null);

  // Tracks the most recent hash submitted so the onError callback always has
  // the correct value regardless of React's re-render timing.
  const pendingHashRef = useRef<string>("");

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

  const hashMutation = useMutation({
    mutationFn: verifyHash,
    onSuccess: (data) => {
      const result = hashVerificationToVerdict(data);
      setVerdictResult({ ...result, displayHash: data.content_hash });
      addRecentVerification({
        hash: data.content_hash,
        type: activeTab === "file" ? "file" : activeTab === "json" ? "json" : "hash",
        verdict: result.verdict,
        timestamp: Date.now(),
      });
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
          type: activeTab === "file" ? "file" : activeTab === "json" ? "json" : "hash",
          verdict: "unknown",
          timestamp: Date.now(),
        });
      } else {
        setHashError(err instanceof Error ? err.message : "Verification failed");
      }
    },
  });

  const submitHash = useCallback(
    (hash: string) => {
      setHashError(null);
      setVerdictResult(null);
      const normalized = hash.trim().toLowerCase();
      if (!HASH_RE.test(normalized)) {
        setHashError("Enter a valid 64-character hexadecimal BLAKE3 hash");
        return;
      }
      pendingHashRef.current = normalized;
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
    submitHash,
    pasteHash,
    reset,
  };
}
