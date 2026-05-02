import { useCallback, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { verifyProofBundle } from "../lib/api";
import { addRecentVerification } from "../lib/storage";
import type { ProofVerificationRequest, VerdictState } from "../lib/types";
import { proofVerificationToVerdict } from "../lib/verdictHelpers";

export function useProofVerification(
  setVerdictResult: (r: VerdictState | null) => void,
) {
  const [proofInput, setProofInput] = useState("");
  const [proofError, setProofError] = useState<string | null>(null);

  const proofMutation = useMutation({
    mutationFn: verifyProofBundle,
    onSuccess: (data) => {
      const result = proofVerificationToVerdict(data);
      setVerdictResult({ ...result, displayHash: data.content_hash });
      addRecentVerification({
        hash: data.content_hash,
        type: "proof",
        verdict: result.verdict,
        timestamp: Date.now(),
      });
    },
    onError: (err) => {
      setProofError(err instanceof Error ? err.message : "Verification failed");
    },
  });

  const submitProof = useCallback(() => {
    setProofError(null);
    setVerdictResult(null);
    try {
      const parsed = JSON.parse(proofInput) as ProofVerificationRequest;
      if (!parsed.content_hash || !parsed.merkle_root || !parsed.merkle_proof) {
        setProofError("Bundle must include content_hash, merkle_root, and merkle_proof");
        return;
      }
      proofMutation.mutate(parsed);
    } catch {
      setProofError("Invalid JSON: paste the full proof bundle");
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [proofInput, proofMutation]);

  const reset = useCallback(() => {
    setProofInput("");
    setProofError(null);
  }, []);

  return {
    proofInput,
    setProofInput,
    proofError,
    setProofError,
    proofMutation,
    submitProof,
    reset,
  };
}
