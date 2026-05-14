import { useCallback, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { verifyProofBundle } from "../lib/api";
import { addRecentVerification } from "../lib/storage";
import type { VerdictState } from "../lib/types";
import { proofVerificationToVerdict } from "../lib/verdictHelpers";
import { parseProofBundleInput, serializeProofBundle } from "../lib/proofBundle";

export function useProofVerification(
  setVerdictResult: (r: VerdictState | null) => void,
) {
  const [proofInput, setProofInput] = useState("");
  const [proofError, setProofError] = useState<string | null>(null);

  const proofMutation = useMutation({
    mutationFn: verifyProofBundle,
    onSuccess: (data, submittedBundle) => {
      const result = proofVerificationToVerdict(data);
      const proofBundleJson = serializeProofBundle({
        proof_id: data.proof_id ?? submittedBundle.proof_id,
        content_hash: data.content_hash,
        merkle_root: data.merkle_root,
        merkle_proof: submittedBundle.merkle_proof,
      });
      setVerdictResult({ ...result, displayHash: data.content_hash, proofBundleJson });
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
      const parsed = parseProofBundleInput(proofInput);
      proofMutation.mutate(parsed);
    } catch {
      const looksLikeVerdictSummary =
        proofInput.includes("CONTENT_HASH") ||
        proofInput.includes("ACCESS_GRANTED") ||
        proofInput.includes("MERKLE_PROOF");
      setProofError(
        looksLikeVerdictSummary
          ? "That is the display summary, not JSON. Use LOAD_VERIFIED_BUNDLE or DOWNLOAD_JSON."
          : "Invalid JSON: paste the full proof bundle",
      );
    }
  }, [proofInput, proofMutation, setVerdictResult]);

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
