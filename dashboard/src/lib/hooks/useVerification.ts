"use client";

import { useCallback, useState } from "react";
import { useAuth } from "@/lib/hooks/useAuth";
import {
  createLocationClaim,
  sanitizeProof,
  validateVerificationProof,
  type VerificationMethod,
  type VerificationProof,
  type VerificationRecord,
  type VerificationRequestPayload,
  type VerificationResponse,
} from "@/lib/utils/verification";

type VerificationStatus = "idle" | "submitting" | "success" | "error";

type VerificationSubmission = {
  method: VerificationMethod;
  proof: VerificationProof;
  locationZip: string;
  consent: boolean;
  assertion: boolean;
};

type VerificationState = {
  status: VerificationStatus;
  error?: string;
};

export function useVerification() {
  const { walletAddress, saveVerification } = useAuth();
  const [state, setState] = useState<VerificationState>({ status: "idle" });

  const submitVerification = useCallback(
    async (submission: VerificationSubmission): Promise<VerificationRecord | null> => {
      if (!walletAddress) {
        setState({ status: "error", error: "Connect a wallet before verifying." });
        return null;
      }

      const proofCheck = validateVerificationProof(
        submission.method,
        submission.proof,
      );
      if (!proofCheck.valid) {
        setState({ status: "error", error: proofCheck.issues.join(" ") });
        return null;
      }

      setState({ status: "submitting" });
      try {
        const location = createLocationClaim(submission.locationZip);
        const payload: VerificationRequestPayload = {
          walletAddress,
          method: submission.method,
          proof: sanitizeProof(submission.method, submission.proof),
          location,
          consent: submission.consent,
          assertion: submission.assertion,
        };

        const response = await fetch("/api/auth/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        if (!response.ok) {
          const errorBody = (await response.json()) as { error?: string };
          setState({
            status: "error",
            error: errorBody.error ?? "Verification failed. Please retry.",
          });
          return null;
        }

        const data = (await response.json()) as VerificationResponse;
        saveVerification(data.record);
        setState({ status: "success" });
        return data.record;
      } catch (error) {
        const message =
          error instanceof Error
            ? error.message
            : "Verification failed. Please retry.";
        setState({ status: "error", error: message });
        return null;
      }
    },
    [walletAddress, saveVerification],
  );

  const reset = useCallback(() => {
    setState({ status: "idle" });
  }, []);

  return {
    status: state.status,
    error: state.error,
    submitVerification,
    reset,
  };
}
