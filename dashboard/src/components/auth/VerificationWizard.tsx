"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { WalletConnect } from "@/components/auth/WalletConnect";
import { VerificationBadge } from "@/components/auth/VerificationBadge";
import { useAuth } from "@/lib/hooks/useAuth";
import { useVerification } from "@/lib/hooks/useVerification";
import {
  VERIFICATION_METHODS,
  maskZip,
  isValidZipCode,
  sanitizeProof,
  validateVerificationProof,
  type VerificationMethod,
  type VerificationProof,
} from "@/lib/utils/verification";

const steps = [
  "Connect wallet",
  "Choose method",
  "Prove humanity",
  "Share location",
  "Mint verification SBT",
];

export function VerificationWizard() {
  const { isConnected, verificationRecord, verificationStatus } = useAuth();
  const { status, error, submitVerification, reset } = useVerification();
  const [step, setStep] = useState(0);
  const [method, setMethod] = useState<VerificationMethod>("social-graph");
  const [proof, setProof] = useState<VerificationProof>({});
  const [locationZip, setLocationZip] = useState("");
  const [assertion, setAssertion] = useState(false);
  const [consent, setConsent] = useState(false);

  useEffect(() => {
    if (verificationRecord) {
      setStep(steps.length - 1);
    }
  }, [verificationRecord]);

  const proofValidation = useMemo(
    () => validateVerificationProof(method, proof),
    [method, proof],
  );
  const zipValid = isValidZipCode(locationZip);
  const sanitizedProof = useMemo(() => sanitizeProof(method, proof), [method, proof]);

  const canAdvance = [
    isConnected,
    true,
    proofValidation.valid,
    proofValidation.valid && zipValid && assertion && consent,
  ];

  const handleNext = () => {
    if (step < steps.length - 1 && canAdvance[step]) {
      setStep(step + 1);
    }
  };

  const handleBack = () => {
    if (step > 0) {
      setStep(step - 1);
    }
  };

  const handleSubmit = async () => {
    const record = await submitVerification({
      method,
      proof: sanitizedProof,
      locationZip,
      assertion,
      consent,
    });
    if (record) {
      setStep(steps.length - 1);
    }
  };

  const resetFlow = () => {
    reset();
    setStep(0);
    setAssertion(false);
    setConsent(false);
    setLocationZip("");
    setProof({});
  };

  return (
    <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-5 text-xs uppercase tracking-[0.2em]">
        {steps.map((label, index) => (
          <div
            key={label}
            className="border px-2 py-2 text-center"
            style={{
              background:
                step >= index ? "var(--color-surface)" : "var(--color-surface-muted)",
              borderColor: "var(--color-border)",
              borderRadius: "var(--radius)",
              color: step >= index ? "var(--color-text)" : "var(--color-text-muted)",
            }}
          >
            {label}
          </div>
        ))}
      </div>

      {verificationStatus === "verified" && verificationRecord ? (
        <div className="space-y-4">
          <VerificationBadge />
          <div
            className="border px-4 py-3 text-sm"
            style={{
              background: "var(--color-surface-muted)",
              borderColor: "var(--color-border)",
              borderRadius: "var(--radius)",
              color: "var(--color-text-muted)",
            }}
          >
            Verification is already active. You can proceed to the protected
            dashboard or reset to test another flow.
          </div>
          <div className="flex flex-wrap gap-3 text-sm">
            <Link
              href="/dashboard"
              className="border px-4 py-2 font-semibold"
              style={{
                borderColor: "var(--color-border)",
                borderRadius: "var(--radius)",
                color: "var(--color-primary)",
              }}
            >
              Go to dashboard
            </Link>
            <button
              type="button"
              onClick={resetFlow}
              className="border px-4 py-2"
              style={{
                borderColor: "var(--color-border)",
                borderRadius: "var(--radius)",
                color: "var(--color-text-muted)",
              }}
            >
              Restart verification
            </button>
          </div>
        </div>
      ) : (
        <>
          {step === 0 && (
            <section className="space-y-3">
              <h2 className="text-lg font-semibold">Connect wallet</h2>
              <p style={{ color: "var(--color-text-muted)" }}>
                Olympus Civic requires a wallet connection to mint a human-only
                SBT.
              </p>
              <WalletConnect />
            </section>
          )}

          {step === 1 && (
            <section className="space-y-3">
              <h2 className="text-lg font-semibold">Choose verification method</h2>
              <p style={{ color: "var(--color-text-muted)" }}>
                Select the proof of personhood flow that best fits your identity
                stack.
              </p>
              <div className="grid gap-4 md:grid-cols-3">
                {VERIFICATION_METHODS.map((option) => (
                  <button
                    key={option.id}
                    type="button"
                    onClick={() => setMethod(option.id)}
                    className="border p-4 text-left space-y-2"
                    style={{
                      borderColor: "var(--color-border)",
                      borderRadius: "var(--radius)",
                      background:
                        method === option.id
                          ? "var(--color-surface)"
                          : "var(--color-surface-muted)",
                    }}
                  >
                    <div className="text-sm font-semibold">{option.label}</div>
                    <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
                      {option.description}
                    </p>
                    <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
                      {option.disclaimer}
                    </p>
                  </button>
                ))}
              </div>
            </section>
          )}

          {step === 2 && (
            <section className="space-y-3">
              <h2 className="text-lg font-semibold">Prove humanity</h2>
              <p style={{ color: "var(--color-text-muted)" }}>
                Provide anonymized evidence that you are a unique human.
              </p>
              {method === "world-id" && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <input
                    type="text"
                    placeholder="World ID proof"
                    value={proof.worldIdProof ?? ""}
                    onChange={(event) =>
                      setProof((prev) => ({
                        ...prev,
                        worldIdProof: event.target.value,
                      }))
                    }
                    className="border px-3 py-2 text-sm"
                    style={{
                      borderColor: "var(--color-border)",
                      borderRadius: "var(--radius)",
                      background: "var(--color-surface)",
                    }}
                  />
                  <input
                    type="text"
                    placeholder="Nullifier hash"
                    value={proof.worldIdNullifier ?? ""}
                    onChange={(event) =>
                      setProof((prev) => ({
                        ...prev,
                        worldIdNullifier: event.target.value,
                      }))
                    }
                    className="border px-3 py-2 text-sm"
                    style={{
                      borderColor: "var(--color-border)",
                      borderRadius: "var(--radius)",
                      background: "var(--color-surface)",
                    }}
                  />
                </div>
              )}
              {method === "gitcoin-passport" && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <input
                    type="text"
                    placeholder="Passport ID"
                    value={proof.passportId ?? ""}
                    onChange={(event) =>
                      setProof((prev) => ({
                        ...prev,
                        passportId: event.target.value,
                      }))
                    }
                    className="border px-3 py-2 text-sm"
                    style={{
                      borderColor: "var(--color-border)",
                      borderRadius: "var(--radius)",
                      background: "var(--color-surface)",
                    }}
                  />
                  <input
                    type="number"
                    placeholder="Passport score"
                    value={proof.passportScore ?? ""}
                    onChange={(event) =>
                      setProof((prev) => ({
                        ...prev,
                        passportScore: Number(event.target.value),
                      }))
                    }
                    className="border px-3 py-2 text-sm"
                    style={{
                      borderColor: "var(--color-border)",
                      borderRadius: "var(--radius)",
                      background: "var(--color-surface)",
                    }}
                  />
                </div>
              )}
              {method === "social-graph" && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <select
                    value={proof.socialPlatform ?? ""}
                    onChange={(event) =>
                      setProof((prev) => ({
                        ...prev,
                        socialPlatform: event.target.value,
                      }))
                    }
                    className="border px-3 py-2 text-sm"
                    style={{
                      borderColor: "var(--color-border)",
                      borderRadius: "var(--radius)",
                      background: "var(--color-surface)",
                    }}
                  >
                    <option value="">Select platform</option>
                    <option value="x">X</option>
                    <option value="farcaster">Farcaster</option>
                    <option value="github">GitHub</option>
                  </select>
                  <input
                    type="text"
                    placeholder="Social handle"
                    value={proof.socialHandle ?? ""}
                    onChange={(event) =>
                      setProof((prev) => ({
                        ...prev,
                        socialHandle: event.target.value,
                      }))
                    }
                    className="border px-3 py-2 text-sm"
                    style={{
                      borderColor: "var(--color-border)",
                      borderRadius: "var(--radius)",
                      background: "var(--color-surface)",
                    }}
                  />
                  <input
                    type="text"
                    placeholder="Attestation hash"
                    value={proof.socialProof ?? ""}
                    onChange={(event) =>
                      setProof((prev) => ({
                        ...prev,
                        socialProof: event.target.value,
                      }))
                    }
                    className="border px-3 py-2 text-sm sm:col-span-2"
                    style={{
                      borderColor: "var(--color-border)",
                      borderRadius: "var(--radius)",
                      background: "var(--color-surface)",
                    }}
                  />
                  <input
                    type="number"
                    placeholder="Confirmed connections"
                    value={proof.socialGraphConnections ?? ""}
                    onChange={(event) =>
                      setProof((prev) => ({
                        ...prev,
                        socialGraphConnections: Number(event.target.value),
                      }))
                    }
                    className="border px-3 py-2 text-sm"
                    style={{
                      borderColor: "var(--color-border)",
                      borderRadius: "var(--radius)",
                      background: "var(--color-surface)",
                    }}
                  />
                </div>
              )}
              {!proofValidation.valid && (
                <div
                  className="border px-3 py-2 text-xs"
                  style={{
                    borderColor: "var(--color-danger)",
                    borderRadius: "var(--radius)",
                    color: "var(--color-danger)",
                    background: "var(--color-danger-bg)",
                  }}
                >
                  {proofValidation.issues.join(" ")}
                </div>
              )}
            </section>
          )}

          {step === 3 && (
            <section className="space-y-3">
              <h2 className="text-lg font-semibold">Share location</h2>
              <p style={{ color: "var(--color-text-muted)" }}>
                Share a ZIP code so Olympus can mint a location-scoped SBT.
                Only the ZIP3 prefix is retained.
              </p>
              <input
                type="text"
                placeholder="ZIP code (5 digits)"
                value={locationZip}
                onChange={(event) => setLocationZip(event.target.value)}
                className="border px-3 py-2 text-sm"
                style={{
                  borderColor: "var(--color-border)",
                  borderRadius: "var(--radius)",
                  background: "var(--color-surface)",
                }}
              />
              {locationZip && (
                <div
                  className="text-xs"
                  style={{ color: "var(--color-text-muted)" }}
                >
                  Stored location hint: {maskZip(locationZip)}
                </div>
              )}
              <label className="flex items-start gap-2 text-xs">
                <input
                  type="checkbox"
                  checked={assertion}
                  onChange={(event) => setAssertion(event.target.checked)}
                />
                <span>I attest that I am a unique human and not an organization.</span>
              </label>
              <label className="flex items-start gap-2 text-xs">
                <input
                  type="checkbox"
                  checked={consent}
                  onChange={(event) => setConsent(event.target.checked)}
                />
                <span>I consent to minting a non-transferable verification SBT.</span>
              </label>
              {!zipValid && locationZip.length > 0 && (
                <div
                  className="text-xs"
                  style={{ color: "var(--color-danger)" }}
                >
                  Enter a valid 5-digit ZIP code.
                </div>
              )}
            </section>
          )}

          {step === 4 && (
            <section className="space-y-4">
              <h2 className="text-lg font-semibold">Mint verification SBT</h2>
              <div
                className="border px-4 py-3 text-sm"
                style={{
                  background: "var(--color-surface-muted)",
                  borderColor: "var(--color-border)",
                  borderRadius: "var(--radius)",
                  color: "var(--color-text-muted)",
                }}
              >
                <p>Method: {method.replace("-", " ")}</p>
                <p>Location hint: {maskZip(locationZip)}</p>
                <p>Proof fields: {Object.keys(sanitizedProof).length}</p>
              </div>
              <button
                type="button"
                onClick={handleSubmit}
                disabled={status === "submitting" || !canAdvance[3]}
                className="border px-4 py-2 text-sm font-semibold"
                style={{
                  borderColor: "var(--color-border)",
                  borderRadius: "var(--radius)",
                  color: "var(--color-primary)",
                }}
              >
                {status === "submitting" ? "Verifying…" : "Verify & mint SBT"}
              </button>
              {error && (
                <div
                  className="border px-3 py-2 text-xs"
                  style={{
                    borderColor: "var(--color-danger)",
                    borderRadius: "var(--radius)",
                    color: "var(--color-danger)",
                    background: "var(--color-danger-bg)",
                  }}
                >
                  {error}
                </div>
              )}
              {status === "success" && verificationRecord && (
                <div className="space-y-3">
                  <VerificationBadge />
                  <Link
                    href="/dashboard"
                    className="inline-flex items-center gap-2 text-sm font-semibold"
                    style={{ color: "var(--color-primary)" }}
                  >
                    Access dashboard →
                  </Link>
                </div>
              )}
            </section>
          )}

          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              onClick={handleBack}
              disabled={step === 0}
              className="border px-4 py-2 text-sm"
              style={{
                borderColor: "var(--color-border)",
                borderRadius: "var(--radius)",
                color: "var(--color-text-muted)",
              }}
            >
              Back
            </button>
            {step < steps.length - 1 && (
              <button
                type="button"
                onClick={handleNext}
                disabled={!canAdvance[step]}
                className="border px-4 py-2 text-sm font-semibold"
                style={{
                  borderColor: "var(--color-border)",
                  borderRadius: "var(--radius)",
                  color: "var(--color-primary)",
                }}
              >
                Next
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
}
