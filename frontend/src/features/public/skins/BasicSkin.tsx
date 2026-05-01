/**
 * BasicSkin — Clean, reassuring public verification UI.
 *
 * Designed for general-audience users (journalists reading a published story,
 * members of the public following a document link) who need a clear,
 * confidence-inspiring answer to a single question:
 *
 *   "Was this document tampered with?"
 *
 * Aesthetic: minimal white/grey with a dominant green check or red cross.
 * No cryptographic jargon on the happy path — just a plain-language verdict.
 * Technical details are available in an expandable "Show details" section.
 *
 * Placeholder status: the core layout and wiring are complete; visual polish
 * (illustrations, animations) can be added in a future iteration.
 */

import { useState, type FC } from "react";
import type { VerificationEngineState } from "../verificationEngine";

export type BasicSkinProps = VerificationEngineState;

const VERDICT_LABELS: Record<string, { emoji: string; headline: string; subline: string; color: string }> = {
  verified: {
    emoji: "✅",
    headline: "Document verified",
    subline: "This record was found on the Olympus ledger and its cryptographic proof is valid.",
    color: "#16a34a",
  },
  failed: {
    emoji: "❌",
    headline: "Verification failed",
    subline: "The cryptographic proof does not match. This record may have been tampered with.",
    color: "#dc2626",
  },
  unknown: {
    emoji: "❓",
    headline: "Record not found",
    subline: "This hash has not been committed to the Olympus ledger, or the server could not be reached.",
    color: "#d97706",
  },
};

/**
 * Clean, accessible verification skin intended for general-audience users.
 *
 * Plain-language verdicts, accessible colour contrast, no cryptographic jargon
 * on the happy path.  Technical detail rows are hidden behind "Show details".
 */
export const BasicSkin: FC<BasicSkinProps> = ({
  tab,
  switchTab,
  hashInput,
  setHashInput,
  hashError,
  submitHash,
  loading,
  result,
}) => {
  const [showDetails, setShowDetails] = useState(false);

  const verdictCfg = result ? VERDICT_LABELS[result.verdict] ?? VERDICT_LABELS.unknown : null;

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#f9fafb",
        color: "#111827",
        fontFamily: "system-ui, -apple-system, sans-serif",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        padding: "3rem 1.25rem",
      }}
    >
      {/* Logo / wordmark */}
      <div style={{ marginBottom: "2.5rem", textAlign: "center" }}>
        <div
          style={{
            fontSize: "1.5rem",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            color: "#1e3a5f",
          }}
        >
          Olympus Ledger
        </div>
        <div style={{ fontSize: "0.85rem", color: "#6b7280", marginTop: "0.25rem" }}>
          Independent document verification
        </div>
      </div>

      {/* Verification card */}
      <div
        style={{
          width: "100%",
          maxWidth: "520px",
          background: "#fff",
          borderRadius: "0.75rem",
          boxShadow: "0 1px 4px rgba(0,0,0,0.08), 0 4px 16px rgba(0,0,0,0.04)",
          padding: "2rem",
        }}
      >
        {/* Skin switcher hint */}
        <div
          style={{
            display: "flex",
            justifyContent: "flex-end",
            marginBottom: "1.25rem",
          }}
        >
          {(["hash", "file", "proof"] as const).map((id) => (
            <button
              key={id}
              type="button"
              onClick={() => switchTab(id)}
              style={{
                padding: "0.3rem 0.75rem",
                fontSize: "0.75rem",
                background: tab === id ? "#1e3a5f" : "transparent",
                color: tab === id ? "#fff" : "#6b7280",
                border: "1px solid",
                borderColor: tab === id ? "#1e3a5f" : "#e5e7eb",
                borderRadius: "0.375rem",
                cursor: "pointer",
                marginLeft: "0.5rem",
                textTransform: "capitalize",
              }}
            >
              {id}
            </button>
          ))}
        </div>

        {/* Hash lookup (default view) */}
        {tab === "hash" && (
          <div>
            <label
              htmlFor="basic-hash-input"
              style={{
                display: "block",
                fontSize: "0.85rem",
                fontWeight: 500,
                color: "#374151",
                marginBottom: "0.5rem",
              }}
            >
              Enter a document hash
            </label>
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <input
                id="basic-hash-input"
                type="text"
                value={hashInput}
                onChange={(e) => setHashInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") submitHash(); }}
                placeholder="64-character BLAKE3 hex hash"
                maxLength={64}
                spellCheck={false}
                style={{
                  flex: 1,
                  padding: "0.625rem 0.875rem",
                  border: "1px solid #d1d5db",
                  borderRadius: "0.375rem",
                  fontSize: "0.85rem",
                  fontFamily: "monospace",
                  outline: "none",
                  color: "#111827",
                }}
              />
              <button
                type="button"
                onClick={submitHash}
                disabled={loading}
                style={{
                  padding: "0.625rem 1.25rem",
                  background: "#1e3a5f",
                  color: "#fff",
                  border: "none",
                  borderRadius: "0.375rem",
                  fontSize: "0.85rem",
                  fontWeight: 500,
                  cursor: loading ? "not-allowed" : "pointer",
                  opacity: loading ? 0.6 : 1,
                  flexShrink: 0,
                  transition: "opacity 0.15s",
                }}
              >
                {loading ? "Checking…" : "Verify"}
              </button>
            </div>
            {hashError && (
              <p style={{ color: "#dc2626", fontSize: "0.8rem", margin: "0.5rem 0 0" }}>
                {hashError}
              </p>
            )}
          </div>
        )}

        {/* File / proof tabs — minimal placeholder */}
        {tab !== "hash" && (
          <div
            style={{
              textAlign: "center",
              padding: "2rem 0",
              color: "#9ca3af",
              fontSize: "0.875rem",
            }}
          >
            Switch to the{" "}
            <button
              type="button"
              onClick={() => switchTab("hash")}
              style={{
                background: "none",
                border: "none",
                color: "#1e3a5f",
                cursor: "pointer",
                textDecoration: "underline",
                fontSize: "inherit",
                padding: 0,
              }}
            >
              Hash
            </button>{" "}
            tab, or use the full{" "}
            <strong>Mayhem</strong> skin for file drop and proof bundle verification.
          </div>
        )}

        {/* Verdict */}
        {verdictCfg && result && (
          <div style={{ marginTop: "1.5rem" }}>
            <div
              style={{
                textAlign: "center",
                padding: "1.5rem",
                background: "#f9fafb",
                borderRadius: "0.5rem",
                border: `2px solid ${verdictCfg.color}22`,
              }}
            >
              <div style={{ fontSize: "2.5rem", marginBottom: "0.5rem" }}>
                {verdictCfg.emoji}
              </div>
              <div
                style={{
                  fontSize: "1.1rem",
                  fontWeight: 600,
                  color: verdictCfg.color,
                  marginBottom: "0.4rem",
                }}
              >
                {verdictCfg.headline}
              </div>
              <div style={{ fontSize: "0.875rem", color: "#6b7280", lineHeight: 1.5 }}>
                {verdictCfg.subline}
              </div>

              {result.localVerdict !== undefined && (
                <div
                  style={{
                    display: "inline-block",
                    marginTop: "0.75rem",
                    fontSize: "0.75rem",
                    color: result.localVerdict ? "#16a34a" : "#dc2626",
                    background: result.localVerdict ? "#dcfce7" : "#fee2e2",
                    padding: "0.25rem 0.75rem",
                    borderRadius: "9999px",
                  }}
                >
                  {result.localVerdict
                    ? "✓ Locally re-verified (no server trust required)"
                    : "⚠ Local verification failed"}
                </div>
              )}
            </div>

            {/* Show/hide details */}
            <button
              type="button"
              onClick={() => setShowDetails((v) => !v)}
              style={{
                display: "block",
                width: "100%",
                marginTop: "0.75rem",
                padding: "0.5rem",
                background: "none",
                border: "none",
                color: "#6b7280",
                fontSize: "0.8rem",
                cursor: "pointer",
                textAlign: "center",
              }}
            >
              {showDetails ? "Hide details ▲" : "Show technical details ▼"}
            </button>

            {showDetails && (
              <div
                style={{
                  marginTop: "0.5rem",
                  borderTop: "1px solid #e5e7eb",
                  paddingTop: "0.75rem",
                }}
              >
                {result.details.map((d) => (
                  <div
                    key={d.key}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      gap: "1rem",
                      padding: "0.3rem 0",
                      borderBottom: "1px solid #f3f4f6",
                      fontSize: "0.75rem",
                    }}
                  >
                    <span style={{ color: "#9ca3af", flexShrink: 0 }}>
                      {d.key}
                    </span>
                    <span
                      style={{
                        fontFamily: "monospace",
                        color: "#374151",
                        wordBreak: "break-all",
                        textAlign: "right",
                      }}
                    >
                      {d.value}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Footer */}
      <div
        style={{
          marginTop: "2.5rem",
          fontSize: "0.75rem",
          color: "#9ca3af",
          textAlign: "center",
        }}
      >
        Proofs verified locally in your browser · No server trust required
      </div>
    </div>
  );
};

export default BasicSkin;
