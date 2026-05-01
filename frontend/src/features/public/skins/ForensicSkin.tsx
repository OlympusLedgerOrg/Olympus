/**
 * ForensicSkin — Detailed analytical verification UI.
 *
 * Designed for technically-proficient investigators (OSINT analysts, forensic
 * journalists, security researchers) who need to see every verifiable detail
 * about a ledger record:
 *
 * • Full Merkle proof path visualisation (sibling hashes + positions)
 * • Raw cryptographic field display (BLAKE3 digests, Poseidon roots)
 * • Step-by-step audit trail for the verification pipeline
 * • Copy-to-clipboard for every hash value
 * • JSON proof bundle export
 *
 * Aesthetic: dense information, monospace everywhere, dark-but-readable grey
 * palette.  Think Wireshark meets a diff tool.
 *
 * Placeholder status: the core layout and wiring are complete; the Merkle tree
 * path visualisation is a simplified list — a full tree diagram can be added
 * in a future iteration.
 */

import { useState, type FC } from "react";
import type { VerificationEngineState } from "../verificationEngine";

export type ForensicSkinProps = VerificationEngineState;

// ─── Sub-components ───────────────────────────────────────────────────────────

const CopyButton: FC<{ text: string }> = ({ text }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = (): void => {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      title="Copy to clipboard"
      style={{
        padding: "0.1rem 0.4rem",
        fontSize: "0.65rem",
        background: copied ? "#374151" : "transparent",
        border: "1px solid #374151",
        borderRadius: "0.25rem",
        color: copied ? "#9ca3af" : "#6b7280",
        cursor: "pointer",
        flexShrink: 0,
        transition: "all 0.15s",
        fontFamily: "monospace",
      }}
    >
      {copied ? "✓" : "copy"}
    </button>
  );
};

const FieldRow: FC<{ label: string; value: string; mono?: boolean; full?: boolean }> = ({
  label,
  value,
  mono = true,
  full = false,
}) => (
  <div
    style={{
      display: "grid",
      gridTemplateColumns: full ? "1fr" : "180px 1fr auto",
      gap: "0.5rem",
      padding: "0.4rem 0",
      borderBottom: "1px solid #1f2937",
      alignItems: "start",
    }}
  >
    <span
      style={{
        fontSize: "0.7rem",
        color: "#6b7280",
        fontFamily: "monospace",
        paddingTop: "0.05rem",
      }}
    >
      {label}
    </span>
    <span
      style={{
        fontSize: "0.72rem",
        fontFamily: mono ? "monospace" : "inherit",
        color: "#e5e7eb",
        wordBreak: "break-all",
      }}
    >
      {value}
    </span>
    <CopyButton text={value} />
  </div>
);

const AuditStep: FC<{
  index: number;
  label: string;
  status: "ok" | "fail" | "pending" | "skip";
  detail?: string;
}> = ({ index, label, status, detail }) => {
  const statusCfg = {
    ok: { color: "#22c55e", icon: "✓" },
    fail: { color: "#ef4444", icon: "✗" },
    pending: { color: "#f59e0b", icon: "…" },
    skip: { color: "#374151", icon: "—" },
  };
  const cfg = statusCfg[status];

  return (
    <div
      style={{
        display: "flex",
        gap: "0.75rem",
        padding: "0.5rem 0",
        borderBottom: "1px solid #1f2937",
      }}
    >
      <div
        style={{
          fontSize: "0.65rem",
          color: "#374151",
          fontFamily: "monospace",
          flexShrink: 0,
          paddingTop: "0.1rem",
          width: "1.5rem",
          textAlign: "right",
        }}
      >
        {(index + 1).toString().padStart(2, "0")}
      </div>
      <div style={{ flex: 1 }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span style={{ fontSize: "0.8rem", color: "#d1d5db" }}>{label}</span>
          <span
            style={{
              fontSize: "0.72rem",
              fontFamily: "monospace",
              color: cfg.color,
              fontWeight: "bold",
            }}
          >
            {cfg.icon}
          </span>
        </div>
        {detail && (
          <div
            style={{
              fontSize: "0.7rem",
              color: "#6b7280",
              fontFamily: "monospace",
              marginTop: "0.2rem",
              wordBreak: "break-all",
            }}
          >
            {detail}
          </div>
        )}
      </div>
    </div>
  );
};

// ─── ForensicSkin ─────────────────────────────────────────────────────────────

/**
 * Detailed analytical verification skin for technically-proficient investigators.
 *
 * Shows the full cryptographic audit trail: BLAKE3 hashes, Merkle proof path,
 * server vs. client verification results, and proof-bundle export.
 */
export const ForensicSkin: FC<ForensicSkinProps> = ({
  tab,
  switchTab,
  hashInput,
  setHashInput,
  hashError,
  submitHash,
  proofInput,
  setProofInput,
  proofError,
  submitProof,
  loading,
  result,
  recents,
}) => {
  const [exportOpen, setExportOpen] = useState(false);

  const auditSteps = result
    ? [
        {
          label: "Hash format validated (64-char BLAKE3 hex)",
          status: "ok" as const,
          detail: result.hash,
        },
        {
          label: "Ledger lookup via GET /ingest/records/hash/{hash}/verify",
          status: result.verdict !== "unknown" ? ("ok" as const) : ("fail" as const),
        },
        {
          label: "Server-side Merkle proof verified",
          status:
            result.verdict === "verified"
              ? ("ok" as const)
              : result.verdict === "failed"
                ? ("fail" as const)
                : ("skip" as const),
          detail: result.details.find((d) => d.key === "SERVER_VERIFIED")?.value,
        },
        {
          label: "Client-side Merkle proof re-verified (no server trust)",
          status:
            result.localVerdict === true
              ? ("ok" as const)
              : result.localVerdict === false
                ? ("fail" as const)
                : ("skip" as const),
          detail:
            result.localVerdict !== undefined
              ? result.localVerdict
                ? "Root hash matches"
                : "Root hash MISMATCH"
              : "Proof not available",
        },
      ]
    : [];

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#111827",
        color: "#d1d5db",
        fontFamily: "monospace",
        padding: "0",
      }}
    >
      {/* Top bar */}
      <div
        style={{
          background: "#0f172a",
          borderBottom: "1px solid #1f2937",
          padding: "0.75rem 1.5rem",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "1rem",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <span
            style={{
              fontSize: "0.8rem",
              color: "#3b82f6",
              fontWeight: "bold",
              letterSpacing: "0.05em",
            }}
          >
            OLYMPUS / FORENSIC
          </span>
          <span style={{ color: "#374151", fontSize: "0.7rem" }}>
            v0.1 — Merkle Proof Analyser
          </span>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          {(["hash", "proof"] as const).map((id) => (
            <button
              key={id}
              type="button"
              onClick={() => switchTab(id)}
              style={{
                padding: "0.3rem 0.75rem",
                fontSize: "0.7rem",
                background: tab === id ? "#1d4ed8" : "transparent",
                color: tab === id ? "#fff" : "#6b7280",
                border: "1px solid",
                borderColor: tab === id ? "#1d4ed8" : "#374151",
                borderRadius: "0.25rem",
                cursor: "pointer",
                transition: "all 0.15s",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
              }}
            >
              {id}
            </button>
          ))}
        </div>
      </div>

      <div style={{ maxWidth: "900px", margin: "0 auto", padding: "1.5rem" }}>
        {/* Input panel */}
        <div
          style={{
            background: "#0f172a",
            border: "1px solid #1f2937",
            borderRadius: "0.5rem",
            padding: "1.25rem",
            marginBottom: "1.25rem",
          }}
        >
          {tab === "hash" && (
            <div>
              <div
                style={{
                  fontSize: "0.65rem",
                  color: "#6b7280",
                  marginBottom: "0.5rem",
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                }}
              >
                Target hash (BLAKE3, 64 hex chars)
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <input
                  type="text"
                  value={hashInput}
                  onChange={(e) => setHashInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") submitHash(); }}
                  placeholder="Enter 64-character BLAKE3 hex hash…"
                  maxLength={64}
                  spellCheck={false}
                  style={{
                    flex: 1,
                    background: "#1f2937",
                    border: "1px solid #374151",
                    padding: "0.6rem 0.75rem",
                    color: "#e5e7eb",
                    fontFamily: "monospace",
                    fontSize: "0.78rem",
                    outline: "none",
                    borderRadius: "0.25rem",
                    boxSizing: "border-box",
                  }}
                />
                <button
                  type="button"
                  onClick={submitHash}
                  disabled={loading}
                  style={{
                    padding: "0.6rem 1.25rem",
                    background: "#1d4ed8",
                    color: "#fff",
                    border: "none",
                    borderRadius: "0.25rem",
                    fontSize: "0.75rem",
                    fontFamily: "monospace",
                    cursor: loading ? "not-allowed" : "pointer",
                    opacity: loading ? 0.6 : 1,
                    textTransform: "uppercase",
                    letterSpacing: "0.05em",
                    flexShrink: 0,
                  }}
                >
                  {loading ? "QUERYING…" : "QUERY"}
                </button>
              </div>
              {hashError && (
                <p style={{ color: "#ef4444", fontSize: "0.75rem", margin: "0.5rem 0 0" }}>
                  {hashError}
                </p>
              )}
            </div>
          )}

          {tab === "proof" && (
            <div>
              <div
                style={{
                  fontSize: "0.65rem",
                  color: "#6b7280",
                  marginBottom: "0.5rem",
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                }}
              >
                Proof bundle JSON (content_hash + merkle_root + merkle_proof)
              </div>
              <textarea
                value={proofInput}
                onChange={(e) => setProofInput(e.target.value)}
                rows={6}
                placeholder='{"content_hash":"...","merkle_root":"...","merkle_proof":{"leafHash":"...","siblings":[...],"rootHash":"..."}}'
                spellCheck={false}
                style={{
                  width: "100%",
                  background: "#1f2937",
                  border: "1px solid #374151",
                  padding: "0.6rem 0.75rem",
                  color: "#e5e7eb",
                  fontFamily: "monospace",
                  fontSize: "0.72rem",
                  outline: "none",
                  resize: "vertical",
                  borderRadius: "0.25rem",
                  boxSizing: "border-box",
                }}
              />
              {proofError && (
                <p style={{ color: "#ef4444", fontSize: "0.75rem", margin: "0.5rem 0 0" }}>
                  {proofError}
                </p>
              )}
              <button
                type="button"
                onClick={() => void submitProof()}
                disabled={loading}
                style={{
                  marginTop: "0.75rem",
                  padding: "0.6rem 1.25rem",
                  background: "#1d4ed8",
                  color: "#fff",
                  border: "none",
                  borderRadius: "0.25rem",
                  fontSize: "0.75rem",
                  fontFamily: "monospace",
                  cursor: loading ? "not-allowed" : "pointer",
                  opacity: loading ? 0.6 : 1,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                }}
              >
                {loading ? "VERIFYING…" : "VERIFY BUNDLE"}
              </button>
            </div>
          )}
        </div>

        {/* Results panels */}
        {result && (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))",
              gap: "1rem",
            }}
          >
            {/* Audit trail */}
            <div
              style={{
                background: "#0f172a",
                border: "1px solid #1f2937",
                borderRadius: "0.5rem",
                padding: "1rem",
              }}
            >
              <div
                style={{
                  fontSize: "0.65rem",
                  color: "#6b7280",
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  marginBottom: "0.75rem",
                }}
              >
                Audit Trail
              </div>
              {auditSteps.map((step, i) => (
                <AuditStep key={i} index={i} {...step} />
              ))}
            </div>

            {/* Field detail */}
            <div
              style={{
                background: "#0f172a",
                border: "1px solid #1f2937",
                borderRadius: "0.5rem",
                padding: "1rem",
              }}
            >
              <div
                style={{
                  fontSize: "0.65rem",
                  color: "#6b7280",
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  marginBottom: "0.75rem",
                }}
              >
                Cryptographic Fields
              </div>
              {result.details.map((d) => (
                <FieldRow key={d.key} label={d.key} value={d.value} />
              ))}
            </div>
          </div>
        )}

        {/* Export proof bundle */}
        {result && result.verdict === "verified" && (
          <div
            style={{
              marginTop: "1rem",
              background: "#0f172a",
              border: "1px solid #1f2937",
              borderRadius: "0.5rem",
              padding: "1rem",
            }}
          >
            <button
              type="button"
              onClick={() => setExportOpen((v) => !v)}
              style={{
                background: "none",
                border: "none",
                color: "#6b7280",
                fontSize: "0.75rem",
                fontFamily: "monospace",
                cursor: "pointer",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                padding: 0,
              }}
            >
              {exportOpen ? "▼ Hide proof bundle JSON" : "▶ Export proof bundle JSON"}
            </button>
            {exportOpen && (
              <pre
                style={{
                  marginTop: "0.75rem",
                  background: "#1f2937",
                  padding: "0.875rem",
                  borderRadius: "0.25rem",
                  fontSize: "0.7rem",
                  color: "#e5e7eb",
                  overflowX: "auto",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                }}
              >
                {JSON.stringify(
                  Object.fromEntries(result.details.map((d) => [d.key, d.value])),
                  null,
                  2,
                )}
              </pre>
            )}
          </div>
        )}

        {/* Recent lookups */}
        {recents.length > 0 && (
          <div
            style={{
              marginTop: "1rem",
              background: "#0f172a",
              border: "1px solid #1f2937",
              borderRadius: "0.5rem",
              padding: "1rem",
            }}
          >
            <div
              style={{
                fontSize: "0.65rem",
                color: "#6b7280",
                textTransform: "uppercase",
                letterSpacing: "0.08em",
                marginBottom: "0.5rem",
              }}
            >
              Recent lookups
            </div>
            {recents.map((item, i) => (
              <div
                key={i}
                style={{
                  display: "flex",
                  gap: "1rem",
                  padding: "0.3rem 0",
                  borderBottom: "1px solid #1f2937",
                  fontSize: "0.72rem",
                }}
              >
                <span
                  style={{
                    color:
                      item.verdict === "verified"
                        ? "#22c55e"
                        : item.verdict === "failed"
                          ? "#ef4444"
                          : "#f59e0b",
                    flexShrink: 0,
                    fontWeight: "bold",
                  }}
                >
                  {item.verdict.toUpperCase()}
                </span>
                <span
                  style={{
                    fontFamily: "monospace",
                    color: "#9ca3af",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {item.hash}
                </span>
                <span style={{ color: "#374151", flexShrink: 0, fontSize: "0.65rem" }}>
                  {new Date(item.ts).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ForensicSkin;
