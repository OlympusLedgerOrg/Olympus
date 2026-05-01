import { useEffect } from "react";
import { playGlitchSound } from "../lib/audio";
import CopyButton from "./CopyButton";
import type { Verdict, VerdictDetail } from "../lib/types";

const VERDICT_CFG: Record<
  Verdict,
  { color: string; borderColor: string; icon: string; label: string; desc: string }
> = {
  verified: {
    color: "#00FF41",
    borderColor: "#00FF41",
    icon: "✓",
    label: ">>> ACCESS_GRANTED",
    desc: "Record exists on the ledger and the Merkle proof is cryptographically valid.",
  },
  failed: {
    color: "#ff0055",
    borderColor: "#ff0055",
    icon: "✗",
    label: ">>> SECURITY_BREACH_DETECTED",
    desc: "Hash or Merkle proof mismatch — possible tampering or corrupted proof bundle.",
  },
  unknown: {
    color: "#f59e0b",
    borderColor: "#f59e0b",
    icon: "?",
    label: ">>> RECORD_NOT_FOUND",
    desc: "This hash has not been committed to the Olympus ledger, or the server could not be reached.",
  },
};

const statusColor: Record<string, string> = {
  ok: "#00FF41",
  err: "#ff0055",
  warn: "#f59e0b",
  neutral: "rgba(0,255,65,0.4)",
};

interface VerdictCardProps {
  verdict: Verdict;
  details?: VerdictDetail[];
  localVerdict?: boolean;
}

export default function VerdictCard({
  verdict,
  details = [],
  localVerdict,
}: VerdictCardProps) {
  const cfg = VERDICT_CFG[verdict];

  useEffect(() => {
    if (verdict === "verified") playGlitchSound("success");
    else if (verdict === "failed") playGlitchSound("fail");
    else playGlitchSound("noise");
  }, [verdict]);

  return (
    <div
      className="verdict-card"
      style={{
        marginTop: "1.5rem",
        border: `1px solid ${cfg.borderColor}`,
        background: "rgba(0,0,0,0.92)",
        padding: "1.25rem 1.5rem",
        clipPath: "polygon(0 0, 96% 0, 100% 4%, 100% 100%, 4% 100%, 0 96%)",
      }}
    >
      <div
        style={{
          color: cfg.color,
          fontWeight: "bold",
          fontSize: "0.8rem",
          textShadow: `0 0 8px ${cfg.color}`,
          marginBottom: "0.5rem",
          letterSpacing: "0.05em",
        }}
      >
        {cfg.icon} {cfg.label}
      </div>
      <p
        style={{
          color: "rgba(0,255,65,0.5)",
          fontSize: "0.72rem",
          margin: "0 0 0.75rem",
          lineHeight: 1.5,
        }}
      >
        {cfg.desc}
      </p>

      {localVerdict !== undefined && (
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "0.4rem",
            fontSize: "0.65rem",
            color: localVerdict ? "#00FF41" : "#ff0055",
            background: "rgba(0,0,0,0.5)",
            padding: "0.25rem 0.6rem",
            border: `1px solid ${localVerdict ? "rgba(0,255,65,0.3)" : "rgba(255,0,85,0.3)"}`,
            borderRadius: 2,
            marginBottom: "0.75rem",
            fontFamily: "'DM Mono', monospace",
          }}
        >
          {localVerdict ? "✓" : "✗"} CLIENT_MERKLE_VERIFY:{" "}
          {localVerdict ? "PASS" : "FAIL"}
        </div>
      )}

      {details.length > 0 && (
        <div
          style={{
            borderTop: "1px solid rgba(0,255,65,0.1)",
            paddingTop: "0.6rem",
          }}
        >
          {details.map((d) => (
            <div
              key={d.key}
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                gap: "1rem",
                padding: "0.35rem 0",
                borderBottom: "1px solid rgba(0,255,65,0.05)",
                fontSize: "0.7rem",
              }}
            >
              <span
                style={{
                  color: "rgba(0,255,65,0.4)",
                  whiteSpace: "nowrap",
                  flexShrink: 0,
                  display: "flex",
                  alignItems: "center",
                  gap: "0.4rem",
                }}
              >
                {d.status && (
                  <span
                    style={{
                      display: "inline-block",
                      width: 5,
                      height: 5,
                      borderRadius: "50%",
                      background: statusColor[d.status] ?? "rgba(0,255,65,0.4)",
                      flexShrink: 0,
                    }}
                  />
                )}
                {d.key.toUpperCase().replace(/ /g, "_")}
              </span>
              <span
                style={{
                  fontFamily: "'DM Mono', monospace",
                  color: "rgba(0,255,65,0.85)",
                  wordBreak: "break-all",
                  textAlign: "right",
                  display: "flex",
                  alignItems: "center",
                  gap: "0.4rem",
                }}
              >
                {d.value}
                {d.copyable && <CopyButton text={d.value} />}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
