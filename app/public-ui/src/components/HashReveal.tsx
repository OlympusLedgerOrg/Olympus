import type { FC } from "react";

interface HashRevealProps {
  hash: string | null;
  label?: string;
}

const HashReveal: FC<HashRevealProps> = ({ hash, label = "BLAKE3_DIGEST" }) => {
  if (!hash) return null;

  return (
    <div
      style={{
        fontFamily: "'DM Mono', monospace",
        fontSize: "0.7rem",
        wordBreak: "break-all",
        letterSpacing: "0.06em",
        padding: "0.6rem 0.75rem",
        background: "rgba(0,255,65,0.04)",
        border: "1px solid rgba(0,255,65,0.2)",
        borderRadius: 2,
        color: "#00FF41",
        textShadow: "0 0 4px rgba(0,255,65,0.5)",
      }}
      aria-label="BLAKE3 hash"
    >
      <span
        style={{
          opacity: 0.4,
          fontSize: "0.6rem",
          display: "block",
          marginBottom: "0.2rem",
          letterSpacing: "0.1em",
        }}
      >
        {label}
      </span>
      <span key={hash} className="hash-reveal-text">
        {hash}
      </span>
    </div>
  );
};

export default HashReveal;
