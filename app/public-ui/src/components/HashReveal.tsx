import { useState, useEffect, type FC } from "react";

interface HashRevealProps {
  hash: string | null;
  label?: string;
}

const HashReveal: FC<HashRevealProps> = ({ hash, label = "BLAKE3_DIGEST" }) => {
  const [revealed, setRevealed] = useState<number>(0);

  useEffect(() => {
    if (!hash) {
      setRevealed(0);
      return;
    }
    setRevealed(0);
    let i = 0;
    const id = setInterval(() => {
      i += 2;
      setRevealed(i);
      if (i >= hash.length) clearInterval(id);
    }, 14);
    return (): void => clearInterval(id);
  }, [hash]);

  if (!hash) return null;
  const done = Math.min(revealed, hash.length);

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
      {hash.slice(0, done)}
      <span style={{ opacity: 0.25 }}>{hash.slice(done)}</span>
    </div>
  );
};

export default HashReveal;
