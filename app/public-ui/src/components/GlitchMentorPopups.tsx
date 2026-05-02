import { useCallback, useEffect, useState } from "react";

const messages = [
  "DON'T TRUST THE COUNTER. CHECK THE PROOF.",
  "HASH FIRST. ASK QUESTIONS AFTER.",
  "THE LEDGER DOES NOT CARE WHO YOU ARE.",
  "IF THE ROOT DOESN'T MATCH, THE STORY DOESN'T MATTER.",
  "LOCAL BYTES. PUBLIC PROOF. NO HAND-WAVING.",
  "A VERDICT WITHOUT A PROOF IS JUST MARKETING.",
];

type Popup = {
  id: number;
  text: string;
  x: number;
  y: number;
};

export default function GlitchMentorPopups() {
  const [popups, setPopups] = useState<Popup[]>([]);
  const [enabled, setEnabled] = useState(true);

  const summon = useCallback(() => {
    if (!enabled) return;

    const popup: Popup = {
      id: Date.now(),
      text: messages[Math.floor(Math.random() * messages.length)],
      x: 12 + Math.random() * 64,
      y: 16 + Math.random() * 48,
    };

    setPopups((prev) => [...prev.slice(-2), popup]);

    window.setTimeout(() => {
      setPopups((prev) => prev.filter((p) => p.id !== popup.id));
    }, 4200);
  }, [enabled]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      if (Math.random() > 0.55) summon();
    }, 22000);

    return () => window.clearInterval(interval);
  }, [summon]);

  return (
    <>
      {popups.map((popup) => (
        <div
          key={popup.id}
          style={{
            position: "fixed",
            left: `${popup.x}%`,
            top: `${popup.y}%`,
            zIndex: 30,
            width: "min(280px, 80vw)",
            pointerEvents: "none",
            padding: "0.85rem 1rem",
            border: "1px solid rgba(0,255,65,0.5)",
            background:
              "linear-gradient(135deg, rgba(0,0,0,0.92), rgba(0,35,10,0.86))",
            boxShadow:
              "0 0 28px rgba(0,255,65,0.22), inset 0 0 24px rgba(0,255,65,0.06)",
            color: "#00ff41",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.72rem",
            letterSpacing: "0.06em",
            lineHeight: 1.45,
            animation: "mentorPop 4.2s ease-in-out forwards",
            textTransform: "uppercase",
          }}
        >
          <div
            style={{
              fontSize: "0.58rem",
              color: "rgba(0,255,65,0.45)",
              marginBottom: "0.35rem",
            }}
          >
            SIGNAL INTERRUPTION
          </div>
          {popup.text}
        </div>
      ))}

      <button
        type="button"
        onClick={summon}
        onDoubleClick={() => setEnabled((v) => !v)}
        title="Summon signal. Double-click to toggle random popups."
        style={{
          position: "fixed",
          right: "1rem",
          bottom: "1rem",
          zIndex: 40,
          width: "44px",
          height: "44px",
          borderRadius: "50%",
          border: "1px solid rgba(0,255,65,0.55)",
          background: enabled
            ? "rgba(0,30,8,0.88)"
            : "rgba(30,0,8,0.88)",
          color: "#00ff41",
          fontFamily: "'DM Mono', monospace",
          fontSize: "1.1rem",
          cursor: "pointer",
          boxShadow: "0 0 18px rgba(0,255,65,0.25)",
        }}
      >
        :)
      </button>

      <style>
        {`
          @keyframes mentorPop {
            0% {
              opacity: 0;
              transform: translateY(10px) scale(0.94) skew(-6deg);
              filter: blur(2px);
            }
            8% {
              opacity: 1;
              transform: translateY(0) scale(1) skew(3deg);
              filter: blur(0);
            }
            12% {
              transform: translateX(-4px) skew(-5deg);
            }
            14% {
              transform: translateX(4px) skew(4deg);
            }
            18%, 82% {
              transform: translateX(0) skew(0deg);
              opacity: 1;
            }
            100% {
              opacity: 0;
              transform: translateY(-12px) scale(0.98);
            }
          }
        `}
      </style>
    </>
  );
}
