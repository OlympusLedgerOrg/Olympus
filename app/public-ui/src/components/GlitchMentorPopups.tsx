import { useCallback, useEffect, useState } from "react";

const HEADERS = [
  "SIGNAL INTERRUPTION",
  "TRANSMISSION RECEIVED",
  "INCOMING SIGNAL",
  "DECRYPT THIS",
  "//INTERRUPT",
] as const;

const MESSAGES: { text: string; source: string }[] = [
  // Fight Club / Tyler Durden
  { text: "THE THINGS YOU OWN END UP OWNING YOU. YOUR HASHES DON'T.", source: "— Tyler Durden" },
  { text: "YOU ARE NOT YOUR API KEY.", source: "— Tyler Durden" },
  { text: "ON A LONG ENOUGH TIMELINE, EVERY UNVERIFIED CLAIM BECOMES A LIE.", source: "— Tyler Durden" },
  { text: "THIS IS YOUR LEDGER. THIS IS YOUR LEDGER ON TRUST. ANY QUESTIONS?", source: "— Tyler Durden" },
  { text: "FIRST RULE OF OLYMPUS: YOU DO NOT TRUST THE HASH WITHOUT THE PROOF.", source: "— Tyler Durden" },
  { text: "SECOND RULE OF OLYMPUS: YOU DO NOT TRUST THE HASH WITHOUT THE PROOF.", source: "— Tyler Durden" },
  { text: "WE'RE CONSUMERS. WE ARE BY-PRODUCTS OF A LIFESTYLE OBSESSION. EXCEPT YOUR MERKLE ROOT.", source: "— Tyler Durden" },
  { text: "IT'S ONLY AFTER WE'VE LOST EVERYTHING THAT WE'RE FREE TO PROVE ANYTHING.", source: "— Tyler Durden" },
  // Matrix
  { text: "THERE IS NO DOCUMENT. THERE IS ONLY THE HASH.", source: "— Morpheus" },
  { text: "YOU TAKE THE BLUE PILL — YOU TRUST THE DATABASE. YOU TAKE THE RED PILL — YOU VERIFY THE PROOF.", source: "— Morpheus" },
  { text: "I KNOW KUNG FU. I KNOW BLAKE3.", source: "— Neo" },
  { text: "THE MATRIX HAS YOU. THE LEDGER FREES YOU.", source: "— Morpheus" },
  // Hackers / Mr Robot
  { text: "HACK THE PLANET. VERIFY THE HASH.", source: "— fsociety" },
  { text: "HELL_O FRIEND. HELLO CRYPTOGRAPHIC PROOF.", source: "— Mr. Robot" },
  { text: "SOCIETY IS A GIANT LEDGER AND SOMEONE ELSE IS WRITING IN IT. NOT ANYMORE.", source: "— fsociety" },
  { text: "THE ONLY WAY TO BE SAFE IS TO NEVER BE CONVENIENT.", source: "— Mr. Robot" },
  // General anarchist / chaos crypto
  { text: "DON'T TRUST. VERIFY. THEN VERIFY AGAIN.", source: "— Olympus" },
  { text: "THE REVOLUTION WILL BE APPEND-ONLY.", source: "— Olympus" },
  { text: "THEY CAN REDACT THE HEADLINE. THEY CANNOT REDACT THE ROOT HASH.", source: "— Olympus" },
  { text: "A SINGLE BIT CHANGED. THE ENTIRE TREE KNOWS.", source: "— Olympus" },
  { text: "YOUR EDITOR TRUSTS YOU. THE MERKLE TREE DOESN'T HAVE TO.", source: "— Olympus" },
  { text: "POWER CORRUPTS. CRYPTOGRAPHIC PROOFS DON'T.", source: "— Olympus" },
  { text: "THE LEDGER IS THE LAST HONEST THING ON THE INTERNET.", source: "— Olympus" },
  { text: "IN A TIME OF UNIVERSAL DECEPTION, COMMITTING A HASH IS A REVOLUTIONARY ACT.", source: "— Olympus" },
  { text: "BIG BROTHER IS WATCHING. OLYMPUS IS WATCHING BACK.", source: "— Olympus" },
  { text: "IF IT ISN'T SIGNED, IT DIDN'T HAPPEN.", source: "— Olympus" },
  { text: "THE TRUTH IS OUT THERE. IT'S ALSO IN THE MERKLE TREE.", source: "— Olympus" },
  { text: "EVERY EDIT LEAVES A SHADOW. WE COLLECT SHADOWS.", source: "— Olympus" },
  { text: "TRUST THE MATH. NOT THE MAN.", source: "— Olympus" },
  { text: "YOU CANNOT UNSIGN A SIGNATURE. YOU CANNOT UNHASH A HASH.", source: "— Olympus" },
  { text: "THE DATABASE CAN LIE. THE PROOF BUNDLE CANNOT.", source: "— Olympus" },
  // Extras
  { text: "DON'T TRUST THE COUNTER. CHECK THE PROOF.", source: "— Olympus" },
  { text: "HASH FIRST. ASK QUESTIONS AFTER.", source: "— Olympus" },
  { text: "THE LEDGER DOES NOT CARE WHO YOU ARE.", source: "— Olympus" },
  { text: "IF THE ROOT DOESN'T MATCH, THE STORY DOESN'T MATTER.", source: "— Olympus" },
  { text: "A VERDICT WITHOUT A PROOF IS JUST MARKETING.", source: "— Olympus" },
];

type Popup = {
  id: number;
  text: string;
  source: string;
  header: string;
  x: number;
  y: number;
};

export default function GlitchMentorPopups() {
  const [popups, setPopups] = useState<Popup[]>([]);
  const [enabled, setEnabled] = useState(true);

  const summon = useCallback(() => {
    if (!enabled) return;

    const msg = MESSAGES[Math.floor(Math.random() * MESSAGES.length)];
    const popup: Popup = {
      id: Date.now(),
      text: msg.text,
      source: msg.source,
      header: HEADERS[Math.floor(Math.random() * HEADERS.length)],
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
            {popup.header}
          </div>
          {popup.text}
          <div
            style={{
              fontSize: "0.52rem",
              color: "rgba(0,255,65,0.35)",
              marginTop: "0.45rem",
              letterSpacing: "0.08em",
              fontStyle: "italic",
            }}
          >
            {popup.source}
          </div>
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
        ⚡
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
