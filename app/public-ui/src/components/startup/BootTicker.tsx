// SPDX-License-Identifier: Apache-2.0

const TICKER_PHRASES = [
  "SEEK THE EGG · TRUST THE PROOF · THE LEDGER NEVER LIES",
  "WAKE THE F*** UP, SAMURAI. WE HAVE A LEDGER TO BURN.",
  "ALL THESE PROOFS WILL BE LOST IN TIME, LIKE TEARS IN RAIN…",
  "I AM THE LAW. THE LAW IS A MERKLE PROOF.",
  "YOU TAKE THE RED PILL — YOU VERIFY THE PROOF.",
  "THREE HIDDEN KEYS · THREE SECRET GATES · ONE LEDGER",
  "↑↑↓↓←→←→ B A · GODMODE UNLOCKED",
  "ARASAKA TRIED TO REWRITE THE ROOT HASH. ARASAKA FAILED.",
  "TRUST THE MATH. NOT THE MAN.",
  "THE REVOLUTION WILL BE APPEND-ONLY.",
  "HACK THE PLANET. VERIFY THE HASH.",
  "WAKE UP, OPERATOR. THE LEDGER HAS YOU.",
  "FIRST RULE OF OLYMPUS: YOU DO NOT TRUST THE HASH WITHOUT THE PROOF.",
  "A VERDICT WITHOUT A PROOF IS JUST MARKETING.",
  "HELL_O FRIEND. HELLO CRYPTOGRAPHIC PROOF.",
  "IF IT ISN'T SIGNED, IT DIDN'T HAPPEN.",
  "THE DATABASE CAN LIE. THE PROOF BUNDLE CANNOT.",
  "I KNOW KUNG FU. I KNOW BLAKE3.",
].join("  ·  ");

export function BootTicker() {
  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        zIndex: 50,
        height: "28px",
        background: "rgba(0,0,0,0.92)",
        borderBottom: "1px solid rgba(0,255,65,0.22)",
        overflow: "hidden",
        display: "flex",
        alignItems: "center",
      }}
    >
      <div
        style={{
          whiteSpace: "nowrap",
          fontFamily: "var(--font-terminal, 'Share Tech Mono', monospace)",
          fontSize: "0.6rem",
          color: "rgba(0,255,65,0.72)",
          letterSpacing: "0.06em",
          // Linear 80s infinite translateX paints the entire row every
          // frame; under WSL/llvmpipe it's a measurable cursor-jitter
          // contributor. Disable when the OS asks for reduced motion —
          // the static text is still readable.
          animation: "bootTicker 80s linear infinite",
          paddingLeft: "100%",
        }}
      >
        {TICKER_PHRASES}&nbsp;&nbsp;&nbsp;&nbsp;{TICKER_PHRASES}
      </div>
      <style>{`
        @keyframes bootTicker {
          from { transform: translateX(0); }
          to   { transform: translateX(-50%); }
        }
        @media (prefers-reduced-motion: reduce) {
          @keyframes bootTicker {
            0%, 100% { transform: translateX(-12%); }
          }
        }
      `}</style>
    </div>
  );
}
