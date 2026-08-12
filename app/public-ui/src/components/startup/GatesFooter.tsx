// SPDX-License-Identifier: Apache-2.0

const GATE_KEYS = [
  { label: "COPPER KEY", color: "#b87333", status: "SEALED" },
  { label: "JADE KEY", color: "#00b388", status: "SEALED" },
  { label: "CRYSTAL KEY", color: "#a0d8ef", status: "SEALED" },
] as const;

export function GatesFooter() {
  return (
    <div
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        gap: "2rem",
        padding: "1.25rem 2rem",
        borderTop: "1px solid rgba(0,255,65,0.10)",
        marginTop: "2rem",
      }}
    >
      {GATE_KEYS.map((k) => (
        <div key={k.label} style={{ textAlign: "center" }}>
          <svg
            width="28"
            height="38"
            viewBox="0 0 28 38"
            style={{ display: "block", margin: "0 auto 0.35rem" }}
          >
            <rect
              x="8"
              y="0"
              width="12"
              height="12"
              rx="6"
              fill="none"
              stroke={k.color}
              strokeWidth="2.5"
              opacity="0.7"
            />
            <rect x="11" y="10" width="6" height="22" rx="1.5" fill={k.color} opacity="0.55" />
            <rect x="11" y="21" width="8" height="3" rx="1" fill={k.color} opacity="0.7" />
            <rect x="11" y="27" width="5" height="3" rx="1" fill={k.color} opacity="0.7" />
          </svg>
          <div
            style={{ fontSize: "0.44rem", letterSpacing: "0.12em", color: k.color, opacity: 0.7 }}
          >
            {k.label}
          </div>
          <div
            style={{
              fontSize: "0.4rem",
              letterSpacing: "0.1em",
              color: "rgba(255,0,85,0.6)",
              marginTop: "0.2rem",
            }}
          >
            {k.status}
          </div>
        </div>
      ))}
    </div>
  );
}
