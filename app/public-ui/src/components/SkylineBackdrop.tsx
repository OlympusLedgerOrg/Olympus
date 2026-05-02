import { useEffect, useRef } from "react";

const buildings = [
  { left: "3%", width: "9%", height: "38%", delay: "0s" },
  { left: "13%", width: "7%", height: "52%", delay: "0.4s" },
  { left: "22%", width: "12%", height: "44%", delay: "0.8s" },
  { left: "36%", width: "8%", height: "62%", delay: "0.2s" },
  { left: "47%", width: "14%", height: "56%", delay: "0.7s", smile: true },
  { left: "64%", width: "9%", height: "48%", delay: "0.1s" },
  { left: "76%", width: "11%", height: "66%", delay: "0.5s" },
  { left: "90%", width: "8%", height: "42%", delay: "0.9s" },
];

export default function SkylineBackdrop() {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const onMove = (event: MouseEvent) => {
      const x = (event.clientX / window.innerWidth - 0.5) * 16;
      const y = (event.clientY / window.innerHeight - 0.5) * 10;

      ref.current?.style.setProperty("--mx", `${x}px`);
      ref.current?.style.setProperty("--my", `${y}px`);
    };

    window.addEventListener("mousemove", onMove);
    return () => window.removeEventListener("mousemove", onMove);
  }, []);

  return (
    <div
      ref={ref}
      aria-hidden="true"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: -2,
        overflow: "hidden",
        background:
          "radial-gradient(circle at 50% 20%, rgba(0,255,65,0.08), transparent 32%), linear-gradient(180deg, #020503 0%, #030904 48%, #000 100%)",
      }}
    >
      <div
        style={{
          position: "absolute",
          inset: 0,
          background:
            "linear-gradient(rgba(0,255,65,0.035) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,65,0.025) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
          transform: "translate(var(--mx, 0px), var(--my, 0px))",
          transition: "transform 160ms linear",
          opacity: 0.45,
        }}
      />

      <div
        style={{
          position: "absolute",
          left: 0,
          right: 0,
          bottom: 0,
          height: "68vh",
          transform:
            "translate(calc(var(--mx, 0px) * -0.35), calc(var(--my, 0px) * -0.25))",
          transition: "transform 160ms linear",
        }}
      >
        {buildings.map((b, i) => (
          <div
            key={i}
            style={{
              position: "absolute",
              left: b.left,
              bottom: 0,
              width: b.width,
              height: b.height,
              background:
                "linear-gradient(180deg, rgba(0,255,65,0.08), rgba(0,0,0,0.95) 22%), linear-gradient(90deg, rgba(0,255,65,0.08) 1px, transparent 1px)",
              backgroundSize: "100% 100%, 18px 18px",
              border: "1px solid rgba(0,255,65,0.12)",
              boxShadow: "0 0 32px rgba(0,255,65,0.06)",
              animation: `towerPulse 7s ease-in-out infinite ${b.delay}`,
            }}
          >
            {b.smile && (
              <div
                style={{
                  position: "absolute",
                  top: "18%",
                  left: "50%",
                  transform: "translateX(-50%)",
                  width: "74px",
                  height: "74px",
                  borderRadius: "50%",
                  border: "2px solid rgba(0,255,65,0.8)",
                  boxShadow:
                    "0 0 18px rgba(0,255,65,0.85), inset 0 0 18px rgba(0,255,65,0.16)",
                  color: "#00ff41",
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "34px",
                  display: "grid",
                  placeItems: "center",
                  textShadow: "0 0 12px #00ff41",
                  animation: "smileGlitch 3.5s infinite",
                }}
              >
                :)
              </div>
            )}
          </div>
        ))}
      </div>

      <style>
        {`
          @keyframes towerPulse {
            0%, 100% { opacity: 0.46; }
            50% { opacity: 0.72; }
          }

          @keyframes smileGlitch {
            0%, 92%, 100% { transform: translateX(-50%) skew(0deg); opacity: 1; }
            93% { transform: translateX(-52%) skew(8deg); opacity: 0.72; }
            94% { transform: translateX(-47%) skew(-10deg); opacity: 1; }
          }
        `}
      </style>
    </div>
  );
}
