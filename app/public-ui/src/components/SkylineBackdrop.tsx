import { useEffect, useMemo, useRef, type FC } from "react";

const buildings = [
  { left: "2%",  width: "8%",  height: "34%", delay: "0s",   windows: 4 },
  { left: "12%", width: "7%",  height: "50%", delay: "0.4s", windows: 5 },
  { left: "21%", width: "11%", height: "42%", delay: "0.8s", windows: 4 },
  { left: "34%", width: "8%",  height: "60%", delay: "0.2s", windows: 6 },
  { left: "44%", width: "15%", height: "72%", delay: "0.7s", windows: 7, smile: true },
  { left: "62%", width: "9%",  height: "46%", delay: "0.1s", windows: 5 },
  { left: "74%", width: "12%", height: "64%", delay: "0.5s", windows: 6 },
  { left: "89%", width: "9%",  height: "40%", delay: "0.9s", windows: 4 },
];

// CSS drop-shadow stacks compose to the same halo silhouette as a pair of
// SVG feGaussianBlur+feMerge filters, but webkit2gtk rasterises them in
// a single GPU pass — under WSLg/llvmpipe the old filter pair recomputed
// the blur on every mousemove parallax tick. See design item [2].
const SMILEY_GLOW = "drop-shadow(0 0 2px #ffe000) drop-shadow(0 0 6px rgba(255,224,0,0.55))";
const SMILEY_GLOW_HOT = "drop-shadow(0 0 4px #ffe000) drop-shadow(0 0 10px rgba(255,224,0,0.35))";
const BLOOD_GLOW = "drop-shadow(0 0 3px rgba(204,0,0,0.7))";

const NeonSmiley: FC = () => (
  <div style={{
    position: "absolute",
    top: "12%",
    left: "50%",
    transform: "translateX(-50%)",
    width: "clamp(72px, 9vw, 130px)",
    height: "clamp(72px, 9vw, 130px)",
  }}>
    <svg
      viewBox="0 0 100 100"
      width="100%"
      height="100%"
      style={{ overflow: "visible" }}
    >
      {/* Outer halo bloom */}
      <circle cx="50" cy="50" r="48" fill="none" stroke="#ffe000" strokeWidth="0.5" opacity="0.18" style={{ filter: SMILEY_GLOW_HOT }} />

      {/* Face circle — neon yellow tube */}
      <circle
        cx="50" cy="50" r="44"
        fill="none"
        stroke="#ffe000"
        strokeWidth="3.5"
        style={{ filter: SMILEY_GLOW, animation: "neonFlicker 4.2s ease-in-out infinite" }}
      />

      {/* Left eye */}
      <circle
        cx="33" cy="38"
        r="5.5"
        fill="none"
        stroke="#ffe000"
        strokeWidth="3"
        style={{ filter: SMILEY_GLOW, animation: "neonFlicker 4.2s ease-in-out infinite 0.3s" }}
      />

      {/* Right eye */}
      <circle
        cx="67" cy="38"
        r="5.5"
        fill="none"
        stroke="#ffe000"
        strokeWidth="3"
        style={{ filter: SMILEY_GLOW, animation: "neonFlicker 4.2s ease-in-out infinite 0.6s" }}
      />

      {/* Smile arc */}
      <path
        d="M 26 58 Q 50 84 74 58"
        fill="none"
        stroke="#ffe000"
        strokeWidth="3.5"
        strokeLinecap="round"
        style={{ filter: SMILEY_GLOW, animation: "neonFlicker 4.2s ease-in-out infinite 0.15s" }}
      />

      {/* Blood drip 1 — Project Mayhem edge */}
      <path d="M 38 92 Q 39 100 37 106" fill="none" stroke="#cc0000" strokeWidth="2.5" strokeLinecap="round" opacity="0.85" style={{ filter: BLOOD_GLOW }} />
      <circle cx="37" cy="108" r="3" fill="#cc0000" opacity="0.85" style={{ filter: BLOOD_GLOW }} />

      {/* Blood drip 2 */}
      <path d="M 56 93 Q 57 103 55 110" fill="none" stroke="#cc0000" strokeWidth="2" strokeLinecap="round" opacity="0.7" style={{ filter: BLOOD_GLOW }} />
      <circle cx="55" cy="112" r="2.5" fill="#cc0000" opacity="0.7" style={{ filter: BLOOD_GLOW }} />
    </svg>

    <style>{`
      @keyframes neonFlicker {
        0%,  100% { opacity: 1;    }
        3%         { opacity: 0.85; }
        6%         { opacity: 1;    }
        40%        { opacity: 0.9;  }
        41%        { opacity: 0.3;  }
        42%        { opacity: 1;    }
        78%        { opacity: 1;    }
        79%        { opacity: 0.5;  }
        80%        { opacity: 1;    }
        81%        { opacity: 0.2;  }
        82%        { opacity: 1;    }
      }
    `}</style>
  </div>
);

const WindowGrid: FC<{ cols: number; rows: number }> = ({ cols, rows }) => {
  const cells = useMemo(() => {
    return Array.from({ length: cols * rows }, (_, i) => {
      const lit = Math.random() > 0.45;
      const red = lit && Math.random() > 0.88;
      const duration = 3 + Math.random() * 9;
      const delay = Math.random() * 4;
      return { i, lit, red, duration, delay };
    });
  }, [cols, rows]);
  return (
    <div style={{
      position: "absolute",
      inset: "8% 10% auto",
      display: "grid",
      gridTemplateColumns: `repeat(${cols}, 1fr)`,
      gap: "3px",
      padding: "4px",
    }}>
      {cells.map(({ i, lit, red, duration, delay }) => {
        return (
          <div key={i} style={{
            aspectRatio: "1 / 1.4",
            background: red
              ? "rgba(255,0,85,0.7)"
              : lit
                ? "rgba(0,255,65,0.55)"
                : "rgba(0,255,65,0.04)",
            boxShadow: lit
              ? `0 0 4px ${red ? "rgba(255,0,85,0.8)" : "rgba(0,255,65,0.5)"}`
              : "none",
            animation: lit ? `winBlink ${duration}s ease-in-out infinite ${delay}s` : "none",
          }} />
        );
      })}
    </div>
  );
};

export default function SkylineBackdrop() {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    // Honor the OS reduced-motion preference — skip parallax entirely.
    if (typeof window !== "undefined"
        && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      return;
    }
    // Coalesce mousemove events through rAF: webkit2gtk under WSLg can
    // emit 100-200 events/sec, and writing two CSS custom properties on
    // a fixed full-viewport element triggers a relayout + repaint of
    // the grid and city layers each time. Without rAF the cursor jitter
    // is dominated by this loop.
    let raf = 0;
    let mx = 0;
    let my = 0;
    const onMove = (e: MouseEvent) => {
      mx = (e.clientX / window.innerWidth  - 0.5) * 16;
      my = (e.clientY / window.innerHeight - 0.5) * 10;
      if (raf) return;
      raf = requestAnimationFrame(() => {
        ref.current?.style.setProperty("--mx", `${mx}px`);
        ref.current?.style.setProperty("--my", `${my}px`);
        raf = 0;
      });
    };
    window.addEventListener("mousemove", onMove, { passive: true });
    return () => {
      if (raf) cancelAnimationFrame(raf);
      window.removeEventListener("mousemove", onMove);
    };
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
          "radial-gradient(ellipse at 50% 0%, rgba(255,220,0,0.04) 0%, transparent 42%), " +
          "radial-gradient(circle at 50% 20%, rgba(0,255,65,0.06), transparent 30%), " +
          "linear-gradient(180deg, #010202 0%, #020503 50%, #000 100%)",
      }}
    >
      {/* Grid */}
      <div style={{
        position: "absolute",
        inset: 0,
        background:
          "linear-gradient(rgba(0,255,65,0.028) 1px, transparent 1px), " +
          "linear-gradient(90deg, rgba(0,255,65,0.022) 1px, transparent 1px)",
        backgroundSize: "48px 48px",
        transform: "translate(var(--mx,0px), var(--my,0px))",
        transition: "transform 160ms linear",
        opacity: 0.5,
      }} />

      {/* City layer */}
      <div style={{
        position: "absolute",
        left: 0,
        right: 0,
        bottom: 0,
        height: "74vh",
        transform: "translate(calc(var(--mx,0px)*-0.35), calc(var(--my,0px)*-0.25))",
        transition: "transform 160ms linear",
      }}>
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
                "linear-gradient(180deg, rgba(0,255,65,0.10) 0%, rgba(0,0,0,0.96) 28%), " +
                "linear-gradient(90deg, rgba(0,255,65,0.06) 1px, transparent 1px)",
              backgroundSize: "100% 100%, 16px 16px",
              border: "1px solid rgba(0,255,65,0.14)",
              boxShadow:
                b.smile
                  ? "0 0 60px rgba(255,220,0,0.12), 0 0 24px rgba(0,255,65,0.08)"
                  : "0 0 24px rgba(0,255,65,0.05)",
              animation: `towerPulse 7s ease-in-out infinite ${b.delay}`,
            }}
          >
            {/* Window grids on non-smile buildings */}
            {!b.smile && <WindowGrid cols={3} rows={b.windows} />}

            {/* Project Mayhem neon smiley */}
            {b.smile && <NeonSmiley />}
          </div>
        ))}

        {/* Ground reflection glow */}
        <div style={{
          position: "absolute",
          bottom: 0,
          left: 0,
          right: 0,
          height: "3px",
          background: "linear-gradient(90deg, transparent, rgba(255,220,0,0.25) 44%, rgba(0,255,65,0.25) 56%, transparent)",
          boxShadow: "0 0 40px rgba(255,220,0,0.15), 0 0 80px rgba(0,255,65,0.1)",
        }} />
      </div>

      {/* Ambient moon / haze */}
      <div style={{
        position: "absolute",
        top: "8%",
        right: "18%",
        width: 80,
        height: 80,
        borderRadius: "50%",
        background: "radial-gradient(circle, rgba(255,220,0,0.08) 0%, transparent 70%)",
        boxShadow: "0 0 60px rgba(255,220,0,0.06)",
      }} />

      <style>{`
        @keyframes towerPulse {
          0%,100% { opacity: 0.48; }
          50%      { opacity: 0.74; }
        }
        @keyframes winBlink {
          0%,100% { opacity: 1; }
          50%     { opacity: 0.2; }
        }
      `}</style>
    </div>
  );
}
