/// Boot-progress overlay shown while the embedded Axum + pg_embed stack
/// is still coming up.  Before this component existed the user saw a
/// blank window for ~30-120s during the first-launch flow (pg_embed
/// downloading ~200MB of postgres binaries, then `sqlx::migrate!`),
/// with no indication anything was happening.
///
/// Strategy: poll `/health` with exponential backoff capped at 1.5s.
/// Render one of three stages based on elapsed time:
///   <  3s : "starting" — barely shown on fast boots
///   < 30s : "preparing database" — pg_embed binary unpack / connect
///   ≥ 30s : "downloading postgres" — first-launch CDN fetch path
///
/// These stage thresholds are heuristic (the backend doesn't yet
/// instrument its own state — that's a tracked follow-up via a
/// `get_boot_status` Tauri command). Heuristic > nothing.
import { useEffect, useState } from "react";
import { getApiBase } from "../lib/api";

type Stage =
  | { phase: "starting"; elapsed_s: number }
  | { phase: "preparing"; elapsed_s: number }
  | { phase: "downloading"; elapsed_s: number };

function stageFor(elapsed_s: number): Stage {
  if (elapsed_s < 3) return { phase: "starting", elapsed_s };
  if (elapsed_s < 30) return { phase: "preparing", elapsed_s };
  return { phase: "downloading", elapsed_s };
}

const STAGE_COPY: Record<Stage["phase"], { title: string; sub: string }> = {
  starting: {
    title: "INITIALISING",
    sub: "Loading native binary…",
  },
  preparing: {
    title: "PREPARING DATABASE",
    sub: "Bringing up the embedded PostgreSQL and applying migrations. First boot can take a minute.",
  },
  downloading: {
    title: "DOWNLOADING POSTGRES",
    sub: "First-launch only — fetching ~200 MB of PostgreSQL binaries. Subsequent launches are instant.",
  },
};

const BootProgress: React.FC<{ onReady: () => void }> = ({ onReady }) => {
  const [stage, setStage] = useState<Stage>({ phase: "starting", elapsed_s: 0 });

  useEffect(() => {
    let cancelled = false;
    let delay = 250;
    const startedAt = Date.now();
    const tick = async () => {
      if (cancelled) return;
      const elapsed_s = Math.floor((Date.now() - startedAt) / 1000);
      setStage(stageFor(elapsed_s));
      try {
        const base = await getApiBase();
        const res = await fetch(`${base}/health`);
        if (res.ok) {
          if (!cancelled) onReady();
          return;
        }
      } catch {
        // server still booting — keep polling
      }
      delay = Math.min(delay * 1.4, 1500);
      window.setTimeout(tick, delay);
    };
    void tick();
    return () => { cancelled = true; };
  }, [onReady]);

  const copy = STAGE_COPY[stage.phase];

  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 9000,
        background: "#0a0a0a",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        fontFamily: "'DM Mono', monospace",
        color: "#00ff41",
        padding: "2rem",
      }}
    >
      <div
        style={{
          fontFamily: "'Share Tech Mono', monospace",
          fontSize: "0.78rem",
          letterSpacing: "0.32em",
          color: "#ff0055",
          marginBottom: "0.4rem",
        }}
      >
        OLYMPUS_PROTOCØL
      </div>
      <div
        style={{
          fontFamily: "'Share Tech Mono', monospace",
          fontSize: "1.05rem",
          letterSpacing: "0.16em",
          color: "#ccffcc",
          marginBottom: "0.4rem",
        }}
      >
        {copy.title}
      </div>
      <div
        style={{
          maxWidth: 460,
          textAlign: "center",
          fontSize: "0.7rem",
          color: "rgba(0,255,65,0.55)",
          lineHeight: 1.6,
          marginBottom: "1.4rem",
        }}
      >
        {copy.sub}
      </div>

      {/* Indeterminate progress bar — a single shimmering segment so the
          user can confirm the process hasn't hung. */}
      <div
        style={{
          width: "min(380px, 60vw)",
          height: 6,
          background: "rgba(0,255,65,0.08)",
          border: "1px solid rgba(0,255,65,0.2)",
          overflow: "hidden",
          position: "relative",
        }}
      >
        <div
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            height: "100%",
            width: "30%",
            background:
              "linear-gradient(90deg, transparent, rgba(0,255,65,0.7), transparent)",
            animation: "bootProgress 1.4s ease-in-out infinite",
          }}
        />
      </div>

      <div
        style={{
          marginTop: "0.8rem",
          fontSize: "0.55rem",
          letterSpacing: "0.1em",
          color: "rgba(0,255,65,0.35)",
        }}
      >
        elapsed {stage.elapsed_s}s
      </div>

      <style>{`
        @keyframes bootProgress {
          0%   { transform: translateX(-100%); }
          100% { transform: translateX(380%); }
        }
        @media (prefers-reduced-motion: reduce) {
          @keyframes bootProgress {
            0%, 100% { transform: translateX(50%); opacity: 0.6; }
          }
        }
      `}</style>
    </div>
  );
};

export default BootProgress;
