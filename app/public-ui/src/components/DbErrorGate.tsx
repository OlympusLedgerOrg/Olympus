/**
 * DbErrorGate — blocks the UI with a hard error screen when the embedded
 * PostgreSQL failed to start.
 *
 * Checks two sources in order:
 *  1. `get_db_error` Tauri command — available immediately, no network needed.
 *  2. GET /health — fallback for browser dev mode where Tauri invoke isn't present.
 *
 * If either reports a DB error, nothing renders until the user dismisses or
 * the app is restarted. "Dismiss" is intentionally hidden — a missing DB means
 * every write and read will fail, so letting the user in is misleading.
 */

import { useCallback, useEffect, useState } from "react";
import { getApiBase } from "../lib/api";
import BootProgress from "./BootProgress";

type DbStatus = "checking" | "ok" | "error";

async function checkDbError(): Promise<string | null> {
  // Fast path: Tauri command (available in desktop build, not browser).
  const isTauri =
    typeof window !== "undefined" &&
    typeof (window as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !==
      "undefined";

  if (isTauri) {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const err = await invoke<string | null>("get_db_error");
      if (err) return err;
      return null; // Tauri says no error — trust it.
    } catch {
      // Invoke failed (command not registered in older build) — fall through.
    }
  }

  // Fallback: hit /health and check the response.
  try {
    const base = await getApiBase();
    const res = await fetch(`${base}/health`);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      let detail: string | null = null;
      try {
        const json = JSON.parse(text) as { error?: string; db?: string };
        detail = json.error ?? (json.db === "failed" ? "Database failed to start." : null);
      } catch {
        /* not JSON */
      }
      return detail ?? `Database unavailable (HTTP ${res.status.toString()}).`;
    }
    return null;
  } catch (e) {
    // Network error — server might still be starting. Don't block on this.
    return null;
  }
}

export default function DbErrorGate({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<DbStatus>("checking");
  const [errorMsg, setErrorMsg] = useState<string>("");

  // BootProgress polls /health itself; transition to "ok" the moment it
  // succeeds. The legacy `checkDbError` path is still consulted on the
  // first tick — if Tauri's get_db_error already reports a failure
  // (pg_embed init crashed), short-circuit to the error screen.
  const handleReady = useCallback(() => {
    void checkDbError().then((err) => {
      if (err) {
        setErrorMsg(err);
        setStatus("error");
      } else {
        setStatus("ok");
      }
    });
  }, []);

  useEffect(() => {
    // Also race a fast Tauri-side error check so a known-bad start
    // surfaces immediately instead of after the first /health failure.
    let cancelled = false;
    void checkDbError().then((err) => {
      if (cancelled) return;
      if (err) {
        setErrorMsg(err);
        setStatus("error");
      }
    });
    return () => { cancelled = true; };
  }, []);

  if (status === "checking") {
    return <BootProgress onReady={handleReady} />;
  }

  if (status === "error") {
    return (
      <div style={{
        position: "fixed", inset: 0, zIndex: 9999,
        background: "#0a0a0a",
        display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center",
        fontFamily: "'DM Mono', 'Share Tech Mono', monospace",
        padding: "2rem",
      }}>
        {/* Red pulsing indicator */}
        <div style={{
          width: 16, height: 16, borderRadius: "50%",
          background: "#ff0055",
          boxShadow: "0 0 12px 4px rgba(255,0,85,0.5)",
          marginBottom: "1.5rem",
          animation: "dbErrPulse 1.4s ease-in-out infinite",
        }} />

        <div style={{
          fontSize: "0.6rem", letterSpacing: "0.2em",
          color: "rgba(255,0,85,0.7)", marginBottom: "0.75rem",
        }}>
          FATAL — DATABASE FAILURE
        </div>

        <div style={{
          fontSize: "1.1rem", letterSpacing: "0.08em",
          color: "#ff0055", marginBottom: "1.5rem", textAlign: "center",
        }}>
          Embedded PostgreSQL did not start
        </div>

        {/* Error detail box */}
        <pre style={{
          maxWidth: 640, width: "100%",
          background: "rgba(255,0,85,0.06)",
          border: "1px solid rgba(255,0,85,0.25)",
          color: "rgba(255,120,120,0.9)",
          fontSize: "0.68rem", lineHeight: 1.7,
          padding: "1rem 1.25rem",
          whiteSpace: "pre-wrap", wordBreak: "break-word",
          marginBottom: "1.75rem",
        }}>
          {errorMsg}
        </pre>

        {/* Remediation hints */}
        <div style={{
          maxWidth: 640, width: "100%",
          fontSize: "0.62rem", lineHeight: 1.8,
          color: "rgba(255,255,255,0.35)",
          marginBottom: "2rem",
        }}>
          <div>▸ Check that <span style={{ color: "rgba(255,200,0,0.6)" }}>port 5433</span> is not used by another process</div>
          <div>▸ Verify the app data directory is writable</div>
          <div>▸ Ensure at least <span style={{ color: "rgba(255,200,0,0.6)" }}>500 MB</span> of free disk space</div>
          <div>▸ On first launch, allow the PG binary download to complete</div>
        </div>

        <button
          type="button"
          onClick={() => window.location.reload()}
          style={{
            background: "rgba(255,0,85,0.12)",
            border: "1px solid rgba(255,0,85,0.4)",
            color: "#ff0055",
            fontSize: "0.68rem", letterSpacing: "0.14em",
            padding: "0.7rem 1.5rem", cursor: "pointer",
          }}
        >
          RESTART APP
        </button>

        <style>{`
          @keyframes dbErrPulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.85); }
          }
        `}</style>
      </div>
    );
  }

  return <>{children}</>;
}
