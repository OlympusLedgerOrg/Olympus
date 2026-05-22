/// Global banner that surfaces permission failures from React Query so the
/// user can see *why* a button just bounced off the server, not just that
/// it did. Without this, a 403 from `/zk/prove` or `/ingest/commit` shows
/// only as red text inside the page that triggered it — easy to miss, and
/// missing the "you need scope X" framing.
///
/// Subscribes once at mount to the QueryClient's QueryCache + MutationCache
/// `subscribe` channels and shows the most recent ApiError that is either
/// a 401 or 403. Auto-dismisses after 8s; dismissable manually.
import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ApiError } from "../lib/api";

type ActiveBanner = {
  status: number;
  detail: string;
  requiredScope?: string | string[];
  grantedScopes?: string[];
  code?: string;
  shownAt: number;
};

const AUTO_DISMISS_MS = 8000;

const ScopeBanner: React.FC = () => {
  const qc = useQueryClient();
  const [active, setActive] = useState<ActiveBanner | null>(null);

  useEffect(() => {
    const considerError = (e: unknown) => {
      if (!(e instanceof ApiError)) return;
      if (e.status !== 401 && e.status !== 403) return;
      setActive({
        status: e.status,
        detail: e.detail,
        requiredScope: e.requiredScope,
        grantedScopes: e.grantedScopes,
        code: e.code,
        shownAt: Date.now(),
      });
    };
    const unsubQ = qc.getQueryCache().subscribe(ev => {
      if (ev.type === "updated" && ev.action.type === "error") {
        considerError(ev.action.error);
      }
    });
    const unsubM = qc.getMutationCache().subscribe(ev => {
      if (ev.type === "updated" && ev.action.type === "error") {
        considerError(ev.action.error);
      }
    });
    return () => { unsubQ(); unsubM(); };
  }, [qc]);

  useEffect(() => {
    if (!active) return;
    const t = window.setTimeout(() => setActive(null), AUTO_DISMISS_MS);
    return () => window.clearTimeout(t);
  }, [active]);

  if (!active) return null;

  const required = Array.isArray(active.requiredScope)
    ? active.requiredScope.join(" / ")
    : active.requiredScope;
  const granted = active.grantedScopes?.join(", ");
  const title = active.status === 401 ? "NOT AUTHENTICATED" : "INSUFFICIENT SCOPE";

  return (
    <div
      role="alert"
      aria-live="polite"
      style={{
        position: "fixed",
        bottom: "1.2rem",
        right: "1.2rem",
        maxWidth: 460,
        zIndex: 90,
        background: "rgba(0,0,0,0.92)",
        border: `1px solid ${active.status === 401 ? "rgba(255,0,85,0.55)" : "rgba(255,200,120,0.5)"}`,
        color: active.status === 401 ? "#ff4477" : "rgba(255,200,120,0.95)",
        fontFamily: "'DM Mono', monospace",
        padding: "0.8rem 1rem",
        boxShadow: "0 0 24px rgba(0,0,0,0.6)",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "0.4rem" }}>
        <strong style={{ fontFamily: "'Share Tech Mono', monospace", letterSpacing: "0.12em", fontSize: "0.7rem" }}>
          {title}
        </strong>
        <button
          type="button"
          aria-label="Dismiss"
          onClick={() => setActive(null)}
          style={{
            background: "transparent", border: "none", color: "inherit",
            fontFamily: "inherit", fontSize: "0.7rem", cursor: "pointer", padding: 0,
            opacity: 0.6,
          }}
        >
          ✕
        </button>
      </div>
      <div style={{ fontSize: "0.65rem", lineHeight: 1.5 }}>{active.detail}</div>
      {required && (
        <div style={{ fontSize: "0.6rem", marginTop: "0.4rem", color: "rgba(255,200,120,0.7)" }}>
          requires scope: <strong>{required}</strong>
          {granted && <> · your key has: <strong>{granted}</strong></>}
        </div>
      )}
      <div style={{ fontSize: "0.55rem", marginTop: "0.5rem", color: "rgba(255,200,120,0.55)" }}>
        Ask an admin to grant the missing scope on the <a href="/admin/users" style={{ color: "inherit", textDecoration: "underline" }}>USERS</a> page.
      </div>
    </div>
  );
};

export default ScopeBanner;
