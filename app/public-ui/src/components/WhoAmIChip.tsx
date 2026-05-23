/// Small header chip showing the operator's current API-key scopes +
/// a short BLAKE3 fingerprint of the key. Closes the "users can't see
/// what they have / what an endpoint requires" gap.
///
/// Heuristic: derives scopes from the locally-stored `olympus_admin_key`
/// by hitting a lightweight identity endpoint (`/auth/whoami` — defined
/// here as the conventional name; falls back to "scopes unknown" if the
/// endpoint isn't yet implemented so this component is forward-safe).
import { useEffect, useState } from "react";
import { apiFetch } from "../lib/api";
import { getStoredAdminKey, hasStoredAdminKey } from "../lib/storage";

// Best-effort fetch-error status extraction. The typed ApiError class
// lives on post-#941 main; this branch was opened before that landed.
// Once rebased onto main, the caller below can switch to
// `e instanceof ApiError && e.status === ...`.
function errStatus(e: unknown): number | null {
  if (typeof e === "object" && e !== null && "status" in e) {
    const s = (e as { status: unknown }).status;
    return typeof s === "number" ? s : null;
  }
  // Legacy string-based errors like "HTTP 404: …" — parse the status.
  if (e instanceof Error) {
    const m = /^HTTP (\d{3}):/.exec(e.message);
    if (m) return Number(m[1]);
  }
  return null;
}

type Identity = {
  user_id?: string;
  email?: string;
  scopes?: string[];
  key_fingerprint?: string; // first 12 hex chars of BLAKE3(key)
};

const WhoAmIChip: React.FC = () => {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [missingEndpoint, setMissingEndpoint] = useState(false);

  useEffect(() => {
    const key = getStoredAdminKey();
    if (!key) return;
    let cancelled = false;
    void apiFetch<Identity>("/auth/whoami", {
      headers: { "X-API-Key": key },
    })
      .then(r => {
        if (!cancelled) setIdentity(r);
      })
      .catch(e => {
        if (cancelled) return;
        // The endpoint may not yet exist on the server — render a
        // "scopes unknown" chip rather than disappearing entirely, so
        // the operator still gets a hint that a key is configured.
        const s = errStatus(e);
        if (s === 404 || s === 501) {
          setMissingEndpoint(true);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // No admin key stored → render nothing (Layout doesn't reserve
  // space for us).
  if (!hasStoredAdminKey()) {
    return null;
  }

  const label = identity?.scopes?.length
    ? identity.scopes.join(" ")
    : missingEndpoint
    ? "scopes unknown"
    : "loading…";
  const fp = identity?.key_fingerprint ?? "•••";
  const isAdmin = identity?.scopes?.includes("admin");

  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "0.4rem",
        fontFamily: "'DM Mono', monospace",
        fontSize: "0.55rem",
        letterSpacing: "0.06em",
        color: isAdmin ? "#ccffcc" : "rgba(0,255,65,0.7)",
        border: "1px solid rgba(0,255,65,0.18)",
        padding: "0.18rem 0.5rem",
        background: "rgba(0,255,65,0.04)",
      }}
      title={
        identity?.user_id
          ? `${identity.email ?? identity.user_id} · ${label}`
          : `key fingerprint ${fp} · ${label}`
      }
    >
      <span style={{ opacity: 0.7 }}>OP•{fp.slice(0, 6)}</span>
      <span>·</span>
      <span>{label}</span>
    </div>
  );
};

export default WhoAmIChip;
