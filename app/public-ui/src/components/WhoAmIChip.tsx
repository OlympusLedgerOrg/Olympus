/// Small header chip showing the operator's current API-key scopes +
/// a short BLAKE3 fingerprint of the key. Closes the "users can't see
/// what they have / what an endpoint requires" gap.
///
/// Heuristic: derives scopes from the locally-stored `olympus_admin_key`
/// by hitting a lightweight identity endpoint (`/auth/whoami` — defined
/// here as the conventional name; falls back to "scopes unknown" if the
/// endpoint isn't yet implemented so this component is forward-safe).
import { useEffect, useState } from "react";
import { ApiError, apiFetch } from "../lib/api";

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
    const key =
      typeof window !== "undefined"
        ? localStorage.getItem("olympus_admin_key")
        : null;
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
        if (e instanceof ApiError && (e.status === 404 || e.status === 501)) {
          setMissingEndpoint(true);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // No key in localStorage → render nothing (Layout doesn't reserve
  // space for us).
  if (typeof window !== "undefined" && !localStorage.getItem("olympus_admin_key")) {
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
