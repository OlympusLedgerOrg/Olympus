import { useState } from "react";

const API_BASE =
  (typeof import.meta !== "undefined" &&
    (import.meta as { env?: { VITE_API_BASE?: string } }).env?.VITE_API_BASE) ||
  (typeof window !== "undefined" ? window.location.origin : "");

const ALL_SCOPES = ["read", "write", "ingest", "commit", "verify", "admin"] as const;

type RegisteredUser = {
  user_id: string;
  email: string;
  api_key: string;
  key_id: string;
  scopes: string[];
};

function CopyField({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <div style={{ marginBottom: "1.2rem" }}>
      <div style={{ fontSize: "0.58rem", color: "rgba(0,255,65,0.5)", letterSpacing: "0.1em", marginBottom: "0.35rem" }}>
        {label}
      </div>
      <div style={{ display: "flex", gap: "0.6rem", alignItems: "flex-start" }}>
        <code style={{
          flex: 1,
          background: "rgba(0,255,65,0.05)",
          border: "1px solid rgba(0,255,65,0.18)",
          padding: "0.6rem 0.8rem",
          fontSize: mono ? "0.72rem" : "0.78rem",
          wordBreak: "break-all",
          lineHeight: 1.5,
          color: "#00ff41",
          fontFamily: mono ? "'DM Mono', monospace" : "inherit",
        }}>
          {value}
        </code>
        <button
          type="button"
          onClick={() => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1800); }}
          style={{
            flexShrink: 0,
            background: copied ? "rgba(0,255,65,0.18)" : "rgba(0,255,65,0.07)",
            border: "1px solid rgba(0,255,65,0.4)",
            color: "#00ff41",
            fontSize: "0.6rem",
            letterSpacing: "0.08em",
            padding: "0.45rem 0.75rem",
            cursor: "pointer",
            fontFamily: "'DM Mono', monospace",
          }}
        >
          {copied ? "COPIED" : "COPY"}
        </button>
      </div>
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  width: "100%",
  background: "rgba(0,0,0,0.7)",
  border: "1px solid rgba(0,255,65,0.25)",
  color: "#00ff41",
  fontFamily: "'DM Mono', monospace",
  fontSize: "0.78rem",
  padding: "0.6rem 0.75rem",
  outline: "none",
  boxSizing: "border-box",
};

const labelStyle: React.CSSProperties = {
  display: "block",
  fontSize: "0.58rem",
  letterSpacing: "0.1em",
  color: "rgba(0,255,65,0.55)",
  marginBottom: "0.4rem",
};

// ── Register panel ────────────────────────────────────────────────────────────

function RegisterPanel() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [keyName, setKeyName] = useState("default");
  const [scopes, setScopes] = useState<Set<string>>(new Set(["ingest", "verify"]));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<RegisteredUser | null>(null);

  function toggleScope(s: string) {
    setScopes(prev => { const n = new Set(prev); n.has(s) ? n.delete(s) : n.add(s); return n; });
  }

  async function submit() {
    if (!email.trim()) { setError("Email required."); return; }
    if (password.length < 12) { setError("Password must be at least 12 characters."); return; }
    setError(null); setResult(null); setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password, name: keyName.trim() || "default", scopes: [...scopes] }),
      });
      const data = await res.json() as Record<string, unknown>;
      if (!res.ok) {
        const d = data.detail;
        setError(typeof d === "string" ? d : JSON.stringify(d));
        return;
      }
      setResult(data as unknown as RegisteredUser);
      setEmail(""); setPassword("");
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }

  return (
    <div style={{ padding: "1.5rem", border: "1px solid rgba(0,255,65,0.14)", background: "rgba(0,255,65,0.02)", marginBottom: "1.5rem" }}>
      <div style={{ fontSize: "0.58rem", letterSpacing: "0.12em", color: "rgba(0,255,65,0.45)", marginBottom: "1.2rem" }}>
        REGISTER NEW USER
      </div>

      <div style={{ marginBottom: "1rem" }}>
        <label style={labelStyle}>EMAIL</label>
        <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="user@example.com" style={inputStyle} />
      </div>

      <div style={{ marginBottom: "1rem" }}>
        <label style={labelStyle}>PASSWORD (min 12 chars)</label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="strong passphrase" style={inputStyle} />
      </div>

      <div style={{ marginBottom: "1rem" }}>
        <label style={labelStyle}>KEY NAME</label>
        <input type="text" value={keyName} onChange={e => setKeyName(e.target.value)} placeholder="default" style={inputStyle} />
      </div>

      <div style={{ marginBottom: "1.5rem" }}>
        <label style={labelStyle}>SCOPES</label>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
          {ALL_SCOPES.map(s => (
            <button key={s} type="button" onClick={() => toggleScope(s)} style={{
              background: scopes.has(s) ? "rgba(0,255,65,0.18)" : "rgba(0,0,0,0.5)",
              border: `1px solid ${scopes.has(s) ? "rgba(0,255,65,0.7)" : "rgba(0,255,65,0.2)"}`,
              color: scopes.has(s) ? "#00ff41" : "rgba(0,255,65,0.4)",
              fontFamily: "'DM Mono', monospace",
              fontSize: "0.65rem",
              letterSpacing: "0.08em",
              padding: "0.35rem 0.75rem",
              cursor: "pointer",
            }}>{s}</button>
          ))}
        </div>
      </div>

      <button type="button" onClick={() => void submit()} disabled={loading} style={{
        width: "100%",
        padding: "0.75rem",
        background: loading ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.12)",
        border: "1px solid rgba(0,255,65,0.5)",
        color: "#00ff41",
        fontFamily: "'DM Mono', monospace",
        fontSize: "0.72rem",
        letterSpacing: "0.12em",
        cursor: loading ? "not-allowed" : "pointer",
      }}>
        {loading ? "REGISTERING..." : "CREATE USER + API KEY"}
      </button>

      {error && (
        <div style={{ padding: "0.75rem 1rem", border: "1px solid rgba(255,0,85,0.4)", color: "#ff0055", fontSize: "0.7rem", marginTop: "1rem", background: "rgba(255,0,85,0.05)" }}>
          {error}
        </div>
      )}

      {result && (
        <div style={{ padding: "1.5rem", border: "1px solid rgba(0,255,65,0.35)", marginTop: "1rem", background: "rgba(0,255,65,0.03)" }}>
          <div style={{ fontSize: "0.58rem", letterSpacing: "0.12em", color: "rgba(0,255,65,0.5)", marginBottom: "1rem" }}>
            USER CREATED — COPY THE API KEY NOW, IT WON'T BE SHOWN AGAIN
          </div>
          <CopyField label="EMAIL" value={result.email} mono={false} />
          <CopyField label="API KEY" value={result.api_key} />
          <div style={{ fontSize: "0.62rem", color: "rgba(0,255,65,0.45)", lineHeight: 1.6 }}>
            <strong style={{ color: "rgba(0,255,65,0.7)" }}>USER ID</strong>{" "}{result.user_id}
            {" · "}
            <strong style={{ color: "rgba(0,255,65,0.7)" }}>SCOPES</strong>{" "}{result.scopes.join(", ")}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Login / key lookup panel ──────────────────────────────────────────────────

type KeyInfo = { id: string; name: string; scopes: string[]; expires_at: string };

function LoginPanel() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [keys, setKeys] = useState<KeyInfo[] | null>(null);
  const [userId, setUserId] = useState("");

  async function submit() {
    if (!email.trim() || !password) { setError("Email and password required."); return; }
    setError(null); setKeys(null); setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password }),
      });
      const data = await res.json() as { keys?: KeyInfo[]; user_id?: string; detail?: unknown };
      if (!res.ok) {
        const d = data.detail;
        setError(typeof d === "string" ? d : "Login failed.");
        return;
      }
      setKeys(data.keys ?? []);
      setUserId(data.user_id ?? "");
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }

  return (
    <div style={{ padding: "1.5rem", border: "1px solid rgba(0,255,65,0.14)", background: "rgba(0,255,65,0.02)", marginBottom: "1.5rem" }}>
      <div style={{ fontSize: "0.58rem", letterSpacing: "0.12em", color: "rgba(0,255,65,0.45)", marginBottom: "1.2rem" }}>
        LOOK UP USER KEYS
      </div>

      <div style={{ marginBottom: "1rem" }}>
        <label style={labelStyle}>EMAIL</label>
        <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="user@example.com" style={inputStyle} />
      </div>

      <div style={{ marginBottom: "1.5rem" }}>
        <label style={labelStyle}>PASSWORD</label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="passphrase" style={inputStyle} />
      </div>

      <button type="button" onClick={() => void submit()} disabled={loading} style={{
        width: "100%",
        padding: "0.75rem",
        background: loading ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.12)",
        border: "1px solid rgba(0,255,65,0.5)",
        color: "#00ff41",
        fontFamily: "'DM Mono', monospace",
        fontSize: "0.72rem",
        letterSpacing: "0.12em",
        cursor: loading ? "not-allowed" : "pointer",
      }}>
        {loading ? "CHECKING..." : "LOOK UP KEYS"}
      </button>

      {error && (
        <div style={{ padding: "0.75rem 1rem", border: "1px solid rgba(255,0,85,0.4)", color: "#ff0055", fontSize: "0.7rem", marginTop: "1rem", background: "rgba(255,0,85,0.05)" }}>
          {error}
        </div>
      )}

      {keys !== null && (
        <div style={{ marginTop: "1rem" }}>
          <div style={{ fontSize: "0.58rem", letterSpacing: "0.1em", color: "rgba(0,255,65,0.45)", marginBottom: "0.75rem" }}>
            {keys.length === 0 ? "NO ACTIVE KEYS" : `${keys.length} ACTIVE KEY(S) — user_id: ${userId}`}
          </div>
          {keys.map(k => (
            <div key={k.id} style={{ padding: "0.75rem 1rem", border: "1px solid rgba(0,255,65,0.15)", marginBottom: "0.5rem", fontSize: "0.7rem", color: "rgba(0,255,65,0.8)" }}>
              <strong>{k.name}</strong>{" · "}{k.scopes.join(", ")}{" · expires "}{k.expires_at.slice(0, 10)}
              <br />
              <span style={{ color: "rgba(0,255,65,0.4)", fontSize: "0.6rem" }}>{k.id}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Admin key reload panel ────────────────────────────────────────────────────

function ReloadPanel() {
  const [adminKey, setAdminKey] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function reload() {
    setStatus(null); setError(null);
    try {
      const res = await fetch(`${API_BASE}/key/admin/reload-keys`, {
        method: "POST",
        headers: { "X-Admin-Key": adminKey },
      });
      const data = await res.json() as { key_count?: number };
      if (!res.ok) { setError("Reload failed."); return; }
      setStatus(`[ok] Reloaded — ${data.key_count ?? "?"} env key(s) active`);
    } catch (e) { setError(String(e)); }
  }

  return (
    <div style={{ padding: "1rem 1.5rem", border: "1px solid rgba(0,255,65,0.1)", display: "flex", gap: "1rem", flexWrap: "wrap", alignItems: "center" }}>
      <div style={{ flex: 1 }}>
        <label style={labelStyle}>ADMIN KEY (env-var key hot-reload)</label>
        <input type="password" value={adminKey} onChange={e => setAdminKey(e.target.value)} placeholder="OLYMPUS_ADMIN_KEY" style={{ ...inputStyle, width: "auto", minWidth: "280px" }} />
      </div>
      <button type="button" onClick={() => void reload()} style={{
        background: "transparent",
        border: "1px solid rgba(0,255,65,0.3)",
        color: "rgba(0,255,65,0.7)",
        fontFamily: "'DM Mono', monospace",
        fontSize: "0.62rem",
        letterSpacing: "0.1em",
        padding: "0.5rem 1rem",
        cursor: "pointer",
        whiteSpace: "nowrap",
        alignSelf: "flex-end",
        marginBottom: "0.05rem",
      }}>RELOAD ENV KEYS</button>
      {status && <div style={{ fontSize: "0.65rem", color: "#00ff41", width: "100%" }}>{status}</div>}
      {error && <div style={{ fontSize: "0.65rem", color: "#ff0055", width: "100%" }}>{error}</div>}
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AdminPage() {
  return (
    <div style={{ maxWidth: "680px", margin: "0 auto" }}>
      <div style={{ marginBottom: "2.5rem" }}>
        <div style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.4)", letterSpacing: "0.15em", marginBottom: "0.5rem" }}>
          OLYMPUS_PROTOCØL // ADMIN
        </div>
        <h1 style={{ fontSize: "1.4rem", fontWeight: 400, margin: 0, letterSpacing: "0.05em" }}>
          USER ONBOARDING
        </h1>
        <p style={{ fontSize: "0.7rem", color: "rgba(0,255,65,0.5)", marginTop: "0.6rem", lineHeight: 1.6 }}>
          Create users with a password and an API key in one step. Keys live in postgres — no env file editing required.
          The raw key is shown once on registration.
        </p>
      </div>

      <RegisterPanel />
      <LoginPanel />
      <ReloadPanel />
    </div>
  );
}
