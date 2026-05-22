import { useState } from "react";
import { apiFetch } from "../lib/api";
import { getStoredApiKey, getStoredAdminKey, setStoredAdminKey } from "../lib/storage";

const ALL_SCOPES = ["read", "verify", "ingest", "commit", "write", "admin"] as const;

type IssuedUser = {
  email: string;
  api_key: string;
  user_id: string;
  scopes: string[];
  role: string;
  password?: string;
};

const inp: React.CSSProperties = {
  width: "100%", background: "rgba(0,0,0,0.7)",
  border: "1px solid rgba(0,255,65,0.25)", color: "#00ff41",
  fontFamily: "'DM Mono', monospace", fontSize: "0.78rem",
  padding: "0.6rem 0.75rem", outline: "none", boxSizing: "border-box",
};

const lbl: React.CSSProperties = {
  display: "block", fontSize: "0.58rem", letterSpacing: "0.1em",
  color: "rgba(0,255,65,0.55)", marginBottom: "0.4rem",
};

function CopyField({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <div style={{ marginBottom: "1rem" }}>
      <div style={lbl}>{label}</div>
      <div style={{ display: "flex", gap: "0.5rem" }}>
        <code style={{
          flex: 1, background: "rgba(0,255,65,0.05)", border: "1px solid rgba(0,255,65,0.18)",
          padding: "0.55rem 0.75rem", fontSize: mono ? "0.7rem" : "0.78rem",
          wordBreak: "break-all", lineHeight: 1.5, color: "#00ff41",
          fontFamily: mono ? "'DM Mono', monospace" : "inherit",
        }}>
          {value}
        </code>
        <button
          type="button"
          onClick={() => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1800); }}
          style={{
            flexShrink: 0, background: copied ? "rgba(0,255,65,0.18)" : "rgba(0,255,65,0.07)",
            border: "1px solid rgba(0,255,65,0.4)", color: "#00ff41",
            fontFamily: "'DM Mono', monospace", fontSize: "0.6rem", letterSpacing: "0.08em",
            padding: "0.4rem 0.7rem", cursor: "pointer",
          }}
        >
          {copied ? "COPIED" : "COPY"}
        </button>
      </div>
    </div>
  );
}

function generatePassword(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, byte => alphabet[byte % alphabet.length]).join("");
}

export default function AdminPage() {
  const myKey = getStoredApiKey();
  const storedAdminKey = getStoredAdminKey() || myKey;

  const [adminKey, setAdminKey] = useState(storedAdminKey);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState(() => generatePassword());
  const [keyName, setKeyName] = useState("default");
  const [role, setRole] = useState<"user" | "admin">("user");
  const [scopes, setScopes] = useState<Set<string>>(new Set(["read", "verify", "ingest", "commit", "write"]));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<IssuedUser | null>(null);

  function toggleScope(s: string) {
    setScopes(prev => { const n = new Set(prev); n.has(s) ? n.delete(s) : n.add(s); return n; });
  }

  function setPreset(kind: "read" | "write" | "admin") {
    if (kind === "read") {
      setRole("user");
      setScopes(new Set(["read", "verify"]));
    } else if (kind === "write") {
      setRole("user");
      setScopes(new Set(["read", "verify", "ingest", "commit", "write"]));
    } else {
      setRole("admin");
      setScopes(new Set(["read", "verify", "ingest", "commit", "write", "admin"]));
    }
  }

  async function issueKey() {
    if (!adminKey.trim()) { setError("Admin key required."); return; }
    if (!email.trim()) { setError("Email required."); return; }
    if (password.length < 12) { setError("Password must be at least 12 characters."); return; }
    setError(null); setIssued(null); setLoading(true);
    try {
      const data = await apiFetch<Record<string, unknown>>("/auth/admin/users", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": adminKey,
          "X-Admin-Key": adminKey,
        },
        body: JSON.stringify({
          email: email.trim(), password,
          name: keyName.trim() || "default",
          scopes: [...scopes], role,
        }),
      });
      setIssued({ ...(data as unknown as IssuedUser), password });
      setEmail(""); setPassword(generatePassword());
      // Save admin key for next time
      setStoredAdminKey(adminKey.trim());
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }

  return (
    <div style={{ maxWidth: "660px", margin: "0 auto" }}>
      <div style={{ marginBottom: "2rem" }}>
        <div style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.4)", letterSpacing: "0.15em", marginBottom: "0.5rem" }}>
          OLYMPUS_PROTOCØL // KEY VAULT
        </div>
        <h1 style={{ fontSize: "1.4rem", fontWeight: 400, margin: 0, letterSpacing: "0.05em" }}>
          KEYS
        </h1>
        <p style={{ fontSize: "0.7rem", color: "rgba(0,255,65,0.5)", marginTop: "0.5rem", lineHeight: 1.6 }}>
          Your API key, and a tool to issue keys to other users.
        </p>
      </div>

      {/* Your key */}
      {myKey && (
        <div style={{ marginBottom: "2rem", padding: "1.25rem", border: "1px solid rgba(0,255,65,0.2)", background: "rgba(0,255,65,0.02)" }}>
          <div style={{ fontSize: "0.56rem", letterSpacing: "0.12em", color: "rgba(0,255,65,0.4)", marginBottom: "0.75rem" }}>
            YOUR API KEY
          </div>
          <CopyField label="ACTIVE KEY" value={myKey} />
          <div style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.35)", lineHeight: 1.5 }}>
            Pre-filled on the LEDGER tab. If you need to regenerate, reset your account from the startup screen.
          </div>
        </div>
      )}

      {/* Issue a key */}
      <div style={{ padding: "1.5rem", border: "1px solid rgba(0,255,65,0.14)", background: "rgba(0,255,65,0.02)" }}>
        <div style={{ fontSize: "0.58rem", letterSpacing: "0.12em", color: "rgba(0,255,65,0.45)", marginBottom: "1.25rem" }}>
          ISSUE A KEY TO ANOTHER USER
        </div>

        <div style={{ marginBottom: "1rem" }}>
          <label style={lbl}>YOUR ADMIN API KEY</label>
          <input
            type="password" value={adminKey}
            onChange={e => setAdminKey(e.target.value)}
            placeholder="admin key (pre-filled from your account)"
            style={inp}
          />
        </div>

        <div style={{ marginBottom: "1rem" }}>
          <label style={lbl}>NEW USER EMAIL</label>
          <input type="email" value={email} onChange={e => setEmail(e.target.value)}
            placeholder="user@example.com" style={inp} />
        </div>

        <div style={{ marginBottom: "1rem" }}>
          <label style={lbl}>APP PASSWORD (give to user)</label>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) auto", gap: "0.6rem" }}>
            <input type="text" value={password} onChange={e => setPassword(e.target.value)}
              style={inp} />
            <button type="button" onClick={() => setPassword(generatePassword())} style={{
              background: "rgba(0,0,0,0.5)", border: "1px solid rgba(0,255,65,0.25)",
              color: "rgba(0,255,65,0.75)", fontFamily: "'DM Mono', monospace",
              fontSize: "0.6rem", letterSpacing: "0.08em", padding: "0 0.75rem", cursor: "pointer",
            }}>GEN</button>
          </div>
        </div>

        <div style={{ marginBottom: "1rem" }}>
          <label style={lbl}>KEY NAME</label>
          <input type="text" value={keyName} onChange={e => setKeyName(e.target.value)}
            placeholder="default" style={inp} />
        </div>

        <div style={{ marginBottom: "1.25rem" }}>
          <label style={lbl}>ACCESS LEVEL</label>
          <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.75rem" }}>
            {([
              ["read", "READ ONLY"],
              ["write", "FULL WRITE"],
              ["admin", "ADMIN"],
            ] as const).map(([kind, label]) => (
              <button key={kind} type="button" onClick={() => setPreset(kind)} style={{
                background: (kind === "admin" ? role === "admin" : kind === "read" ? scopes.size === 2 : scopes.has("ingest") && role !== "admin")
                  ? "rgba(0,255,65,0.18)" : "rgba(0,0,0,0.5)",
                border: "1px solid rgba(0,255,65,0.3)", color: "#00ff41",
                fontFamily: "'DM Mono', monospace", fontSize: "0.62rem",
                letterSpacing: "0.08em", padding: "0.4rem 0.75rem", cursor: "pointer",
              }}>{label}</button>
            ))}
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.4rem" }}>
            {ALL_SCOPES.map(s => (
              <button key={s} type="button" onClick={() => toggleScope(s)} style={{
                background: scopes.has(s) ? "rgba(0,255,65,0.15)" : "rgba(0,0,0,0.5)",
                border: `1px solid ${scopes.has(s) ? "rgba(0,255,65,0.6)" : "rgba(0,255,65,0.18)"}`,
                color: scopes.has(s) ? "#00ff41" : "rgba(0,255,65,0.35)",
                fontFamily: "'DM Mono', monospace", fontSize: "0.62rem",
                letterSpacing: "0.08em", padding: "0.3rem 0.65rem", cursor: "pointer",
              }}>{s}</button>
            ))}
          </div>
        </div>

        <button type="button" onClick={() => void issueKey()} disabled={loading} style={{
          width: "100%", padding: "0.75rem",
          background: loading ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.12)",
          border: "1px solid rgba(0,255,65,0.5)", color: "#00ff41",
          fontFamily: "'DM Mono', monospace", fontSize: "0.72rem",
          letterSpacing: "0.12em", cursor: loading ? "not-allowed" : "pointer",
        }}>
          {loading ? "CREATING..." : "ISSUE KEY"}
        </button>

        {error && (
          <div style={{ padding: "0.75rem 1rem", border: "1px solid rgba(255,0,85,0.4)", color: "#ff0055", fontSize: "0.7rem", marginTop: "1rem", background: "rgba(255,0,85,0.05)" }}>
            {error}
          </div>
        )}

        {issued && (
          <div style={{ padding: "1.5rem", border: "1px solid rgba(0,255,65,0.35)", marginTop: "1rem", background: "rgba(0,255,65,0.03)" }}>
            <div style={{ fontSize: "0.56rem", letterSpacing: "0.12em", color: "rgba(0,255,65,0.5)", marginBottom: "1rem" }}>
              KEY ISSUED — COPY NOW, NOT SHOWN AGAIN
            </div>
            <CopyField label="EMAIL" value={issued.email} mono={false} />
            <CopyField label="APP PASSWORD (for login)" value={issued.password ?? ""} mono={false} />
            <CopyField label="API KEY" value={issued.api_key} />
            <div style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.4)", lineHeight: 1.6 }}>
              ROLE: {issued.role} · SCOPES: {issued.scopes.join(", ")}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
