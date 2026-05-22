/// Admin-only page for managing users and their API keys.
///
/// Gated by the operator's `OLYMPUS_ADMIN_KEY` (pasted into the field at
/// top; stored only in component state — never persisted to localStorage
/// because it grants ungated mutation of the entire users + keys table).
///
/// Mirrors the backend at src-tauri/src/api/admin_users.rs:
///   * GET    /admin/users
///   * POST   /admin/users/{user_id}/keys
///   * PATCH  /admin/users/{user_id}/role
///   * PATCH  /admin/keys/{key_id}/scopes
///   * DELETE /admin/keys/{key_id}
import { useCallback, useEffect, useMemo, useState } from "react";

type Row = {
  user_id: string;
  email: string;
  role: string;
  plan: string;
  user_created_at: string;
  key_id: string | null;
  key_name: string | null;
  key_hash_prefix: string | null;
  key_scopes: string | null;
  key_created_at: string | null;
};

type GroupedUser = {
  user_id: string;
  email: string;
  role: string;
  plan: string;
  keys: {
    key_id: string;
    name: string;
    hash_prefix: string;
    scopes: string[];
    created_at: string;
  }[];
};

const ALL_SCOPES = [
  "read", "verify", "ingest", "commit", "write", "prove", "admin",
] as const;

const inp: React.CSSProperties = {
  width: "100%", background: "rgba(0,0,0,0.7)",
  border: "1px solid rgba(0,255,65,0.25)", color: "#00ff41",
  fontFamily: "'DM Mono', monospace", fontSize: "0.78rem",
  padding: "0.5rem 0.7rem", outline: "none", boxSizing: "border-box",
};
const lbl: React.CSSProperties = {
  display: "block", fontSize: "0.55rem", letterSpacing: "0.1em",
  color: "rgba(0,255,65,0.55)", marginBottom: "0.35rem",
};
const btn = (kind: "primary" | "ghost" | "danger" = "primary"): React.CSSProperties => ({
  background: kind === "danger" ? "rgba(255,0,85,0.07)" : "rgba(0,255,65,0.08)",
  border: `1px solid ${kind === "danger" ? "rgba(255,0,85,0.45)" : "rgba(0,255,65,0.4)"}`,
  color: kind === "danger" ? "#ff4477" : "#00ff41",
  fontFamily: "'DM Mono', monospace", fontSize: "0.6rem", letterSpacing: "0.08em",
  padding: "0.35rem 0.7rem", cursor: "pointer",
});

function groupRows(rows: Row[]): GroupedUser[] {
  const map = new Map<string, GroupedUser>();
  for (const r of rows) {
    if (!map.has(r.user_id)) {
      map.set(r.user_id, {
        user_id: r.user_id,
        email: r.email,
        role: r.role,
        plan: r.plan,
        keys: [],
      });
    }
    if (r.key_id) {
      const u = map.get(r.user_id)!;
      let parsed: string[] = [];
      try { parsed = r.key_scopes ? JSON.parse(r.key_scopes) : []; } catch { parsed = []; }
      u.keys.push({
        key_id: r.key_id,
        name: r.key_name ?? "(unnamed)",
        hash_prefix: r.key_hash_prefix ?? "",
        scopes: parsed,
        created_at: r.key_created_at ?? "",
      });
    }
  }
  return Array.from(map.values());
}

async function adminFetch(adminKey: string, path: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  headers.set("x-admin-key", adminKey);
  if (init?.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  return fetch(path, { ...init, headers });
}

const AdminUsersPage: React.FC = () => {
  const [adminKey, setAdminKey] = useState("");
  const [rows, setRows] = useState<Row[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  // Raw key surfaced once per mint — cleared on the next mint or page refresh.
  const [justMinted, setJustMinted] = useState<{
    user_email: string; raw_key: string; scopes: string[];
  } | null>(null);

  const grouped = useMemo(() => groupRows(rows), [rows]);

  const refresh = useCallback(async () => {
    if (!adminKey.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const resp = await adminFetch(adminKey, "/admin/users");
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.detail ?? `HTTP ${resp.status}`);
      }
      const data = await resp.json();
      setRows(data.rows ?? []);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [adminKey]);

  useEffect(() => { void refresh(); }, [refresh]);

  return (
    <div style={{ padding: "2rem", maxWidth: 1100, margin: "0 auto" }}>
      <h1 style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "1.1rem", color: "#00ff41", letterSpacing: "0.16em", marginBottom: "1.5rem" }}>
        ADMIN ▸ USERS
      </h1>

      <section style={{ marginBottom: "2rem", padding: "1rem", border: "1px solid rgba(0,255,65,0.2)" }}>
        <label style={lbl}>OPERATOR ADMIN KEY (matches OLYMPUS_ADMIN_KEY env var)</label>
        <input
          type="password"
          value={adminKey}
          onChange={e => setAdminKey(e.target.value)}
          placeholder="paste your OLYMPUS_ADMIN_KEY here"
          style={inp}
          autoComplete="off"
          spellCheck={false}
        />
        <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.6rem" }}>
          <button type="button" onClick={refresh} style={btn("primary")} disabled={!adminKey.trim() || loading}>
            {loading ? "LOADING…" : "LOAD USERS"}
          </button>
          {error && (
            <span style={{ color: "#ff4477", fontSize: "0.65rem", alignSelf: "center" }}>
              {error}
            </span>
          )}
        </div>
        <div style={{ marginTop: "0.6rem", fontSize: "0.6rem", color: "rgba(255,200,120,0.7)", lineHeight: 1.5 }}>
          The admin key never leaves your browser session — it's not persisted to localStorage and not sent anywhere
          except the local <code>x-admin-key</code> header. Close this tab to forget it.
        </div>
      </section>

      {justMinted && (
        <section style={{ marginBottom: "2rem", padding: "1rem", border: "2px solid rgba(0,255,65,0.5)", background: "rgba(0,255,65,0.04)" }}>
          <h2 style={{ fontFamily: "'Share Tech Mono', monospace", color: "#ccffcc", fontSize: "0.9rem", letterSpacing: "0.1em", marginTop: 0 }}>
            KEY MINTED — COPY NOW (shown only once)
          </h2>
          <div style={{ marginBottom: "0.6rem", fontSize: "0.7rem", color: "rgba(0,255,65,0.7)" }}>
            For: <strong>{justMinted.user_email}</strong> · scopes: {justMinted.scopes.join(", ")}
          </div>
          <code style={{
            display: "block", padding: "0.7rem", background: "#000",
            border: "1px solid rgba(0,255,65,0.4)", color: "#00ff41",
            fontFamily: "'DM Mono', monospace", fontSize: "0.78rem",
            wordBreak: "break-all", lineHeight: 1.4,
          }}>
            {justMinted.raw_key}
          </code>
          <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.6rem" }}>
            <button type="button" style={btn("primary")} onClick={() => navigator.clipboard.writeText(justMinted.raw_key)}>
              COPY
            </button>
            <button type="button" style={btn("ghost")} onClick={() => setJustMinted(null)}>
              DISMISS
            </button>
          </div>
        </section>
      )}

      {grouped.map(u => (
        <UserCard
          key={u.user_id}
          user={u}
          adminKey={adminKey}
          onMint={(raw, scopes) => setJustMinted({ user_email: u.email, raw_key: raw, scopes })}
          onChanged={refresh}
        />
      ))}

      {grouped.length === 0 && adminKey.trim() && !loading && !error && (
        <div style={{ fontSize: "0.7rem", color: "rgba(0,255,65,0.5)", textAlign: "center", padding: "2rem" }}>
          No users registered yet.
        </div>
      )}
    </div>
  );
};

const UserCard: React.FC<{
  user: GroupedUser;
  adminKey: string;
  onMint: (raw_key: string, scopes: string[]) => void;
  onChanged: () => void;
}> = ({ user, adminKey, onMint, onChanged }) => {
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyScopes, setNewKeyScopes] = useState<string[]>(["read", "verify"]);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const toggleScope = (s: string) => {
    setNewKeyScopes(scopes => scopes.includes(s) ? scopes.filter(x => x !== s) : [...scopes, s]);
  };

  const mint = async () => {
    if (!newKeyName.trim()) {
      setActionError("name is required");
      return;
    }
    setBusy(true);
    setActionError(null);
    try {
      const resp = await adminFetch(adminKey, `/admin/users/${user.user_id}/keys`, {
        method: "POST",
        body: JSON.stringify({ name: newKeyName.trim(), scopes: newKeyScopes }),
      });
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.detail ?? `HTTP ${resp.status}`);
      }
      const data = await resp.json();
      onMint(data.raw_key, data.scopes);
      setNewKeyName("");
      onChanged();
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const setRole = async (role: string) => {
    setBusy(true);
    setActionError(null);
    try {
      const resp = await adminFetch(adminKey, `/admin/users/${user.user_id}/role`, {
        method: "PATCH",
        body: JSON.stringify({ role }),
      });
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.detail ?? `HTTP ${resp.status}`);
      }
      onChanged();
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const revokeKey = async (key_id: string) => {
    if (!window.confirm(`Revoke key ${key_id}?\n\nThis is immediate and irreversible.`)) return;
    setBusy(true);
    setActionError(null);
    try {
      const resp = await adminFetch(adminKey, `/admin/keys/${key_id}`, { method: "DELETE" });
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.detail ?? `HTTP ${resp.status}`);
      }
      onChanged();
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const updateKeyScopes = async (key_id: string, scopes: string[]) => {
    setBusy(true);
    setActionError(null);
    try {
      const resp = await adminFetch(adminKey, `/admin/keys/${key_id}/scopes`, {
        method: "PATCH",
        body: JSON.stringify({ scopes }),
      });
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.detail ?? `HTTP ${resp.status}`);
      }
      onChanged();
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <article style={{ marginBottom: "1.5rem", padding: "1.2rem", border: "1px solid rgba(0,255,65,0.18)", background: "rgba(0,255,65,0.015)" }}>
      <header style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1rem", flexWrap: "wrap", gap: "0.6rem" }}>
        <div>
          <div style={{ fontSize: "0.85rem", color: "#00ff41", fontFamily: "'DM Mono', monospace" }}>
            {user.email}
          </div>
          <div style={{ fontSize: "0.55rem", color: "rgba(0,255,65,0.5)", marginTop: "0.2rem", letterSpacing: "0.08em" }}>
            id: {user.user_id} · plan: {user.plan} · role:{" "}
            <span style={{ color: user.role === "admin" ? "#ccffcc" : "rgba(0,255,65,0.7)" }}>
              {user.role}
            </span>
          </div>
        </div>
        <div style={{ display: "flex", gap: "0.4rem" }}>
          <button type="button" style={btn("ghost")} disabled={busy} onClick={() => setRole(user.role === "admin" ? "user" : "admin")}>
            {user.role === "admin" ? "DEMOTE" : "PROMOTE → ADMIN"}
          </button>
        </div>
      </header>

      <div style={{ marginBottom: "1rem" }}>
        <div style={lbl}>API KEYS ({user.keys.length})</div>
        {user.keys.length === 0 && (
          <div style={{ fontSize: "0.62rem", color: "rgba(0,255,65,0.4)", fontStyle: "italic" }}>
            no keys yet — mint one below
          </div>
        )}
        {user.keys.map(k => (
          <div key={k.key_id} style={{ padding: "0.5rem 0.7rem", border: "1px solid rgba(0,255,65,0.12)", marginBottom: "0.4rem", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "0.5rem" }}>
            <div style={{ fontSize: "0.62rem" }}>
              <strong style={{ color: "#00ff41" }}>{k.name}</strong>
              <span style={{ color: "rgba(0,255,65,0.45)" }}>
                {" "}· hash: {k.hash_prefix}… · created: {k.created_at?.slice(0, 10)}
              </span>
              <div style={{ marginTop: "0.3rem", display: "flex", gap: "0.3rem", flexWrap: "wrap" }}>
                {ALL_SCOPES.map(s => (
                  <label key={s} style={{ fontSize: "0.55rem", cursor: "pointer", color: k.scopes.includes(s) ? "#00ff41" : "rgba(0,255,65,0.3)" }}>
                    <input
                      type="checkbox"
                      checked={k.scopes.includes(s)}
                      onChange={() => {
                        const next = k.scopes.includes(s) ? k.scopes.filter(x => x !== s) : [...k.scopes, s];
                        void updateKeyScopes(k.key_id, next);
                      }}
                      style={{ accentColor: "#00ff41", marginRight: 2 }}
                    />
                    {s}
                  </label>
                ))}
              </div>
            </div>
            <button type="button" style={btn("danger")} disabled={busy} onClick={() => revokeKey(k.key_id)}>
              REVOKE
            </button>
          </div>
        ))}
      </div>

      <div style={{ borderTop: "1px dashed rgba(0,255,65,0.15)", paddingTop: "0.8rem" }}>
        <div style={lbl}>MINT NEW KEY</div>
        <div style={{ display: "flex", gap: "0.4rem", alignItems: "center", flexWrap: "wrap", marginBottom: "0.4rem" }}>
          <input
            type="text"
            value={newKeyName}
            onChange={e => setNewKeyName(e.target.value)}
            placeholder="key name (e.g. desktop-laptop)"
            style={{ ...inp, flex: 1, minWidth: 200 }}
          />
          <button type="button" style={btn("primary")} disabled={busy} onClick={mint}>
            {busy ? "…" : "MINT"}
          </button>
        </div>
        <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
          {ALL_SCOPES.map(s => (
            <label key={s} style={{ fontSize: "0.6rem", cursor: "pointer", color: newKeyScopes.includes(s) ? "#00ff41" : "rgba(0,255,65,0.4)" }}>
              <input
                type="checkbox"
                checked={newKeyScopes.includes(s)}
                onChange={() => toggleScope(s)}
                style={{ accentColor: "#00ff41", marginRight: 2 }}
              />
              {s}
            </label>
          ))}
        </div>
        {actionError && (
          <div style={{ marginTop: "0.5rem", color: "#ff4477", fontSize: "0.6rem" }}>{actionError}</div>
        )}
      </div>
    </article>
  );
};

export default AdminUsersPage;
