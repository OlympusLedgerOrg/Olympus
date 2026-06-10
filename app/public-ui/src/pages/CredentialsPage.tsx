/// Operator-facing Soulbound Token (SBT) page.
///
/// Issue, list, revoke, and verify Olympus-native credentials. Every
/// credential is BJJ-signed by the federation authority key at issue and
/// revocation, so a holder can take the JSON payload to a court / lawyer
/// / auditor and have them verify it offline against the federation's
/// public key — no Olympus node contact required.
///
/// Backend wiring: src-tauri/src/api/credentials.rs
import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../lib/api";
import { getStoredApiKey, getStoredAdminKey } from "../lib/storage";

// Best-effort error message extraction. The typed ApiError class lives on
// the post-#941 main; until this branch rebases onto it, just stringify.
function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

const COMMON_TYPES = [
  "press_credential",
  "foia_requester",
  "court_observer",
  "research_clearance",
  "authority_sbt",
] as const;

type Signature = { r8x: string; r8y: string; s: string };

// Pedersen commitment over `details`. Present iff the row was issued with
// `commit: true`; in that case `details` is `{}` and only the commitment is
// stored server-side.
type Commitment = { x: string; y: string; version: number };

type Credential = {
  id: string;
  holder_key: string;
  credential_type: string;
  issued_at: string;
  revoked_at: string | null;
  issuer: string;
  commit_id: string;
  details: Record<string, unknown>;
  issuer_pubkey: { r8x: string; r8y: string } | null;
  issued_signature: Signature | null;
  revoked_signature: Signature | null;
  commitment?: Commitment | null;
};

// The one-time opening returned by POST /credentials when `commit: true`.
// The server discards it; the holder must keep it to verify later.
type Opening = { m: string; r: string };
type IssueResult = Credential & { opening?: Opening | null };

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

// Read fresh on every request — NOT memoized at mount. The operator may paste
// or update the key after this page mounts (e.g. via InitialSecretsModal
// injecting it on first launch, or AdminUsersPage), and a snapshot would keep
// sending the stale/empty value and yield spurious 401/403s until a remount.
// Credential endpoints authenticate on a scoped X-API-Key, so prefer the API-key
// slot and fall back to the admin/bootstrap key (which the system key fills too).
function currentApiKey(): string {
  return getStoredApiKey() || getStoredAdminKey();
}

const CredentialsPage: React.FC = () => {
  const [creds, setCreds] = useState<Credential[]>([]);
  const [filterHolder, setFilterHolder] = useState("");
  const [filterType, setFilterType] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const [newHolder, setNewHolder] = useState("");
  const [newType, setNewType] = useState<string>(COMMON_TYPES[0]);
  const [newDetails, setNewDetails] = useState("{}");
  const [commitPrivate, setCommitPrivate] = useState(false);
  const [issuing, setIssuing] = useState(false);
  const [justIssued, setJustIssued] = useState<IssueResult | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const qs = new URLSearchParams();
      if (filterHolder.trim()) qs.set("holder", filterHolder.trim());
      if (filterType.trim()) qs.set("type", filterType.trim());
      const url = qs.toString() ? `/credentials?${qs}` : "/credentials";
      const data = await apiFetch<{ credentials: Credential[] }>(url, {
        headers: { "X-API-Key": currentApiKey() },
      });
      setCreds(data.credentials ?? []);
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setLoading(false);
    }
  }, [filterHolder, filterType]);

  // Initial + filter-change reload from backend (external system).
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => { void refresh(); }, [refresh]);

  const issue = async () => {
    if (!newHolder.trim() || !newType.trim()) {
      setError("holder + type required");
      return;
    }
    let parsed: Record<string, unknown> = {};
    if (newDetails.trim()) {
      try { parsed = JSON.parse(newDetails); }
      catch (e) { setError(`details JSON: ${(e as Error).message}`); return; }
    }
    setIssuing(true);
    setError(null);
    try {
      const issued = await apiFetch<IssueResult>("/credentials", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": currentApiKey() },
        body: JSON.stringify({
          holder_key: newHolder.trim(),
          credential_type: newType.trim(),
          details: parsed,
          commit: commitPrivate,
        }),
      });
      setJustIssued(issued);
      setNewHolder(""); setNewDetails("{}");
      void refresh();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setIssuing(false);
    }
  };

  const revoke = async (id: string) => {
    if (!window.confirm(`Revoke credential ${id}?\n\nIrreversible. A revocation signature will be written and the credential will be flagged invalid for verifiers.`)) return;
    try {
      await apiFetch(`/credentials/${id}/revoke`, {
        method: "POST",
        headers: { "X-API-Key": currentApiKey() },
      });
      void refresh();
    } catch (e) {
      setError(errMsg(e));
    }
  };

  const verify = async (c: Credential) => {
    // Privately-committed rows can additionally prove that a supplied
    // opening (m, r) reconstructs the stored commitment. Collect it if the
    // operator has it; otherwise fall back to the signature/commit_id check.
    let opening: Opening | undefined;
    if (c.commitment) {
      const raw = window.prompt(
        `This credential is privately committed (Pedersen v${c.commitment.version}).\n\n` +
        `Paste the opening JSON {"m":"…","r":"…"} to prove the cleartext opens\n` +
        `the commitment, or leave blank to check only the signature + commit_id.`,
        "",
      );
      if (raw && raw.trim()) {
        try {
          const parsed = JSON.parse(raw);
          if (typeof parsed.m === "string" && typeof parsed.r === "string") {
            opening = { m: parsed.m, r: parsed.r };
          } else {
            setError('opening must be {"m":"…","r":"…"}');
            return;
          }
        } catch (e) {
          setError(`opening JSON: ${errMsg(e)}`);
          return;
        }
      }
    }
    try {
      const init: RequestInit = {
        method: "POST",
        headers: { "X-API-Key": currentApiKey() },
      };
      if (opening) {
        init.headers = { ...init.headers, "Content-Type": "application/json" };
        init.body = JSON.stringify({ opening });
      }
      const r = await apiFetch<{
        commit_id_matches: boolean;
        issued_signature_valid: boolean;
        revoked_signature_valid: boolean | null;
        is_revoked: boolean;
        commitment_opens?: boolean | null;
      }>(`/credentials/${c.id}/verify`, init);
      window.alert(
        `commit_id matches:      ${r.commit_id_matches}\n` +
        `issued signature valid: ${r.issued_signature_valid}\n` +
        (r.is_revoked
          ? `revoked sig valid:      ${r.revoked_signature_valid ?? "n/a"}\n`
          : "") +
        (r.commitment_opens != null
          ? `commitment opens:       ${r.commitment_opens}\n`
          : "") +
        `\nThis is a server-side re-check. The real verification is\n` +
        `done OFFLINE by anyone with the federation's BJJ pubkey:\n` +
        `BLAKE3 the commit and check the iden3 BJJ signature.`
      );
    } catch (e) {
      setError(errMsg(e));
    }
  };

  return (
    <div style={{ padding: "2rem", maxWidth: 1100, margin: "0 auto" }}>
      <h1 style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "1.1rem", color: "#00ff41", letterSpacing: "0.16em", marginBottom: "1.2rem" }}>
        CREDENTIALS ▸ SBTs
      </h1>
      <p style={{ fontSize: "0.7rem", color: "rgba(0,255,65,0.55)", lineHeight: 1.5, marginBottom: "1.6rem", maxWidth: 720 }}>
        Olympus-native Soulbound Tokens — non-transferable credentials cryptographically signed by the federation's BJJ authority key. Verifiable offline by anyone holding the federation pubkey; no blockchain involved.
      </p>

      {justIssued && (
        <section style={{ marginBottom: "1.8rem", padding: "1rem", border: "2px solid rgba(0,255,65,0.5)", background: "rgba(0,255,65,0.04)" }}>
          <h2 style={{ fontFamily: "'Share Tech Mono', monospace", color: "#ccffcc", fontSize: "0.85rem", margin: 0, marginBottom: "0.4rem", letterSpacing: "0.1em" }}>
            CREDENTIAL ISSUED
          </h2>
          <div style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.6)", marginBottom: "0.4rem" }}>
            id: <code>{justIssued.id}</code> · commit: <code>{justIssued.commit_id.slice(0, 24)}…</code>
            {justIssued.commitment && <> · <span style={{ color: "#ffcc66" }}>🔒 private (Pedersen v{justIssued.commitment.version})</span></>}
          </div>
          {justIssued.opening && (
            <div style={{ marginBottom: "0.5rem", padding: "0.6rem 0.8rem", border: "1px solid rgba(255,180,0,0.55)", background: "rgba(255,180,0,0.06)" }}>
              <div style={{ fontSize: "0.6rem", color: "#ffcc66", letterSpacing: "0.06em", marginBottom: "0.35rem" }}>
                ⚠ PRIVATE OPENING (m, r) — SHOWN ONCE
              </div>
              <div style={{ fontSize: "0.55rem", color: "rgba(255,210,140,0.85)", lineHeight: 1.5, marginBottom: "0.4rem" }}>
                The server stored only the commitment and discarded the cleartext details.
                Save this opening now — it is the holder's only way to later prove the
                credential, and it is not recoverable.
              </div>
              <pre style={{ fontSize: "0.55rem", margin: 0, color: "#ffe0a0", overflow: "auto" }}>
{JSON.stringify(justIssued.opening, null, 2)}
              </pre>
              <button type="button" style={{ ...btn("primary"), marginTop: "0.4rem" }}
                onClick={() => navigator.clipboard.writeText(JSON.stringify(justIssued.opening))}>
                COPY OPENING
              </button>
            </div>
          )}
          <button type="button" style={btn("primary")} onClick={() => navigator.clipboard.writeText(JSON.stringify(justIssued, null, 2))}>
            COPY FULL JSON
          </button>
          <button type="button" style={{ ...btn("ghost"), marginLeft: "0.4rem" }} onClick={() => setJustIssued(null)}>
            DISMISS
          </button>
        </section>
      )}

      {/* Issue form */}
      <section style={{ marginBottom: "1.8rem", padding: "1.2rem", border: "1px solid rgba(0,255,65,0.2)" }}>
        <h2 style={{ fontFamily: "'Share Tech Mono', monospace", color: "#ccffcc", fontSize: "0.8rem", margin: 0, marginBottom: "0.8rem", letterSpacing: "0.1em" }}>
          ISSUE NEW
        </h2>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.7rem", marginBottom: "0.7rem" }}>
          <div>
            <label style={lbl}>HOLDER KEY</label>
            <input type="text" value={newHolder} onChange={e => setNewHolder(e.target.value)}
              placeholder="user:<uuid>, email:..., bjj:<x>:<y>" style={inp} />
          </div>
          <div>
            <label style={lbl}>CREDENTIAL TYPE</label>
            <input type="text" value={newType} onChange={e => setNewType(e.target.value)}
              list="credential-types" style={inp} />
            <datalist id="credential-types">
              {COMMON_TYPES.map(t => <option key={t} value={t} />)}
            </datalist>
          </div>
        </div>
        <div>
          <label style={lbl}>DETAILS (JSON, optional — hashed into commit; discarded if committing privately)</label>
          <textarea
            value={newDetails}
            onChange={e => setNewDetails(e.target.value)}
            style={{ ...inp, height: 96, fontFamily: "'DM Mono', monospace", resize: "vertical" }}
            spellCheck={false}
          />
        </div>
        <div style={{ marginTop: "0.7rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <input id="commit-private" type="checkbox" checked={commitPrivate}
            onChange={e => setCommitPrivate(e.target.checked)} />
          <label htmlFor="commit-private" style={{ ...lbl, marginBottom: 0, cursor: "pointer" }}>
            COMMIT PRIVATELY (PEDERSEN) — STORE ONLY THE COMMITMENT; CLEARTEXT DISCARDED, OPENING RETURNED ONCE
          </label>
        </div>
        <div style={{ marginTop: "0.7rem" }}>
          <button type="button" style={btn("primary")} disabled={issuing} onClick={issue}>
            {issuing ? "ISSUING…" : commitPrivate ? "ISSUE + COMMIT + SIGN" : "ISSUE + SIGN"}
          </button>
        </div>
      </section>

      {/* Filter */}
      <section style={{ marginBottom: "1rem", display: "flex", gap: "0.7rem", alignItems: "flex-end", flexWrap: "wrap" }}>
        <div style={{ flex: 1, minWidth: 200 }}>
          <label style={lbl}>FILTER: HOLDER</label>
          <input type="text" value={filterHolder} onChange={e => setFilterHolder(e.target.value)} style={inp} />
        </div>
        <div style={{ flex: 1, minWidth: 200 }}>
          <label style={lbl}>FILTER: TYPE</label>
          <input type="text" value={filterType} onChange={e => setFilterType(e.target.value)} style={inp} />
        </div>
        <button type="button" style={btn("ghost")} onClick={refresh} disabled={loading}>
          {loading ? "…" : "REFRESH"}
        </button>
      </section>

      {error && (
        <div style={{ marginBottom: "1rem", color: "#ff4477", fontSize: "0.7rem" }}>{error}</div>
      )}

      {creds.map(c => (
        <article key={c.id} style={{
          padding: "0.9rem 1rem", marginBottom: "0.7rem",
          border: `1px solid ${c.revoked_at ? "rgba(255,0,85,0.3)" : "rgba(0,255,65,0.18)"}`,
          background: c.revoked_at ? "rgba(255,0,85,0.025)" : "rgba(0,255,65,0.015)",
        }}>
          <header style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", flexWrap: "wrap", gap: "0.5rem" }}>
            <div>
              <div style={{ fontSize: "0.78rem", color: c.revoked_at ? "#ff4477" : "#00ff41" }}>
                {c.credential_type} {c.revoked_at && "· REVOKED"}
              </div>
              <div style={{ fontSize: "0.58rem", color: "rgba(0,255,65,0.5)", marginTop: "0.2rem" }}>
                holder: <code>{c.holder_key}</code> · id: <code>{c.id}</code>
              </div>
            </div>
            <div style={{ display: "flex", gap: "0.4rem" }}>
              <button type="button" style={btn("ghost")} onClick={() => verify(c)}>VERIFY</button>
              <button type="button" style={btn("ghost")} onClick={() => navigator.clipboard.writeText(JSON.stringify(c, null, 2))}>COPY JSON</button>
              {!c.revoked_at && (
                <button type="button" style={btn("danger")} onClick={() => revoke(c.id)}>REVOKE</button>
              )}
            </div>
          </header>
          <div style={{ marginTop: "0.5rem", fontSize: "0.58rem", color: "rgba(0,255,65,0.5)", lineHeight: 1.5 }}>
            issued: {c.issued_at?.slice(0, 19)}Z
            {c.revoked_at && <> · revoked: {c.revoked_at.slice(0, 19)}Z</>}
            <br />
            commit: <code>{c.commit_id}</code>
            {c.commitment && (
              <>
                <br />
                <span style={{ color: "#ffcc66" }}>
                  🔒 private commitment (Pedersen v{c.commitment.version}) · x:<code>{c.commitment.x.slice(0, 16)}…</code> y:<code>{c.commitment.y.slice(0, 16)}…</code>
                </span>
              </>
            )}
          </div>
          {Object.keys(c.details).length > 0 && (
            <pre style={{
              marginTop: "0.5rem", fontSize: "0.58rem", padding: "0.4rem 0.6rem",
              background: "rgba(0,255,65,0.04)", border: "1px solid rgba(0,255,65,0.1)",
              color: "rgba(0,255,65,0.7)", overflow: "auto", maxHeight: 200,
            }}>
              {JSON.stringify(c.details, null, 2)}
            </pre>
          )}
        </article>
      ))}

      {creds.length === 0 && !loading && !error && (
        <div style={{ fontSize: "0.7rem", color: "rgba(0,255,65,0.4)", textAlign: "center", padding: "2rem" }}>
          No credentials match the current filter.
        </div>
      )}
    </div>
  );
};

export default CredentialsPage;
