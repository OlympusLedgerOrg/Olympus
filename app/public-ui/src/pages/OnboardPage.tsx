import { useState } from "react";
import { Link } from "react-router-dom";

const API_BASE =
  (typeof import.meta !== "undefined" &&
    (import.meta as { env?: { VITE_API_BASE?: string } }).env?.VITE_API_BASE) ||
  (typeof window !== "undefined" ? window.location.origin : "");

type Step = "form" | "done";

function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div style={{ marginBottom: "1.2rem" }}>
      <div style={{ fontSize: "0.58rem", color: "rgba(0,255,65,0.5)", letterSpacing: "0.1em", marginBottom: "0.35rem" }}>
        {label}
      </div>
      <div style={{ display: "flex", gap: "0.6rem" }}>
        <code style={{
          flex: 1,
          background: "rgba(0,255,65,0.06)",
          border: "1px solid rgba(0,255,65,0.22)",
          padding: "0.65rem 0.85rem",
          fontSize: "0.75rem",
          wordBreak: "break-all",
          lineHeight: 1.55,
          color: "#00ff41",
        }}>
          {value}
        </code>
        <button
          type="button"
          onClick={() => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
          style={{
            flexShrink: 0,
            background: copied ? "rgba(0,255,65,0.2)" : "rgba(0,255,65,0.07)",
            border: "1px solid rgba(0,255,65,0.45)",
            color: "#00ff41",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.6rem",
            letterSpacing: "0.08em",
            padding: "0 0.85rem",
            cursor: "pointer",
            transition: "background 0.15s",
          }}
        >
          {copied ? "COPIED" : "COPY"}
        </button>
      </div>
    </div>
  );
}

export default function OnboardPage() {
  const [step, setStep] = useState<Step>("form");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [userId, setUserId] = useState("");

  const inp: React.CSSProperties = {
    width: "100%",
    background: "rgba(0,0,0,0.65)",
    border: "1px solid rgba(0,255,65,0.22)",
    borderRadius: 0,
    color: "#00ff41",
    fontFamily: "'DM Mono', monospace",
    fontSize: "0.85rem",
    padding: "0.75rem 0.9rem",
    outline: "none",
    boxSizing: "border-box",
  };

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password !== confirm) { setError("Passwords do not match."); return; }
    if (password.length < 12) { setError("Password must be at least 12 characters."); return; }

    setLoading(true);
    try {
      const name = email.split("@")[0] || "user";
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, name, scopes: ["ingest", "verify"] }),
      });
      const data = await res.json() as Record<string, unknown>;
      if (!res.ok) {
        const d = data.detail;
        setError(typeof d === "string" ? d : "Registration failed.");
        return;
      }
      setApiKey(data.api_key as string);
      setUserId(data.user_id as string);
      setStep("done");
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  if (step === "done") {
    return (
      <div style={{ maxWidth: "540px", margin: "0 auto", paddingTop: "2rem" }}>
        <div style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.4)", letterSpacing: "0.15em", marginBottom: "2rem" }}>
          OLYMPUS_PROTOCØL // ACCESS GRANTED
        </div>

        <div style={{
          padding: "2rem",
          border: "1px solid rgba(0,255,65,0.35)",
          background: "rgba(0,255,65,0.03)",
          marginBottom: "2rem",
        }}>
          <div style={{ fontSize: "0.58rem", letterSpacing: "0.12em", color: "rgba(0,255,65,0.5)", marginBottom: "1.5rem" }}>
            ACCOUNT CREATED — SAVE YOUR API KEY NOW
          </div>

          <CopyField label="EMAIL" value={email} />
          <CopyField label="API KEY" value={apiKey} />

          <div style={{
            marginTop: "1rem",
            padding: "0.75rem 1rem",
            background: "rgba(255,200,0,0.05)",
            border: "1px solid rgba(255,200,0,0.2)",
            fontSize: "0.65rem",
            color: "rgba(255,200,0,0.8)",
            lineHeight: 1.6,
          }}>
            This key is shown once and never stored in plaintext. Copy it before leaving this page.
          </div>
        </div>

        <div style={{ fontSize: "0.65rem", color: "rgba(0,255,65,0.45)", lineHeight: 1.7, marginBottom: "2rem" }}>
          <strong style={{ color: "rgba(0,255,65,0.7)" }}>USER ID</strong>&nbsp;&nbsp;{userId}
          <br />
          <strong style={{ color: "rgba(0,255,65,0.7)" }}>SCOPES</strong>&nbsp;&nbsp;&nbsp;ingest, verify
          <br />
          <strong style={{ color: "rgba(0,255,65,0.7)" }}>EXPIRES</strong>&nbsp;&nbsp;2099-01-01
        </div>

        <div style={{ display: "flex", gap: "1rem" }}>
          <Link to="/verify" style={{
            flex: 1,
            display: "block",
            padding: "0.75rem",
            border: "1px solid rgba(0,255,65,0.4)",
            color: "#00ff41",
            textDecoration: "none",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.7rem",
            letterSpacing: "0.1em",
            textAlign: "center",
            background: "rgba(0,255,65,0.08)",
          }}>
            GO TO VERIFY
          </Link>
          <button
            type="button"
            onClick={() => { setStep("form"); setEmail(""); setPassword(""); setConfirm(""); setApiKey(""); }}
            style={{
              flex: 1,
              padding: "0.75rem",
              border: "1px solid rgba(0,255,65,0.2)",
              color: "rgba(0,255,65,0.5)",
              fontFamily: "'DM Mono', monospace",
              fontSize: "0.7rem",
              letterSpacing: "0.1em",
              background: "transparent",
              cursor: "pointer",
            }}
          >
            ADD ANOTHER USER
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: "480px", margin: "0 auto", paddingTop: "2rem" }}>
      <div style={{ marginBottom: "2.5rem" }}>
        <div style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.4)", letterSpacing: "0.15em", marginBottom: "0.6rem" }}>
          OLYMPUS_PROTOCØL
        </div>
        <h1 style={{ fontSize: "1.6rem", fontWeight: 400, margin: "0 0 0.6rem", letterSpacing: "0.04em" }}>
          GET ACCESS
        </h1>
        <p style={{ fontSize: "0.72rem", color: "rgba(0,255,65,0.5)", margin: 0, lineHeight: 1.65 }}>
          Create an account to start submitting and verifying records on the ledger.
        </p>
      </div>

      <form onSubmit={(e) => void submit(e)} noValidate>
        <div style={{ marginBottom: "1.1rem" }}>
          <label style={{ display: "block", fontSize: "0.58rem", letterSpacing: "0.1em", color: "rgba(0,255,65,0.55)", marginBottom: "0.4rem" }}>
            EMAIL
          </label>
          <input
            type="email"
            value={email}
            onChange={e => setEmail(e.target.value)}
            placeholder="you@example.com"
            required
            autoComplete="email"
            style={inp}
          />
        </div>

        <div style={{ marginBottom: "1.1rem" }}>
          <label style={{ display: "block", fontSize: "0.58rem", letterSpacing: "0.1em", color: "rgba(0,255,65,0.55)", marginBottom: "0.4rem" }}>
            PASSWORD
          </label>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="at least 12 characters"
            required
            autoComplete="new-password"
            style={inp}
          />
        </div>

        <div style={{ marginBottom: "1.8rem" }}>
          <label style={{ display: "block", fontSize: "0.58rem", letterSpacing: "0.1em", color: "rgba(0,255,65,0.55)", marginBottom: "0.4rem" }}>
            CONFIRM PASSWORD
          </label>
          <input
            type="password"
            value={confirm}
            onChange={e => setConfirm(e.target.value)}
            placeholder="repeat password"
            required
            autoComplete="new-password"
            style={inp}
          />
        </div>

        {error && (
          <div style={{
            padding: "0.75rem 1rem",
            border: "1px solid rgba(255,0,85,0.4)",
            color: "#ff0055",
            fontSize: "0.7rem",
            marginBottom: "1.2rem",
            background: "rgba(255,0,85,0.05)",
          }}>
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          style={{
            width: "100%",
            padding: "0.85rem",
            background: loading ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.13)",
            border: "1px solid rgba(0,255,65,0.55)",
            color: "#00ff41",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.75rem",
            letterSpacing: "0.14em",
            cursor: loading ? "not-allowed" : "pointer",
            transition: "background 0.15s",
          }}
        >
          {loading ? "CREATING ACCOUNT..." : "CREATE ACCOUNT"}
        </button>
      </form>

      <div style={{ marginTop: "1.5rem", fontSize: "0.62rem", color: "rgba(0,255,65,0.3)", textAlign: "center" }}>
        Already have a key?{" "}
        <Link to="/verify" style={{ color: "rgba(0,255,65,0.55)", textDecoration: "none" }}>
          Go to verify
        </Link>
      </div>
    </div>
  );
}
