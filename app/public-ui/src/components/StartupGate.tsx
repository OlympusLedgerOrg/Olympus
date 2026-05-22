import { useEffect, useMemo, useRef, useState } from "react";
// Files in public/ are served as-is; reference by absolute path, don't import.
const loadingPng = "/loading.png";
import { getApiBase } from "../lib/api";
import { safeJsonFetch } from "../lib/safeJson";
import { setStoredApiKey } from "../lib/storage";

const PROFILE_KEY = "olympus_startup_profile_v1";
const SESSION_KEY = "olympus_startup_unlocked_v1";
const PBKDF2_ITERATIONS = 160_000;

type StartupProfile = {
  operator: string;
  email: string;
  salt: string;
  verifier: string;
  createdAt: string;
};

type GateMode = "loading" | "setup" | "login" | "unlock";

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveVerifier(password: string, salt: string): Promise<string> {
  const saltBytes = base64ToBytes(salt);
  const saltBuffer = saltBytes.buffer.slice(
    saltBytes.byteOffset,
    saltBytes.byteOffset + saltBytes.byteLength,
  ) as ArrayBuffer;
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBuffer, iterations: PBKDF2_ITERATIONS },
    keyMaterial,
    256,
  );
  return bytesToBase64(new Uint8Array(bits));
}

function readProfile(): StartupProfile | null {
  try {
    const raw = localStorage.getItem(PROFILE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as StartupProfile;
  } catch {
    return null;
  }
}

function clearStartupProfile() {
  try {
    localStorage.removeItem(PROFILE_KEY);
    sessionStorage.removeItem(SESSION_KEY);
  } catch {
    // Storage may be blocked; state will still reset in memory.
  }
}

const TICKER_PHRASES = [
  "SEEK THE EGG · TRUST THE PROOF · THE LEDGER NEVER LIES",
  "WAKE THE F*** UP, SAMURAI. WE HAVE A LEDGER TO BURN.",
  "ALL THESE PROOFS WILL BE LOST IN TIME, LIKE TEARS IN RAIN…",
  "I AM THE LAW. THE LAW IS A MERKLE PROOF.",
  "YOU TAKE THE RED PILL — YOU VERIFY THE PROOF.",
  "THREE HIDDEN KEYS · THREE SECRET GATES · ONE LEDGER",
  "↑↑↓↓←→←→ B A · GODMODE UNLOCKED",
  "ARASAKA TRIED TO REWRITE THE ROOT HASH. ARASAKA FAILED.",
  "TRUST THE MATH. NOT THE MAN.",
  "THE REVOLUTION WILL BE APPEND-ONLY.",
  "HACK THE PLANET. VERIFY THE HASH.",
  "WAKE UP, OPERATOR. THE LEDGER HAS YOU.",
  "FIRST RULE OF OLYMPUS: YOU DO NOT TRUST THE HASH WITHOUT THE PROOF.",
  "A VERDICT WITHOUT A PROOF IS JUST MARKETING.",
  "HELL_O FRIEND. HELLO CRYPTOGRAPHIC PROOF.",
  "IF IT ISN'T SIGNED, IT DIDN'T HAPPEN.",
  "THE DATABASE CAN LIE. THE PROOF BUNDLE CANNOT.",
  "I KNOW KUNG FU. I KNOW BLAKE3.",
].join("  ·  ");

function BootTicker() {
  return (
    <div style={{
      position: "fixed", top: 0, left: 0, right: 0, zIndex: 50,
      height: "28px", background: "rgba(0,0,0,0.92)",
      borderBottom: "1px solid rgba(0,255,65,0.22)",
      overflow: "hidden", display: "flex", alignItems: "center",
    }}>
      <div
        style={{
          whiteSpace: "nowrap",
          fontFamily: "var(--font-terminal, 'Share Tech Mono', monospace)",
          fontSize: "0.6rem", color: "rgba(0,255,65,0.72)", letterSpacing: "0.06em",
          // Linear 80s infinite translateX paints the entire row every
          // frame; under WSL/llvmpipe it's a measurable cursor-jitter
          // contributor. Disable when the OS asks for reduced motion —
          // the static text is still readable.
          animation: "bootTicker 80s linear infinite",
          paddingLeft: "100%",
        }}
      >
        {TICKER_PHRASES}&nbsp;&nbsp;&nbsp;&nbsp;{TICKER_PHRASES}
      </div>
      <style>{`
        @keyframes bootTicker {
          from { transform: translateX(0); }
          to   { transform: translateX(-50%); }
        }
        @media (prefers-reduced-motion: reduce) {
          @keyframes bootTicker {
            0%, 100% { transform: translateX(-12%); }
          }
        }
      `}</style>
    </div>
  );
}

const GATE_KEYS = [
  { label: "COPPER KEY",  color: "#b87333", status: "SEALED" },
  { label: "JADE KEY",    color: "#00b388", status: "SEALED" },
  { label: "CRYSTAL KEY", color: "#a0d8ef", status: "SEALED" },
] as const;

function GatesFooter() {
  return (
    <div style={{
      display: "flex", justifyContent: "center", alignItems: "center",
      gap: "2rem", padding: "1.25rem 2rem",
      borderTop: "1px solid rgba(0,255,65,0.10)", marginTop: "2rem",
    }}>
      {GATE_KEYS.map((k) => (
        <div key={k.label} style={{ textAlign: "center" }}>
          <svg width="28" height="38" viewBox="0 0 28 38" style={{ display: "block", margin: "0 auto 0.35rem" }}>
            <rect x="8" y="0" width="12" height="12" rx="6" fill="none" stroke={k.color} strokeWidth="2.5" opacity="0.7" />
            <rect x="11" y="10" width="6" height="22" rx="1.5" fill={k.color} opacity="0.55" />
            <rect x="11" y="21" width="8" height="3" rx="1" fill={k.color} opacity="0.7" />
            <rect x="11" y="27" width="5" height="3" rx="1" fill={k.color} opacity="0.7" />
          </svg>
          <div style={{ fontSize: "0.44rem", letterSpacing: "0.12em", color: k.color, opacity: 0.7 }}>{k.label}</div>
          <div style={{ fontSize: "0.4rem", letterSpacing: "0.1em", color: "rgba(255,0,85,0.6)", marginTop: "0.2rem" }}>{k.status}</div>
        </div>
      ))}
    </div>
  );
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      style={{
        flexShrink: 0, background: copied ? "rgba(0,255,65,0.25)" : "rgba(0,255,65,0.08)",
        border: "1px solid rgba(0,255,65,0.5)", color: "#00ff41",
        fontFamily: "'DM Mono', monospace", fontSize: "0.6rem", letterSpacing: "0.1em",
        padding: "0.45rem 0.85rem", cursor: "pointer",
      }}
    >
      {copied ? "COPIED" : "COPY"}
    </button>
  );
}

const inp: React.CSSProperties = {
  width: "100%", background: "rgba(0,0,0,0.7)",
  border: "1px solid rgba(0,255,65,0.25)", color: "#00ff41",
  fontFamily: "'DM Mono', monospace", fontSize: "0.82rem",
  padding: "0.65rem 0.85rem", outline: "none", boxSizing: "border-box",
};

const lbl: React.CSSProperties = {
  display: "block", fontSize: "0.56rem", letterSpacing: "0.1em",
  color: "rgba(0,255,65,0.5)", marginBottom: "0.35rem",
};

export default function StartupGate({ children }: { children: React.ReactNode }) {
  const [mode, setMode] = useState<GateMode>("loading");
  const [profile, setProfile] = useState<StartupProfile | null>(null);

  // setup fields
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [newApiKey, setNewApiKey] = useState("");

  // unlock fields
  const [unlockPassword, setUnlockPassword] = useState("");

  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [unlocked, setUnlocked] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [mayhemMode, setMayhemMode] = useState(false);
  const bootWordBuf = useRef("");

  useEffect(() => {
    if (unlocked) return;
    const handler = (e: KeyboardEvent) => {
      const ch = e.key.length === 1 ? e.key.toUpperCase() : "";
      if (ch) {
        bootWordBuf.current = (bootWordBuf.current + ch).slice(-8);
        if (bootWordBuf.current.includes("MAYHEM")) {
          setMayhemMode(true);
          bootWordBuf.current = "";
          setTimeout(() => setMayhemMode(false), 6000);
        }
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [unlocked]);

  useEffect(() => {
    const saved = readProfile();
    const sessionUnlocked = sessionStorage.getItem(SESSION_KEY) === "1";
    setProfile(saved);
    setUnlocked(Boolean(saved && sessionUnlocked));
    setMode(saved ? "unlock" : "setup");
  }, []);

  const title = useMemo(() => {
    if (mode === "setup") return "FIRST BOOT";
    if (mode === "login") return "SIGN IN";
    return "STARTUP LOCK";
  }, [mode]);

  async function createProfile(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    const trimmedEmail = email.trim();
    const name = displayName.trim() || trimmedEmail.split("@")[0] || "operator";

    // Basic validation — including a rough TLD check to catch typos like gmail.ocm
    if (!trimmedEmail || !trimmedEmail.includes("@")) { setError("Enter a valid email."); return; }
    const tld = trimmedEmail.split(".").at(-1) ?? "";
    if (tld.length < 2 || tld.length > 10) { setError("Email TLD looks wrong — double-check the address."); return; }
    if (name.length < 2) { setError("Enter a display name."); return; }
    if (password.length < 12) { setError("Password must be at least 12 characters."); return; }
    if (password !== confirm) { setError("Passwords do not match."); return; }
    if (!crypto.subtle) { setError("Browser does not support local password verification."); return; }

    setBusy(true);
    try {
      // ── Step 1: Persist the local PBKDF2 profile immediately ────────────────
      // This happens BEFORE any network call so the password is always saved.
      // On the next reload the unlock gate will accept it even if the API
      // is unreachable (air-gap / embedded server not yet running).
      const saltBytes = new Uint8Array(16);
      crypto.getRandomValues(saltBytes);
      const salt = bytesToBase64(saltBytes);
      const verifier = await deriveVerifier(password, salt);
      const nextProfile: StartupProfile = {
        operator: name,
        email: trimmedEmail,
        salt,
        verifier,
        createdAt: new Date().toISOString(),
      };
      localStorage.setItem(PROFILE_KEY, JSON.stringify(nextProfile));
      setProfile(nextProfile);

      // ── Step 2: Attempt server registration (best-effort) ───────────────────
      // Failure here does NOT prevent local unlock. We fall into air-gap mode:
      // the profile is already saved above, so the next visit shows the unlock
      // form (PBKDF2 verify only, no network needed).
      const scopeCandidates = [
        ["read", "verify", "ingest", "commit", "write", "admin"],
        ["read", "verify", "ingest", "commit", "write"],
        ["read", "verify"],
      ];
      let apiKey = "";
      let grantedScopes: string[] = [];
      const base = await getApiBase();

      for (const scopes of scopeCandidates) {
        const { ok, status, data } = await safeJsonFetch<{
          api_key?: string;
          scopes?: string[];
          user_id?: string;
          detail?: string;
        }>(`${base}/auth/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: trimmedEmail, password, name, scopes }),
        });

        if (status === 409 || data?.detail?.toLowerCase().includes("already registered")) {
          // Profile is saved; redirect to login so they can get their API key.
          setMode("login");
          setError("This email is already registered. Sign in to retrieve your API key.");
          return;
        }
        if (status === 429) {
          // Profile saved — they can unlock next visit without an API key.
          setError("Rate limit hit. Your local profile was saved — reload to unlock without an API key, or wait 60 s and try again.");
          setShowKey(false);
          return;
        }
        if (status === 403) continue; // Try next scope set.

        if (ok && data?.api_key) {
          apiKey = data.api_key;
          grantedScopes = data.scopes ?? scopes;
          break;
        }

        // Non-retryable server error or HTML response (asset server).
        // Break and fall through to air-gap mode.
        if (status !== 0) break;
      }

      if (apiKey) {
        setStoredApiKey(apiKey);
        setNewApiKey(apiKey);
        if (grantedScopes.includes("admin")) {
          localStorage.setItem("olympus_admin_key", apiKey);
        }
        setShowKey(true);
      } else {
        // Server unreachable or registration failed — enter the console anyway.
        // The local PBKDF2 profile is already saved; the KEYS tab can issue an
        // API key once the server is reachable.
        enterConsole();
      }
    } catch {
      enterConsole();
    } finally {
      setBusy(false);
    }
  }

  function enterConsole() {
    sessionStorage.setItem(SESSION_KEY, "1");
    setUnlocked(true);
    setShowKey(false);
    setPassword("");
    setConfirm("");
    setNewApiKey("");
  }

  async function signIn(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (!email.trim() || !email.includes("@")) { setError("Enter a valid email."); return; }
    if (!password) { setError("Enter your password."); return; }
    if (!crypto.subtle) { setError("Browser does not support local password verification."); return; }

    setBusy(true);
    try {
      const base = await getApiBase();
      const { ok, status, data } = await safeJsonFetch<{
        user_id?: string;
        email?: string;
        detail?: string;
        keys?: Array<{ id: string; scopes: string[] }>;
      }>(`${base}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password }),
      });

      if (!ok) {
        const msg = data?.detail ?? `Sign in failed (HTTP ${status.toString()}).`;
        setError(msg);
        return;
      }

      // Build local PBKDF2 profile so future visits use the fast unlock flow
      const name = (data?.email ?? email.trim()).split("@")[0] || "operator";
      const saltBytes = new Uint8Array(16);
      crypto.getRandomValues(saltBytes);
      const salt = bytesToBase64(saltBytes);
      const verifier = await deriveVerifier(password, salt);
      const nextProfile: StartupProfile = {
        operator: name,
        email: email.trim(),
        salt,
        verifier,
        createdAt: new Date().toISOString(),
      };
      localStorage.setItem(PROFILE_KEY, JSON.stringify(nextProfile));
      setProfile(nextProfile);

      // Issue a fresh API key — recovery path for lost/expired keys
      try {
        const { ok: keyOk, data: keyData } = await safeJsonFetch<{
          api_key: string; key_id: string; scopes: string[]; expires_at: string;
        }>(`${base}/auth/reissue-key`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: email.trim(), password, scopes: ["read","verify","ingest","commit","write"] }),
        });
        if (keyOk && keyData?.api_key) {
          setStoredApiKey(keyData.api_key);
          setNewApiKey(keyData.api_key);
          setShowKey(true);
          return;
        }
      } catch {
        enterConsole();
        return;
      }
      enterConsole();
    } catch {
      enterConsole();
    } finally {
      setBusy(false);
    }
  }

  async function unlock(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (!profile) { setMode("setup"); return; }
    setBusy(true);
    try {
      const verifier = await deriveVerifier(unlockPassword, profile.salt);
      if (verifier !== profile.verifier) { setError("Startup password rejected."); return; }
      sessionStorage.setItem(SESSION_KEY, "1");
      setUnlocked(true);
      setUnlockPassword("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not unlock.");
    } finally {
      setBusy(false);
    }
  }

  function resetProfile() {
    clearStartupProfile();
    localStorage.removeItem("olympus_api_key");
    localStorage.removeItem("olympus_admin_key");
    setProfile(null);
    setEmail(""); setDisplayName(""); setPassword(""); setConfirm(""); setNewApiKey("");
    setError(null); setUnlocked(false); setShowKey(false); setMode("setup");
  }

  if (unlocked) return <>{children}</>;

  return (
    <main className="startup-screen">
      <BootTicker />
      <section className="startup-shell" aria-labelledby="startup-title">
        <div className="startup-brand">
          <span>[ø]</span>
          <strong>OLYMPUS_PROTOCØL</strong>
        </div>

        <div className="startup-grid">
          <div className="startup-copy">
            <div className="startup-splash-card" aria-hidden="true">
              <img src={loadingPng} alt="" loading="eager" />
              <div className="startup-splash-label">BOOT_ART // GODMODE_BUILD</div>
            </div>
            <p className="startup-kicker">LOCAL BOOT SEQUENCE</p>
            <h1 id="startup-title" style={{ fontFamily: "var(--font-logo)" }}>{title}</h1>
            {mayhemMode ? (
              <p style={{ fontFamily: "var(--font-boot)", fontSize: "1rem", color: "#ff0055", lineHeight: 1.5 }}>
                YOU ARE NOT YOUR API KEY.<br />
                YOU ARE NOT YOUR OPERATOR NAME.<br />
                YOU ARE THE SAME DECAYING ORGANIC MATTER<br />
                AS EVERYONE ELSE — BUT YOUR HASHES ARE FOREVER.<br />
                <span style={{ color: "rgba(255,0,85,0.5)", fontSize: "0.7rem" }}>— Tyler Durden // PROJECT MAYHEM</span>
              </p>
            ) : (
              <p>
                {mode === "setup"
                  ? "Create your operator account. Your API key is generated server-side and stored locally — copy it before leaving."
                  : mode === "login"
                    ? "Sign in with your existing account to unlock the console."
                    : `Welcome back, ${profile?.operator ?? "OPERATOR"}. Enter your password to unlock this session.`}
              </p>
            )}
            <div className="startup-status">
              <span data-active="true">browser local</span>
              <span>api server protected</span>
              <span>session memory unlock</span>
              <span title="↑↑↓↓←→←→ B A" style={{ cursor: "default", opacity: 0.3 }}>⬆⬆⬇⬇◂▸◂▸</span>
            </div>
            <div className="boot-progress" aria-hidden="true">
              <span />
            </div>
          </div>

          {/* ── Show API key after successful first boot ── */}
          {showKey ? (
            <div className="startup-panel">
              <div style={{ fontSize: "0.56rem", letterSpacing: "0.12em", color: "rgba(0,255,65,0.5)", marginBottom: "1rem" }}>
                ACCOUNT CREATED // COPY YOUR API KEY NOW
              </div>
              <div style={{ marginBottom: "0.4rem" }}>
                <div style={lbl}>EMAIL</div>
                <div style={{ fontSize: "0.78rem", color: "#00ff41", marginBottom: "0.75rem" }}>{email}</div>
              </div>
              <div style={{ marginBottom: "0.4rem" }}>
                <div style={lbl}>OPERATOR</div>
                <div style={{ fontSize: "0.78rem", color: "#00ff41", marginBottom: "0.75rem" }}>{profile?.operator}</div>
              </div>
              <div className="startup-key-box" style={{ marginBottom: "1.25rem" }}>
                <div style={lbl}>API KEY — SHOWN ONCE</div>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "stretch" }}>
                  <code>
                    {newApiKey}
                  </code>
                  <CopyButton value={newApiKey} />
                </div>
              </div>
              <div style={{
                padding: "0.6rem 0.85rem", background: "rgba(255,200,0,0.05)",
                border: "1px solid rgba(255,200,0,0.2)", fontSize: "0.6rem",
                color: "rgba(255,200,0,0.8)", lineHeight: 1.6, marginBottom: "1.25rem",
              }}>
                This key is stored in your browser and pre-filled in the LEDGER tab.
                Also save a copy somewhere safe — it will not be shown again.
              </div>
              <button type="button" onClick={enterConsole} style={{
                width: "100%", padding: "0.8rem",
                background: "rgba(0,255,65,0.14)", border: "1px solid rgba(0,255,65,0.6)",
                color: "#00ff41", fontFamily: "'DM Mono', monospace",
                fontSize: "0.72rem", letterSpacing: "0.14em", cursor: "pointer",
              }}>
                ENTER CONSOLE →
              </button>
            </div>

          /* ── Setup form ── */
          ) : mode === "setup" ? (
            <form className="startup-panel" onSubmit={(event) => void createProfile(event)}>
              <div style={{ marginBottom: "1rem" }}>
                <label style={lbl}>EMAIL</label>
                <input autoFocus type="email" value={email} onChange={e => setEmail(e.target.value)}
                  autoComplete="email" placeholder="you@example.com" style={inp} />
              </div>
              <div style={{ marginBottom: "1rem" }}>
                <label style={lbl}>DISPLAY NAME</label>
                <input type="text" value={displayName} onChange={e => setDisplayName(e.target.value)}
                  autoComplete="username" placeholder="operator handle" style={inp} />
              </div>
              <div style={{ marginBottom: "1rem" }}>
                <label style={lbl}>PASSWORD</label>
                <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                  autoComplete="new-password" placeholder="at least 12 characters" style={inp} />
              </div>
              <div style={{ marginBottom: "1.25rem" }}>
                <label style={lbl}>CONFIRM PASSWORD</label>
                <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)}
                  autoComplete="new-password" placeholder="repeat password" style={inp} />
              </div>
              {error && <div className="startup-error">{error}</div>}
              <button type="submit" disabled={busy} style={{
                width: "100%", padding: "0.8rem",
                background: busy ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.14)",
                border: "1px solid rgba(0,255,65,0.6)", color: "#00ff41",
                fontFamily: "'DM Mono', monospace", fontSize: "0.72rem",
                letterSpacing: "0.14em", cursor: busy ? "not-allowed" : "pointer",
              }}>
                {busy ? "INITIALIZING..." : "INITIALIZE OPERATOR"}
              </button>
              <button type="button" onClick={() => { setMode("login"); setError(null); }}
                style={{ marginTop: "0.75rem", width: "100%", background: "none",
                  border: "none", color: "rgba(0,255,65,0.4)", fontSize: "0.58rem",
                  letterSpacing: "0.08em", cursor: "pointer", fontFamily: "'DM Mono', monospace" }}>
                ALREADY HAVE AN ACCOUNT? SIGN IN
              </button>
            </form>

          /* ── Login form ── */
          ) : mode === "login" ? (
            <form className="startup-panel" onSubmit={(event) => void signIn(event)}>
              <div style={{ marginBottom: "1rem" }}>
                <label style={lbl}>EMAIL</label>
                <input autoFocus type="email" value={email} onChange={e => setEmail(e.target.value)}
                  autoComplete="email" placeholder="you@example.com" style={inp} />
              </div>
              <div style={{ marginBottom: "1.25rem" }}>
                <label style={lbl}>PASSWORD</label>
                <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                  autoComplete="current-password" placeholder="your password" style={inp} />
              </div>
              {error && <div className="startup-error">{error}</div>}
              <button type="submit" disabled={busy} style={{
                width: "100%", padding: "0.8rem",
                background: busy ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.14)",
                border: "1px solid rgba(0,255,65,0.6)", color: "#00ff41",
                fontFamily: "'DM Mono', monospace", fontSize: "0.72rem",
                letterSpacing: "0.14em", cursor: busy ? "not-allowed" : "pointer",
              }}>
                {busy ? "SIGNING IN..." : "SIGN IN"}
              </button>
              <div style={{ marginTop: "0.75rem", display: "flex", gap: "0.75rem", justifyContent: "center" }}>
                <button type="button" onClick={() => { setMode("setup"); setError(null); }}
                  style={{ background: "none", border: "none", color: "rgba(0,255,65,0.4)", fontSize: "0.58rem",
                    letterSpacing: "0.08em", cursor: "pointer", fontFamily: "'DM Mono', monospace" }}>
                  CREATE NEW ACCOUNT
                </button>
                <span style={{ color: "rgba(0,255,65,0.2)", fontSize: "0.58rem" }}>·</span>
                <button type="button" onClick={resetProfile}
                  style={{ background: "none", border: "none", color: "rgba(0,255,65,0.25)", fontSize: "0.58rem",
                    letterSpacing: "0.08em", cursor: "pointer", fontFamily: "'DM Mono', monospace" }}>
                  RESET LOCAL DATA
                </button>
              </div>
            </form>

          /* ── Unlock form ── */
          ) : (
            <form className="startup-panel" onSubmit={(event) => void unlock(event)}>
              <div className="startup-operator">
                <span>OPERATOR</span>
                <strong>{profile?.operator ?? "LOCAL USER"}</strong>
              </div>
              {profile?.email && (
                <div style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.4)", marginBottom: "1rem" }}>
                  {profile.email}
                </div>
              )}
              <div style={{ marginBottom: "1.25rem" }}>
                <label style={lbl}>STARTUP PASSWORD</label>
                <input autoFocus type="password" value={unlockPassword}
                  onChange={e => setUnlockPassword(e.target.value)}
                  autoComplete="current-password" placeholder="enter password" style={inp} />
              </div>
              {error && <div className="startup-error">{error}</div>}
              <button type="submit" disabled={busy} style={{
                width: "100%", padding: "0.8rem",
                background: busy ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.14)",
                border: "1px solid rgba(0,255,65,0.6)", color: "#00ff41",
                fontFamily: "'DM Mono', monospace", fontSize: "0.72rem",
                letterSpacing: "0.14em", cursor: busy ? "not-allowed" : "pointer",
              }}>
                {busy ? "CHECKING..." : "UNLOCK CONSOLE"}
              </button>
              <div style={{ marginTop: "0.75rem", display: "flex", gap: "0.75rem", justifyContent: "center" }}>
                <button type="button" onClick={() => { setMode("login"); setEmail(profile?.email ?? ""); setPassword(""); setError(null); }}
                  style={{ background: "none", border: "none", color: "rgba(0,255,65,0.4)", fontSize: "0.58rem",
                    letterSpacing: "0.08em", cursor: "pointer", fontFamily: "'DM Mono', monospace" }}>
                  SIGN IN AGAIN
                </button>
                <span style={{ color: "rgba(0,255,65,0.2)", fontSize: "0.58rem" }}>·</span>
                <button type="button" onClick={resetProfile}
                  style={{ background: "none", border: "none", color: "rgba(0,255,65,0.25)", fontSize: "0.58rem",
                    letterSpacing: "0.08em", cursor: "pointer", fontFamily: "'DM Mono', monospace" }}>
                  RESET / NEW ACCOUNT
                </button>
              </div>
            </form>
          )}
        </div>
        <GatesFooter />
      </section>
    </main>
  );
}
