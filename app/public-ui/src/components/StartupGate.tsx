import { useEffect, useMemo, useState } from "react";

const PROFILE_KEY = "olympus_startup_profile_v1";
const SESSION_KEY = "olympus_startup_unlocked_v1";
const ACCOUNT_SESSION_KEY = "olympus_account_session_v1";
const PBKDF2_ITERATIONS = 160_000;
const API_BASE =
  (typeof import.meta !== "undefined" &&
    (import.meta as { env?: { VITE_API_BASE?: string } }).env?.VITE_API_BASE) ||
  (typeof window !== "undefined" ? window.location.origin : "");

type StartupProfile = {
  operator: string;
  salt: string;
  verifier: string;
  createdAt: string;
};

type GateMode = "loading" | "setup" | "unlock";

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
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBuffer,
      iterations: PBKDF2_ITERATIONS,
    },
    keyMaterial,
    256,
  );
  return bytesToBase64(new Uint8Array(bits));
}

function readProfile(): StartupProfile | null {
  try {
    const raw = localStorage.getItem(PROFILE_KEY);
    return raw ? (JSON.parse(raw) as StartupProfile) : null;
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

export default function StartupGate({ children }: { children: React.ReactNode }) {
  const [mode, setMode] = useState<GateMode>("loading");
  const [profile, setProfile] = useState<StartupProfile | null>(null);
  const [operator, setOperator] = useState("");
  const [loginEmail, setLoginEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [accountLogin, setAccountLogin] = useState(false);
  const [unlocked, setUnlocked] = useState(false);

  useEffect(() => {
    const saved = readProfile();
    const sessionUnlocked =
      sessionStorage.getItem(SESSION_KEY) === "1" ||
      sessionStorage.getItem(ACCOUNT_SESSION_KEY) === "1";
    setProfile(saved);
    setOperator(saved?.operator ?? "");
    setUnlocked(Boolean(saved && sessionUnlocked));
    setMode(saved ? "unlock" : "setup");
  }, []);

  const title = useMemo(
    () => (accountLogin ? "USER SIGN IN" : mode === "setup" ? "FIRST START" : "STARTUP LOCK"),
    [accountLogin, mode],
  );

  async function createProfile(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    const trimmedOperator = operator.trim();
    if (trimmedOperator.length < 2) {
      setError("Enter an operator name.");
      return;
    }
    if (password.length < 10) {
      setError("Startup password must be at least 10 characters.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    if (!crypto.subtle) {
      setError("This browser does not support local password verification.");
      return;
    }

    setBusy(true);
    try {
      const saltBytes = new Uint8Array(16);
      crypto.getRandomValues(saltBytes);
      const salt = bytesToBase64(saltBytes);
      const verifier = await deriveVerifier(password, salt);
      const nextProfile: StartupProfile = {
        operator: trimmedOperator,
        salt,
        verifier,
        createdAt: new Date().toISOString(),
      };
      localStorage.setItem(PROFILE_KEY, JSON.stringify(nextProfile));
      sessionStorage.setItem(SESSION_KEY, "1");
      setProfile(nextProfile);
      setUnlocked(true);
      setPassword("");
      setConfirm("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create startup profile.");
    } finally {
      setBusy(false);
    }
  }

  async function unlock(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    if (!profile) {
      setMode("setup");
      return;
    }

    setBusy(true);
    try {
      const verifier = await deriveVerifier(password, profile.salt);
      if (verifier !== profile.verifier) {
        setError("Startup password rejected.");
        return;
      }
      sessionStorage.setItem(SESSION_KEY, "1");
      setUnlocked(true);
      setPassword("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not unlock startup profile.");
    } finally {
      setBusy(false);
    }
  }

  async function unlockAccount(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (!loginEmail.trim() || !password) {
      setError("Email and password required.");
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: loginEmail.trim(), password }),
      });
      const data = await res.json() as { keys?: Array<{ scopes: string[] }>; detail?: unknown };
      if (!res.ok) {
        setError(typeof data.detail === "string" ? data.detail : "Login failed.");
        return;
      }
      const scopes = Array.from(new Set((data.keys ?? []).flatMap(key => key.scopes)));
      sessionStorage.setItem(ACCOUNT_SESSION_KEY, "1");
      sessionStorage.setItem("olympus_account_scopes_v1", JSON.stringify(scopes));
      setUnlocked(true);
      setPassword("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not log in.");
    } finally {
      setBusy(false);
    }
  }

  function resetProfile() {
    clearStartupProfile();
    setProfile(null);
    setOperator("");
    setPassword("");
    setConfirm("");
    setError(null);
    setUnlocked(false);
    setMode("setup");
  }

  if (unlocked) return <>{children}</>;

  return (
    <main className="startup-screen">
      <section className="startup-shell" aria-labelledby="startup-title">
        <div className="startup-brand">
          <span>[ø]</span>
          <strong>OLYMPUS_PROTOCØL</strong>
        </div>

        <div className="startup-grid">
          <div className="startup-copy">
            <p className="startup-kicker">LOCAL BOOT SEQUENCE</p>
            <h1 id="startup-title">{title}</h1>
            <p>
              {accountLogin
                ? "Use the app password assigned by an admin to open the verification console."
                : mode === "setup"
                  ? "Create the local operator profile for this browser before the ledger tools load."
                  : "Unlock this workstation session to continue into the Olympus console."}
            </p>
            <div className="startup-status">
              <span data-active="true">browser local</span>
              <span>api remains server protected</span>
              <span>session memory unlock</span>
            </div>
          </div>

          {accountLogin ? (
            <form className="startup-panel" onSubmit={(event) => void unlockAccount(event)}>
              <label>
                Email
                <input
                  autoFocus
                  value={loginEmail}
                  onChange={(event) => setLoginEmail(event.target.value)}
                  type="email"
                  autoComplete="username"
                  placeholder="user@example.com"
                />
              </label>
              <label>
                App password
                <input
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  type="password"
                  autoComplete="current-password"
                  placeholder="enter password"
                />
              </label>
              {error && <div className="startup-error">{error}</div>}
              <button type="submit" disabled={busy}>
                {busy ? "CHECKING..." : "SIGN IN"}
              </button>
              <button className="startup-reset" type="button" onClick={() => { setAccountLogin(false); setError(null); setPassword(""); }}>
                LOCAL STARTUP LOCK
              </button>
            </form>
          ) : mode === "setup" ? (
            <form className="startup-panel" onSubmit={(event) => void createProfile(event)}>
              <label>
                Operator
                <input
                  autoFocus
                  value={operator}
                  onChange={(event) => setOperator(event.target.value)}
                  autoComplete="username"
                  placeholder="operator name"
                />
              </label>
              <label>
                Startup password
                <input
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  type="password"
                  autoComplete="new-password"
                  placeholder="minimum 10 characters"
                />
              </label>
              <label>
                Confirm password
                <input
                  value={confirm}
                  onChange={(event) => setConfirm(event.target.value)}
                  type="password"
                  autoComplete="new-password"
                  placeholder="repeat password"
                />
              </label>
              {error && <div className="startup-error">{error}</div>}
              <button type="submit" disabled={busy}>
                {busy ? "CREATING..." : "INITIALIZE STARTUP"}
              </button>
              <button className="startup-reset" type="button" onClick={() => { setAccountLogin(true); setError(null); setPassword(""); }}>
                SIGN IN AS USER
              </button>
              <p className="startup-note">
                The password verifier is stored in this browser with PBKDF2. It does not replace
                API keys or server-side authentication.
              </p>
            </form>
          ) : (
            <form className="startup-panel" onSubmit={(event) => void unlock(event)}>
              <div className="startup-operator">
                <span>OPERATOR</span>
                <strong>{profile?.operator ?? "LOCAL USER"}</strong>
              </div>
              <label>
                Startup password
                <input
                  autoFocus
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  type="password"
                  autoComplete="current-password"
                  placeholder="enter password"
                />
              </label>
              {error && <div className="startup-error">{error}</div>}
              <button type="submit" disabled={busy}>
                {busy ? "CHECKING..." : "UNLOCK CONSOLE"}
              </button>
              <button className="startup-reset" type="button" onClick={() => { setAccountLogin(true); setError(null); setPassword(""); }}>
                SIGN IN AS USER
              </button>
              <button className="startup-reset" type="button" onClick={resetProfile}>
                RESET LOCAL STARTUP
              </button>
            </form>
          )}
        </div>
      </section>
    </main>
  );
}
