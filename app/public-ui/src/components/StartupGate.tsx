import LoadingSplash from "./LoadingSplash";
import { BootTicker } from "./startup/BootTicker";
import { GatesFooter } from "./startup/GatesFooter";
import { CopyButton } from "./startup/CopyButton";
import { useStartupGate } from "../hooks/useStartupGate";

const inp: React.CSSProperties = {
  width: "100%",
  background: "rgba(0,0,0,0.7)",
  border: "1px solid rgba(0,255,65,0.25)",
  color: "#00ff41",
  fontFamily: "var(--font-terminal)",
  fontSize: "0.82rem",
  padding: "0.65rem 0.85rem",
  outline: "none",
  boxSizing: "border-box",
};

const lbl: React.CSSProperties = {
  display: "block",
  fontSize: "0.56rem",
  letterSpacing: "0.1em",
  color: "rgba(0,255,65,0.5)",
  marginBottom: "0.35rem",
};

export default function StartupGate({ children }: { children: React.ReactNode }) {
  const {
    mode,
    profile,
    email,
    setEmail,
    displayName,
    setDisplayName,
    password,
    setPassword,
    confirm,
    setConfirm,
    newApiKey,
    unlockPassword,
    setUnlockPassword,
    error,
    busy,
    unlocked,
    showKey,
    mayhemMode,
    title,
    createProfile,
    signIn,
    unlock,
    resetProfile,
    enterConsole,
    setMode,
    setError,
  } = useStartupGate();

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
              <LoadingSplash />
              <div className="startup-splash-label">BOOT_ART // GODMODE_BUILD</div>
            </div>
            <p className="startup-kicker">LOCAL BOOT SEQUENCE</p>
            <h1 id="startup-title" style={{ fontFamily: "var(--font-logo)" }}>
              {title}
            </h1>
            {mayhemMode ? (
              <p
                style={{
                  fontFamily: "var(--font-boot)",
                  fontSize: "1rem",
                  color: "#ff0055",
                  lineHeight: 1.5,
                }}
              >
                YOU ARE NOT YOUR API KEY.
                <br />
                YOU ARE NOT YOUR OPERATOR NAME.
                <br />
                YOU ARE THE SAME DECAYING ORGANIC MATTER
                <br />
                AS EVERYONE ELSE — BUT YOUR HASHES ARE FOREVER.
                <br />
                <span style={{ color: "rgba(255,0,85,0.5)", fontSize: "0.7rem" }}>
                  — Tyler Durden // PROJECT MAYHEM
                </span>
              </p>
            ) : (
              <p>
                {mode === "setup"
                  ? "Create your operator account. Your API key is generated server-side and held in memory for this session only — copy it before leaving."
                  : mode === "login"
                    ? "Sign in with your existing account to unlock the console."
                    : `Welcome back, ${profile?.operator ?? "OPERATOR"}. Enter your password to unlock this session.`}
              </p>
            )}
            <div className="startup-status">
              <span data-active="true">browser local</span>
              <span>api server protected</span>
              <span>session memory unlock</span>
              <span title="↑↑↓↓←→←→ B A" style={{ cursor: "default", opacity: 0.3 }}>
                ⬆⬆⬇⬇◂▸◂▸
              </span>
            </div>
            <div className="boot-progress" aria-hidden="true">
              <span />
            </div>
          </div>

          {/* ── Show API key after successful first boot ── */}
          {showKey ? (
            <div className="startup-panel">
              <div
                style={{
                  fontSize: "0.56rem",
                  letterSpacing: "0.12em",
                  color: "rgba(0,255,65,0.5)",
                  marginBottom: "1rem",
                }}
              >
                ACCOUNT CREATED // COPY YOUR API KEY NOW
              </div>
              <div style={{ marginBottom: "0.4rem" }}>
                <div style={lbl}>EMAIL</div>
                <div style={{ fontSize: "0.78rem", color: "#00ff41", marginBottom: "0.75rem" }}>
                  {email}
                </div>
              </div>
              <div style={{ marginBottom: "0.4rem" }}>
                <div style={lbl}>OPERATOR</div>
                <div style={{ fontSize: "0.78rem", color: "#00ff41", marginBottom: "0.75rem" }}>
                  {profile?.operator}
                </div>
              </div>
              <div className="startup-key-box" style={{ marginBottom: "1.25rem" }}>
                <div style={lbl}>API KEY — SHOWN ONCE</div>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "stretch" }}>
                  <code>{newApiKey}</code>
                  <CopyButton value={newApiKey} />
                </div>
              </div>
              <div
                style={{
                  padding: "0.6rem 0.85rem",
                  background: "rgba(255,200,0,0.05)",
                  border: "1px solid rgba(255,200,0,0.2)",
                  fontSize: "0.6rem",
                  color: "rgba(255,200,0,0.8)",
                  lineHeight: 1.6,
                  marginBottom: "1.25rem",
                }}
              >
                This key is held in memory for this session and pre-filled in the HASH_LOOKUP tab.
                It is not written to disk or browser storage, so reloading or restarting the app
                clears it. Save a copy somewhere safe — it will not be shown again.
              </div>
              <button
                type="button"
                onClick={enterConsole}
                style={{
                  width: "100%",
                  padding: "0.8rem",
                  background: "rgba(0,255,65,0.14)",
                  border: "1px solid rgba(0,255,65,0.6)",
                  color: "#00ff41",
                  fontFamily: "var(--font-terminal)",
                  fontSize: "0.72rem",
                  letterSpacing: "0.14em",
                  cursor: "pointer",
                }}
              >
                ENTER CONSOLE →
              </button>
            </div>
          ) : /* ── Setup form ── */
          mode === "setup" ? (
            <form className="startup-panel" onSubmit={(event) => void createProfile(event)}>
              <div style={{ marginBottom: "1rem" }}>
                <label style={lbl}>EMAIL</label>
                <input
                  autoFocus
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                  placeholder="you@example.com"
                  style={inp}
                />
              </div>
              <div style={{ marginBottom: "1rem" }}>
                <label style={lbl}>DISPLAY NAME</label>
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  autoComplete="username"
                  placeholder="operator handle"
                  style={inp}
                />
              </div>
              <div style={{ marginBottom: "1rem" }}>
                <label style={lbl}>PASSWORD</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                  placeholder="at least 12 characters"
                  style={inp}
                />
              </div>
              <div style={{ marginBottom: "1.25rem" }}>
                <label style={lbl}>CONFIRM PASSWORD</label>
                <input
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  autoComplete="new-password"
                  placeholder="repeat password"
                  style={inp}
                />
              </div>
              {error && <div className="startup-error">{error}</div>}
              <button
                type="submit"
                disabled={busy}
                style={{
                  width: "100%",
                  padding: "0.8rem",
                  background: busy ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.14)",
                  border: "1px solid rgba(0,255,65,0.6)",
                  color: "#00ff41",
                  fontFamily: "var(--font-terminal)",
                  fontSize: "0.72rem",
                  letterSpacing: "0.14em",
                  cursor: busy ? "not-allowed" : "pointer",
                }}
              >
                {busy ? "INITIALIZING..." : "INITIALIZE OPERATOR"}
              </button>
              <button
                type="button"
                onClick={() => {
                  setMode("login");
                  setError(null);
                }}
                style={{
                  marginTop: "0.75rem",
                  width: "100%",
                  background: "none",
                  border: "none",
                  color: "rgba(0,255,65,0.4)",
                  fontSize: "0.58rem",
                  letterSpacing: "0.08em",
                  cursor: "pointer",
                  fontFamily: "var(--font-terminal)",
                }}
              >
                ALREADY HAVE AN ACCOUNT? SIGN IN
              </button>
            </form>
          ) : /* ── Login form ── */
          mode === "login" ? (
            <form className="startup-panel" onSubmit={(event) => void signIn(event)}>
              <div style={{ marginBottom: "1rem" }}>
                <label style={lbl}>EMAIL</label>
                <input
                  autoFocus
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                  placeholder="you@example.com"
                  style={inp}
                />
              </div>
              <div style={{ marginBottom: "1.25rem" }}>
                <label style={lbl}>PASSWORD</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  placeholder="your password"
                  style={inp}
                />
              </div>
              {error && <div className="startup-error">{error}</div>}
              <button
                type="submit"
                disabled={busy}
                style={{
                  width: "100%",
                  padding: "0.8rem",
                  background: busy ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.14)",
                  border: "1px solid rgba(0,255,65,0.6)",
                  color: "#00ff41",
                  fontFamily: "var(--font-terminal)",
                  fontSize: "0.72rem",
                  letterSpacing: "0.14em",
                  cursor: busy ? "not-allowed" : "pointer",
                }}
              >
                {busy ? "SIGNING IN..." : "SIGN IN"}
              </button>
              <div
                style={{
                  marginTop: "0.75rem",
                  display: "flex",
                  gap: "0.75rem",
                  justifyContent: "center",
                }}
              >
                <button
                  type="button"
                  onClick={() => {
                    setMode("setup");
                    setError(null);
                  }}
                  style={{
                    background: "none",
                    border: "none",
                    color: "rgba(0,255,65,0.4)",
                    fontSize: "0.58rem",
                    letterSpacing: "0.08em",
                    cursor: "pointer",
                    fontFamily: "var(--font-terminal)",
                  }}
                >
                  CREATE NEW ACCOUNT
                </button>
                <span style={{ color: "rgba(0,255,65,0.2)", fontSize: "0.58rem" }}>·</span>
                <button
                  type="button"
                  onClick={resetProfile}
                  style={{
                    background: "none",
                    border: "none",
                    color: "rgba(0,255,65,0.25)",
                    fontSize: "0.58rem",
                    letterSpacing: "0.08em",
                    cursor: "pointer",
                    fontFamily: "var(--font-terminal)",
                  }}
                >
                  RESET LOCAL DATA
                </button>
              </div>
            </form>
          ) : (
            /* ── Unlock form ── */
            <form className="startup-panel" onSubmit={(event) => void unlock(event)}>
              <div className="startup-operator">
                <span>OPERATOR</span>
                <strong>{profile?.operator ?? "LOCAL USER"}</strong>
              </div>
              {profile?.email && (
                <div
                  style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.4)", marginBottom: "1rem" }}
                >
                  {profile.email}
                </div>
              )}
              <div style={{ marginBottom: "1.25rem" }}>
                <label style={lbl}>STARTUP PASSWORD</label>
                <input
                  autoFocus
                  type="password"
                  value={unlockPassword}
                  onChange={(e) => setUnlockPassword(e.target.value)}
                  autoComplete="current-password"
                  placeholder="enter password"
                  style={inp}
                />
              </div>
              {error && <div className="startup-error">{error}</div>}
              <button
                type="submit"
                disabled={busy}
                style={{
                  width: "100%",
                  padding: "0.8rem",
                  background: busy ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.14)",
                  border: "1px solid rgba(0,255,65,0.6)",
                  color: "#00ff41",
                  fontFamily: "var(--font-terminal)",
                  fontSize: "0.72rem",
                  letterSpacing: "0.14em",
                  cursor: busy ? "not-allowed" : "pointer",
                }}
              >
                {busy ? "CHECKING..." : "UNLOCK CONSOLE"}
              </button>
              <div
                style={{
                  marginTop: "0.75rem",
                  display: "flex",
                  gap: "0.75rem",
                  justifyContent: "center",
                }}
              >
                <button
                  type="button"
                  onClick={() => {
                    setMode("login");
                    setEmail(profile?.email ?? "");
                    setPassword("");
                    setError(null);
                  }}
                  style={{
                    background: "none",
                    border: "none",
                    color: "rgba(0,255,65,0.4)",
                    fontSize: "0.58rem",
                    letterSpacing: "0.08em",
                    cursor: "pointer",
                    fontFamily: "var(--font-terminal)",
                  }}
                >
                  SIGN IN AGAIN
                </button>
                <span style={{ color: "rgba(0,255,65,0.2)", fontSize: "0.58rem" }}>·</span>
                <button
                  type="button"
                  onClick={resetProfile}
                  style={{
                    background: "none",
                    border: "none",
                    color: "rgba(0,255,65,0.25)",
                    fontSize: "0.58rem",
                    letterSpacing: "0.08em",
                    cursor: "pointer",
                    fontFamily: "var(--font-terminal)",
                  }}
                >
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
