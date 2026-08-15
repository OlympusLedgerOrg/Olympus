/// One-shot modal that surfaces the bootstrap-generated admin API key and
/// BJJ authority private key on first launch.  Calls the Tauri command
/// `take_initial_secrets` exactly once at mount; if it returns a non-null
/// payload the modal renders.  On dismiss the modal saves the operator's
/// acknowledgement to localStorage so it never reappears, even if the
/// backend command (incorrectly) returns the same secrets twice.
///
/// Backend wiring: see src-tauri/src/main.rs (take_initial_secrets +
/// InitialSecretsState) and src-tauri/src/bootstrap.rs (FreshlyGenerated).
import { useEffect, useState } from "react";
import { setStoredAdminKey, setStoredApiKey } from "../lib/storage";
import { tauriInvoke } from "../lib/api";

type InitialSecrets = {
  system_api_key: string | null;
  bjj_authority_key_hex: string | null;
};

const SEEN_KEY = "olympus_initial_secrets_seen";

const InitialSecretsModal: React.FC = () => {
  const [secrets, setSecrets] = useState<InitialSecrets | null>(null);
  const [apiCopied, setApiCopied] = useState(false);
  const [bjjCopied, setBjjCopied] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  // Operators using password managers that bypass navigator.clipboard
  // (or who copy via select-and-Ctrl+C) won't trip the apiCopied/
  // bjjCopied flags. The manual-ack checkbox lets them confirm
  // explicitly so the dismiss button unblocks.
  const [manualAck, setManualAck] = useState(false);

  useEffect(() => {
    // Skip if the operator already acknowledged on a prior launch — the
    // backend command is one-shot, but during dev we'd remount this
    // component repeatedly and a sticky modal would be irritating.
    if (localStorage.getItem(SEEN_KEY)) return;

    let cancelled = false;
    (async () => {
      try {
        // Tauri 2 IPC via the supported __TAURI_INTERNALS__ path (tauriInvoke
        // returns null in a plain browser, e.g. the Vite dev server).
        const result = await tauriInvoke<InitialSecrets | null>("take_initial_secrets");
        if (cancelled) return;
        if (result && (result.system_api_key || result.bjj_authority_key_hex)) {
          setSecrets(result);
          // Pre-fill the two in-memory slots that AdminPage / IngestPage
          // read from. These are module-scoped variables in storage.ts,
          // NOT localStorage — see the SECURITY MODEL comment there. The
          // operator can change or clear the value any time, and it does
          // not survive a reload, which is what the note in the modal body
          // tells them.
          //
          // The system bootstrap key plays double duty: it's the operator-
          // tier admin secret (x-admin-key) AND a regular admin-scope API
          // key. Populate both slots so the IngestPage's API-key field
          // auto-fills too, otherwise the operator has to paste it by hand
          // into a surface the modal says is already wired up.
          if (result.system_api_key) {
            setStoredAdminKey(result.system_api_key);
            setStoredApiKey(result.system_api_key);
          }
        }
      } catch (e) {
        // Never blow up the boot path on a UI surfacing failure.
        console.warn("take_initial_secrets failed:", e);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (!secrets) return null;

  const dismiss = () => {
    localStorage.setItem(SEEN_KEY, new Date().toISOString());
    setAcknowledged(true);
    // Give the click feedback a beat, then unmount.
    setTimeout(() => setSecrets(null), 200);
  };

  const copy = (value: string, kind: "api" | "bjj") => {
    navigator.clipboard.writeText(value).catch(() => {});
    if (kind === "api") {
      setApiCopied(true);
      setTimeout(() => setApiCopied(false), 1800);
    } else {
      setBjjCopied(true);
      setTimeout(() => setBjjCopied(false), 1800);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.92)",
        zIndex: 100,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "2rem",
      }}
    >
      <div
        style={{
          maxWidth: 720,
          width: "100%",
          maxHeight: "90vh",
          overflowY: "auto",
          background: "#000",
          border: "2px solid rgba(0,255,65,0.55)",
          padding: "1.8rem 2rem",
          fontFamily: "var(--font-terminal)",
          color: "#00ff41",
        }}
      >
        <h2
          style={{
            fontFamily: "'Share Tech Mono', monospace",
            fontSize: "1.1rem",
            letterSpacing: "0.16em",
            color: "#ccffcc",
            margin: 0,
            marginBottom: "0.4rem",
          }}
        >
          FIRST LAUNCH — SAVE THESE NOW
        </h2>
        <p
          style={{
            fontSize: "0.7rem",
            color: "rgba(255,200,120,0.85)",
            lineHeight: 1.5,
            marginTop: 0,
          }}
        >
          {/*
            Deliberately makes no claim about whether the BJJ authority key is
            persisted. That is build-mode dependent and stating it either way
            is a hazard: in production `bjj_private_dev` is left NULL and
            bootstrap.rs refuses the keychain write, so the operator's env var
            is the only copy — but a dev build persists the key to BOTH the DB
            column and the OS keychain (load precedence env → keychain → DB).
            Claiming "never persisted" is false on a dev machine; claiming it
            is recoverable would tell a production operator they can skip
            saving a key they cannot get back. The instruction below is the
            one thing true in both modes, so say only that.
          */}
          These secrets are shown once. The API key is stored server-side only as a BLAKE3 hash, so
          it cannot be read back from the database. <strong>Copy both now</strong> and keep them
          somewhere safe — treat this dialog as the only copy you will get.
        </p>

        {secrets.system_api_key && (
          <section style={{ marginTop: "1.4rem" }}>
            <div
              style={{
                fontSize: "0.6rem",
                letterSpacing: "0.1em",
                color: "rgba(0,255,65,0.6)",
                marginBottom: "0.4rem",
              }}
            >
              ADMIN API KEY (X-API-Key header)
            </div>
            <code
              style={{
                display: "block",
                padding: "0.7rem 0.9rem",
                background: "rgba(0,255,65,0.06)",
                border: "1px solid rgba(0,255,65,0.3)",
                fontSize: "0.78rem",
                wordBreak: "break-all",
                lineHeight: 1.5,
              }}
            >
              {secrets.system_api_key}
            </code>
            <button
              type="button"
              onClick={() => copy(secrets.system_api_key!, "api")}
              style={{
                marginTop: "0.5rem",
                background: apiCopied ? "rgba(0,255,65,0.22)" : "rgba(0,255,65,0.08)",
                border: "1px solid rgba(0,255,65,0.5)",
                color: "#00ff41",
                fontFamily: "var(--font-terminal)",
                fontSize: "0.62rem",
                letterSpacing: "0.08em",
                padding: "0.42rem 0.9rem",
                cursor: "pointer",
              }}
            >
              {apiCopied ? "COPIED ✓" : "COPY"}
            </button>
            <p
              style={{
                fontSize: "0.62rem",
                color: "rgba(0,255,65,0.45)",
                marginTop: "0.5rem",
                lineHeight: 1.4,
              }}
            >
              Loaded into this session, so the IngestPage / KEYS pages pick it up automatically. It
              is held in memory only — never written to disk or browser storage — so reloading or
              restarting the app clears it. Save an external copy now.
            </p>
          </section>
        )}

        {secrets.bjj_authority_key_hex && (
          <section style={{ marginTop: "1.6rem" }}>
            <div
              style={{
                fontSize: "0.6rem",
                letterSpacing: "0.1em",
                color: "rgba(0,255,65,0.6)",
                marginBottom: "0.4rem",
              }}
            >
              BJJ AUTHORITY PRIVATE KEY (OLYMPUS_BJJ_AUTHORITY_KEY env var)
            </div>
            <code
              style={{
                display: "block",
                padding: "0.7rem 0.9rem",
                background: "rgba(0,255,65,0.06)",
                border: "1px solid rgba(0,255,65,0.3)",
                fontSize: "0.7rem",
                wordBreak: "break-all",
                lineHeight: 1.5,
              }}
            >
              {secrets.bjj_authority_key_hex}
            </code>
            <button
              type="button"
              onClick={() => copy(secrets.bjj_authority_key_hex!, "bjj")}
              style={{
                marginTop: "0.5rem",
                background: bjjCopied ? "rgba(0,255,65,0.22)" : "rgba(0,255,65,0.08)",
                border: "1px solid rgba(0,255,65,0.5)",
                color: "#00ff41",
                fontFamily: "var(--font-terminal)",
                fontSize: "0.62rem",
                letterSpacing: "0.08em",
                padding: "0.42rem 0.9rem",
                cursor: "pointer",
              }}
            >
              {bjjCopied ? "COPIED ✓" : "COPY"}
            </button>
            <p
              style={{
                fontSize: "0.62rem",
                color: "rgba(255,200,120,0.7)",
                marginTop: "0.5rem",
                lineHeight: 1.5,
              }}
            >
              Add to your <code>.env</code> file or shell rc:
              <br />
              <code
                style={{
                  color: "#ccffcc",
                  background: "rgba(0,255,65,0.05)",
                  padding: "0.1rem 0.3rem",
                  fontSize: "0.65rem",
                }}
              >
                export OLYMPUS_BJJ_AUTHORITY_KEY={secrets.bjj_authority_key_hex}
              </code>
              <br />
              Without this, the next launch will fail to start the unified ZK prover (the database
              keeps the public key but cannot recover the private one).
            </p>
          </section>
        )}

        {/* Gate the dismiss button so the operator cannot accidentally
            close the dialog without saving the secrets. They must either
            press COPY for every key the modal is showing, or explicitly
            tick "I saved them manually" — the latter exists for password
            managers that don't fire navigator.clipboard.writeText. */}
        {(() => {
          const needApi = !!secrets.system_api_key && !apiCopied;
          const needBjj = !!secrets.bjj_authority_key_hex && !bjjCopied;
          const blockedByCopy = (needApi || needBjj) && !manualAck;
          return (
            <div style={{ marginTop: "1.6rem" }}>
              {(needApi || needBjj) && (
                <label
                  style={{
                    display: "block",
                    fontSize: "0.6rem",
                    color: "rgba(255,200,120,0.8)",
                    marginBottom: "0.6rem",
                    cursor: "pointer",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={manualAck}
                    onChange={(e) => setManualAck(e.target.checked)}
                    style={{ accentColor: "#00ff41", marginRight: 6 }}
                  />
                  I copied {needApi && needBjj ? "both keys" : "the key"} manually (e.g. by
                  selecting + Ctrl+C from the field above).
                </label>
              )}
              <div style={{ display: "flex", justifyContent: "flex-end" }}>
                <button
                  type="button"
                  onClick={dismiss}
                  disabled={acknowledged || blockedByCopy}
                  title={
                    blockedByCopy
                      ? "Copy each shown key (or tick the manual-copy checkbox) before dismissing."
                      : undefined
                  }
                  style={{
                    background: acknowledged
                      ? "rgba(0,255,65,0.18)"
                      : blockedByCopy
                        ? "rgba(255,0,85,0.04)"
                        : "rgba(255,0,85,0.08)",
                    border: `1px solid ${
                      acknowledged
                        ? "rgba(0,255,65,0.5)"
                        : blockedByCopy
                          ? "rgba(255,0,85,0.25)"
                          : "rgba(255,0,85,0.5)"
                    }`,
                    color: acknowledged
                      ? "#00ff41"
                      : blockedByCopy
                        ? "rgba(255,68,119,0.5)"
                        : "#ff4477",
                    fontFamily: "var(--font-terminal)",
                    fontSize: "0.7rem",
                    letterSpacing: "0.1em",
                    padding: "0.6rem 1.4rem",
                    cursor: acknowledged || blockedByCopy ? "not-allowed" : "pointer",
                  }}
                >
                  {acknowledged
                    ? "DISMISSED"
                    : blockedByCopy
                      ? "COPY KEYS TO ENABLE"
                      : "I'VE SAVED BOTH KEYS"}
                </button>
              </div>
            </div>
          );
        })()}
      </div>
    </div>
  );
};

export default InitialSecretsModal;
