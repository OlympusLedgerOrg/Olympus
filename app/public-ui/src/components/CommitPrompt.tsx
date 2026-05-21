import type { CommitStage } from "../hooks/useFileCommit";

interface CommitPromptProps {
  apiKey: string;
  setApiKey: (v: string) => void;
  commitStage: CommitStage;
  commitError: string | null;
  onCommit: () => Promise<void>;
  onReset?: () => void;
  originalHash: string;
  setOriginalHash: (v: string) => void;
}

export default function CommitPrompt({
  apiKey,
  setApiKey,
  commitStage,
  commitError,
  onCommit,
  onReset,
  originalHash,
  setOriginalHash,
}: CommitPromptProps) {
  const isAuthError =
    commitError?.toLowerCase().includes("authentication failed") ||
    commitError?.toLowerCase().includes("invalid api key") ||
    commitError?.toLowerCase().includes("auth_invalid") ||
    commitError?.toLowerCase().includes("auth_expired");

  return (
    <div
      style={{
        marginTop: "1rem",
        padding: "1.25rem 1.5rem",
        border: "1px solid rgba(245,158,11,0.35)",
        background: "rgba(245,158,11,0.03)",
      }}
    >
      <div
        style={{
          fontSize: "0.55rem",
          letterSpacing: "0.12em",
          color: "rgba(245,158,11,0.6)",
          marginBottom: "1rem",
        }}
      >
        COMMIT THIS FILE TO THE LEDGER
      </div>

      <div style={{ marginBottom: "0.75rem" }}>
        <label
          style={{
            display: "block",
            fontSize: "0.5rem",
            letterSpacing: "0.12em",
            color: "rgba(245,158,11,0.5)",
            marginBottom: "0.3rem",
          }}
        >
          ORIGINAL_HASH (optional — link as redaction)
        </label>
        <input
          type="text"
          value={originalHash}
          onChange={(e) => setOriginalHash(e.target.value)}
          placeholder="paste BLAKE3 hash of original document"
          spellCheck={false}
          style={{
            width: "100%",
            background: "rgba(0,0,0,0.4)",
            border: originalHash.trim()
              ? "1px solid rgba(168,85,247,0.5)"
              : "1px solid rgba(245,158,11,0.2)",
            color: originalHash.trim() ? "#a855f7" : "rgba(245,158,11,0.6)",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.65rem",
            padding: "0.5rem 0.6rem",
            outline: "none",
            boxSizing: "border-box",
          }}
        />
        {originalHash.trim() && (
          <div
            style={{
              fontSize: "0.5rem",
              color: "#a855f7",
              marginTop: "0.25rem",
              letterSpacing: "0.08em",
            }}
          >
            REDACTION_MODE — this file will be linked as a redacted version of the original
          </div>
        )}
      </div>

      <button
        type="button"
        onClick={() => void onCommit()}
        disabled={commitStage === "committing" || !apiKey.trim()}
        style={{
          width: "100%",
          padding: "0.75rem",
          background:
            commitStage === "committing"
              ? "rgba(245,158,11,0.06)"
              : "rgba(245,158,11,0.12)",
          border: "1px solid rgba(245,158,11,0.5)",
          color: "#f59e0b",
          fontFamily: "'DM Mono', monospace",
          fontSize: "0.72rem",
          letterSpacing: "0.12em",
          cursor:
            commitStage === "committing" || !apiKey.trim()
              ? "not-allowed"
              : "pointer",
        }}
      >
        {commitStage === "committing" ? "COMMITTING..." : "COMMIT TO LEDGER →"}
      </button>

      {/* Auth error: show error message + key input inline at the error site */}
      {commitError && isAuthError && (
        <div
          style={{
            marginTop: "0.75rem",
            padding: "0.75rem 0.85rem",
            border: "1px solid rgba(255,0,85,0.4)",
            background: "rgba(255,0,85,0.05)",
          }}
        >
          <div style={{ color: "#ff0055", fontSize: "0.7rem", marginBottom: "0.75rem" }}>
            {commitError}
          </div>
          <label
            style={{
              display: "block",
              fontSize: "0.55rem",
              letterSpacing: "0.1em",
              color: "rgba(255,0,85,0.6)",
              marginBottom: "0.35rem",
            }}
          >
            API KEY
          </label>
          {/* eslint-disable-next-line jsx-a11y/no-autofocus */}
          <input
            autoFocus
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="paste a valid API key"
            style={{
              width: "100%",
              background: "rgba(0,0,0,0.65)",
              border: "1px solid rgba(255,0,85,0.5)",
              color: "#ff0055",
              fontFamily: "'DM Mono', monospace",
              fontSize: "0.78rem",
              padding: "0.6rem 0.75rem",
              outline: "none",
              boxSizing: "border-box",
            }}
          />
          <div style={{ display: "flex", gap: "0.75rem", marginTop: "0.5rem" }}>
            <button
              type="button"
              onClick={() => void onCommit()}
              disabled={!apiKey.trim() || commitStage === "committing"}
              style={{
                flex: 1,
                padding: "0.5rem",
                background: "rgba(255,0,85,0.1)",
                border: "1px solid rgba(255,0,85,0.4)",
                color: "#ff0055",
                fontFamily: "'DM Mono', monospace",
                fontSize: "0.6rem",
                letterSpacing: "0.1em",
                cursor: !apiKey.trim() ? "not-allowed" : "pointer",
              }}
            >
              RETRY →
            </button>
            <button
              type="button"
              onClick={() => { setApiKey(""); if (onReset) onReset(); }}
              style={{
                background: "none",
                border: "none",
                color: "rgba(255,0,85,0.5)",
                fontFamily: "'DM Mono', monospace",
                fontSize: "0.6rem",
                letterSpacing: "0.08em",
                cursor: "pointer",
                padding: "0.5rem 0",
              }}
            >
              CLEAR
            </button>
          </div>
        </div>
      )}

      {/* Non-auth errors: plain message only */}
      {commitError && !isAuthError && (
        <div
          style={{
            marginTop: "0.75rem",
            padding: "0.65rem 0.85rem",
            border: "1px solid rgba(255,0,85,0.4)",
            color: "#ff0055",
            fontSize: "0.7rem",
            background: "rgba(255,0,85,0.05)",
          }}
        >
          {commitError}
        </div>
      )}
    </div>
  );
}
