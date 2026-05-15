import type { CommitStage } from "../hooks/useFileCommit";

interface CommitPromptProps {
  apiKey: string;
  setApiKey: (v: string) => void;
  commitStage: CommitStage;
  commitError: string | null;
  onCommit: () => Promise<void>;
  onReset?: () => void;
}

export default function CommitPrompt({
  apiKey,
  setApiKey,
  commitStage,
  commitError,
  onCommit,
  onReset,
}: CommitPromptProps) {
  const isAuthError = commitError?.toLowerCase().includes("authentication failed") ||
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
      <div style={{ marginBottom: "0.85rem" }}>
        <label
          style={{
            display: "block",
            fontSize: "0.55rem",
            letterSpacing: "0.1em",
            color: "rgba(245,158,11,0.5)",
            marginBottom: "0.35rem",
          }}
        >
          API KEY
        </label>
        <input
          // eslint-disable-next-line jsx-a11y/no-autofocus
          autoFocus={isAuthError}
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="your API key from registration"
          style={{
            width: "100%",
            background: "rgba(0,0,0,0.65)",
            border: isAuthError
              ? "1px solid rgba(255,0,85,0.7)"
              : "1px solid rgba(245,158,11,0.3)",
            color: isAuthError ? "#ff0055" : "#f59e0b",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.78rem",
            padding: "0.6rem 0.75rem",
            outline: "none",
            boxSizing: "border-box",
          }}
        />
        {isAuthError && (
          <button
            type="button"
            onClick={() => { setApiKey(""); if (onReset) onReset(); }}
            style={{
              marginTop: "0.4rem",
              background: "none",
              border: "none",
              color: "rgba(255,0,85,0.7)",
              fontFamily: "'DM Mono', monospace",
              fontSize: "0.6rem",
              letterSpacing: "0.08em",
              cursor: "pointer",
              padding: 0,
            }}
          >
            CLEAR KEY AND RETRY →
          </button>
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
      {commitError && (
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
