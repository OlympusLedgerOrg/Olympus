import type { CommitStage } from "../hooks/useFileCommit";
import { apiKeyProblem, clearStoredApiKey } from "../lib/storage";

interface CommitPromptProps {
  apiKey: string;
  setApiKey: (v: string) => void;
  commitStage: CommitStage;
  commitError: string | null;
  onCommit: () => Promise<void>;
}

export default function CommitPrompt({
  apiKey,
  setApiKey,
  commitStage,
  commitError,
  onCommit,
}: CommitPromptProps) {
  const keyProblem = apiKey.trim() ? apiKeyProblem(apiKey) : null;

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
      <p
        style={{
          margin: "0 0 0.85rem",
          color: "rgba(245,158,11,0.72)",
          fontSize: "0.68rem",
          lineHeight: 1.5,
        }}
      >
        Normal verification sent only the hash. This commit action uploads the
        file bytes to /ingest/files and requires an API key.
      </p>
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
        <button
          type="button"
          onClick={() => {
            clearStoredApiKey();
            setApiKey("");
          }}
          style={{
            marginBottom: "0.45rem",
            background: "transparent",
            border: "1px solid rgba(245,158,11,0.28)",
            color: "rgba(245,158,11,0.72)",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.56rem",
            letterSpacing: "0.08em",
            padding: "0.25rem 0.55rem",
            cursor: "pointer",
          }}
        >
          CLEAR_SAVED_KEY
        </button>
        <input
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value.slice(0, 64))}
          placeholder="64-character API key from signup"
          maxLength={64}
          spellCheck={false}
          autoComplete="off"
          style={{
            width: "100%",
            background: "rgba(0,0,0,0.65)",
            border: "1px solid rgba(245,158,11,0.3)",
            color: "#f59e0b",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.78rem",
            padding: "0.6rem 0.75rem",
            outline: "none",
            boxSizing: "border-box",
          }}
        />
        {keyProblem && (
          <div
            style={{
              marginTop: "0.45rem",
              color: "#ff0055",
              fontSize: "0.64rem",
              lineHeight: 1.4,
            }}
          >
            {keyProblem}
          </div>
        )}
      </div>
      <button
        type="button"
        onClick={() => void onCommit()}
        disabled={commitStage === "committing" || !apiKey.trim() || Boolean(keyProblem)}
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
            commitStage === "committing" || !apiKey.trim() || Boolean(keyProblem)
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
