import type { HashVerificationSource } from "../hooks/useHashVerification";
import { SAMPLE_HASH } from "../lib/constants";
import FileHasher from "../components/FileHasher";

interface HashTabProps {
  hashInput: string;
  setHashInput: (v: string) => void;
  hashError: string | null;
  hashStatus: { label: string; tone: "ok" | "warn" | "err" | "neutral" };
  isPending: boolean;
  onSubmit: (hash: string, source?: HashVerificationSource) => void;
  onPaste: () => Promise<void>;
  onClear: () => void;
  apiKey: string;
  setApiKey: (v: string) => void;
  // File-drop integration: dropping a file hashes locally and populates the
  // hash field, then the existing VERIFY button submits it.
  wasmError?: string | null;
  onFile?: (file: File) => void;
  onFileHash?: (hex: string) => void;
  onFileProgress?: (pct: number) => void;
  fileProgress?: number;
}

export default function HashTab({
  hashInput,
  setHashInput,
  hashError,
  hashStatus,
  isPending,
  onSubmit,
  onPaste,
  onClear,
  apiKey,
  setApiKey,
  wasmError,
  onFile,
  onFileHash,
  onFileProgress,
  fileProgress,
}: HashTabProps) {
  return (
    <div>
      {wasmError && (
        <p className="ods-error" style={{ marginBottom: "0.75rem" }}>
          ⚠ {wasmError}
        </p>
      )}
      <div className="ods-field" style={{ marginBottom: "1rem" }}>
        <label htmlFor="hash-api-key" className="ods-label">
          API key <span className="ods-muted">(required — verify scope)</span>
        </label>
        <input
          id="hash-api-key"
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="paste your API key..."
          autoComplete="off"
          spellCheck={false}
          className="ods-input"
          aria-describedby="hash-api-key-hint"
        />
        <div className="ods-hint" id="hash-api-key-hint">
          Held in memory only — cleared on reload.
        </div>
      </div>
      {onFile && onFileHash && onFileProgress && (
        <div style={{ marginBottom: "1rem" }}>
          <FileHasher
            onHash={(hex) => {
              onFileHash(hex);
              setHashInput(hex);
              onSubmit(hex, "file");
            }}
            onProgress={onFileProgress}
            onFile={onFile}
          />
          {fileProgress !== undefined && fileProgress > 0 && fileProgress < 100 && (
            <p className="ods-muted" style={{ fontSize: "0.65rem", marginTop: "0.4rem" }}>
              HASHING_FILE... {fileProgress}%
            </p>
          )}
        </div>
      )}
      <div className="field-head">
        <label htmlFor="hash-input" className="ods-label">
          BLAKE3 content hash
        </label>
        <span className="ods-pill" data-tone={hashStatus.tone}>
          {hashStatus.label}
        </span>
      </div>
      <div className="input-row">
        <input
          id="hash-input"
          type="text"
          value={hashInput}
          onChange={(event) => {
            setHashInput(event.target.value);
          }}
          onKeyDown={(event) => {
            if (event.key === "Enter") onSubmit(hashInput);
          }}
          placeholder="ENTER_BLAKE3_HASH or drop/select a file above..."
          maxLength={64}
          spellCheck={false}
          autoComplete="off"
          className="ods-input"
          aria-invalid={hashError ? true : undefined}
          aria-describedby={hashError ? "hash-input-error" : undefined}
        />
        <button
          type="button"
          className="ods-btn"
          onClick={() => onSubmit(hashInput)}
          disabled={isPending || hashStatus.tone !== "ok"}
        >
          {isPending ? "EXECUTING..." : "VERIFY_HASH"}
        </button>
      </div>
      <div className="quick-actions">
        <button type="button" className="ods-btn-ghost" onClick={() => void onPaste()}>
          PASTE
        </button>
        <button
          type="button"
          className="ods-btn-ghost"
          onClick={() => {
            setHashInput(SAMPLE_HASH);
          }}
        >
          SAMPLE
        </button>
        <button type="button" className="ods-btn-ghost" onClick={onClear}>
          CLEAR
        </button>
      </div>
      {hashError && (
        <p className="ods-error" id="hash-input-error" style={{ marginTop: "0.4rem" }}>
          {hashError}
        </p>
      )}
    </div>
  );
}
