import { useSkin } from "../skins/SkinContext";
import { SAMPLE_HASH } from "../lib/constants";
import FileHasher from "../components/FileHasher";

interface HashTabProps {
  hashInput: string;
  setHashInput: (v: string) => void;
  hashError: string | null;
  hashStatus: { label: string; tone: "ok" | "warn" | "err" | "neutral" };
  isPending: boolean;
  onSubmit: (hash: string) => void;
  onPaste: () => Promise<void>;
  onClear: () => void;
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
  wasmError,
  onFile,
  onFileHash,
  onFileProgress,
  fileProgress,
}: HashTabProps) {
  const { skin } = useSkin();
  return (
    <div>
      {wasmError && (
        <p className="err-text" style={{ marginBottom: "0.75rem" }}>
          ⚠ {wasmError}
        </p>
      )}
      {onFile && onFileHash && onFileProgress && (
        <div style={{ marginBottom: "1rem" }}>
          <FileHasher
            onHash={(hex) => {
              onFileHash(hex);
              setHashInput(hex);
            }}
            onProgress={onFileProgress}
            onFile={onFile}
          />
          {fileProgress !== undefined && fileProgress > 0 && fileProgress < 100 && (
            <p
              className={skin.classes.mutedText}
              style={{ fontSize: "0.65rem", marginTop: "0.4rem" }}
            >
              HASHING... {fileProgress}%
            </p>
          )}
        </div>
      )}
      <div className="field-head">
        <label htmlFor="hash-input" className="terminal-label">
          BLAKE3 content hash
        </label>
        <span className={`status-pill status-${hashStatus.tone}`}>
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
          placeholder="ENTER_BLAKE3_HASH or drop a file above..."
          maxLength={64}
          spellCheck={false}
          autoComplete="off"
          className={skin.classes.input}
        />
        <button
          type="button"
          className={skin.classes.buttonPrimary}
          onClick={() => onSubmit(hashInput)}
          disabled={isPending || hashStatus.tone !== "ok"}
        >
          {isPending ? "EXECUTING..." : "VERIFY"}
        </button>
      </div>
      <div className="quick-actions">
        <button
          type="button"
          className={skin.classes.buttonSecondary}
          onClick={() => void onPaste()}
        >
          PASTE
        </button>
        <button
          type="button"
          className={skin.classes.buttonSecondary}
          onClick={() => {
            setHashInput(SAMPLE_HASH);
          }}
        >
          SAMPLE
        </button>
        <button type="button" className={skin.classes.buttonSecondary} onClick={onClear}>
          CLEAR
        </button>
      </div>
      {hashError && <p className="err-text">{hashError}</p>}
    </div>
  );
}
