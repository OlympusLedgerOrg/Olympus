import { SAMPLE_HASH } from "../lib/constants";

interface HashTabProps {
  hashInput: string;
  setHashInput: (v: string) => void;
  hashError: string | null;
  hashStatus: { label: string; tone: "ok" | "warn" | "err" | "neutral" };
  isPending: boolean;
  onSubmit: (hash: string) => void;
  onPaste: () => Promise<void>;
  onClear: () => void;
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
}: HashTabProps) {
  return (
    <div>
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
          placeholder="ENTER_BLAKE3_HASH..."
          maxLength={64}
          spellCheck={false}
          autoComplete="off"
          className="cyber-input"
        />
        <button
          type="button"
          className="cyber-button"
          onClick={() => onSubmit(hashInput)}
          disabled={isPending || hashStatus.tone !== "ok"}
        >
          {isPending ? "EXECUTING..." : "VERIFY"}
        </button>
      </div>
      <div className="quick-actions">
        <button type="button" className="icon-text-btn" onClick={() => void onPaste()}>
          PASTE
        </button>
        <button
          type="button"
          className="icon-text-btn"
          onClick={() => {
            setHashInput(SAMPLE_HASH);
          }}
        >
          SAMPLE
        </button>
        <button type="button" className="icon-text-btn" onClick={onClear}>
          CLEAR
        </button>
      </div>
      {hashError && <p className="err-text">{hashError}</p>}
    </div>
  );
}
