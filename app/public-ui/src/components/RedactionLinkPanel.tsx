import { useCallback, useRef } from "react";
import type { RedactionLinkResult, RedactionStage } from "../hooks/useRedactionLink";

interface Props {
  redactedFileName: string;
  stage: RedactionStage;
  originalFile: File | null;
  originalHash: string;
  commitId: string;
  setCommitId: (v: string) => void;
  result: RedactionLinkResult | null;
  error: string | null;
  onStart: () => void;
  onOriginalFile: (f: File) => void;
  onLink: () => void;
  onReset: () => void;
}

const mono: React.CSSProperties = { fontFamily: "'DM Mono', monospace" };

const lbl: React.CSSProperties = {
  display: "block", fontSize: "0.56rem", letterSpacing: "0.12em",
  color: "rgba(0,255,65,0.45)", marginBottom: "0.3rem", ...mono,
};

const inp: React.CSSProperties = {
  width: "100%", background: "rgba(0,0,0,0.65)",
  border: "1px solid rgba(0,255,65,0.22)", color: "#00ff41",
  ...mono, fontSize: "0.72rem",
  padding: "0.55rem 0.75rem", outline: "none", boxSizing: "border-box",
};

const dimRow: React.CSSProperties = {
  display: "flex", gap: "0.5rem", fontSize: "0.62rem",
  color: "rgba(0,255,65,0.5)", marginBottom: "0.4rem", ...mono,
};

export default function RedactionLinkPanel({
  redactedFileName, stage, originalFile, originalHash,
  commitId, setCommitId, result, error,
  onStart, onOriginalFile, onLink, onReset,
}: Props) {
  const inputRef = useRef<HTMLInputElement>(null);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (f) onOriginalFile(f);
  }, [onOriginalFile]);

  const onPick = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) onOriginalFile(f);
  }, [onOriginalFile]);

  // --- idle: just show the "prove as redaction" entry button ---
  if (stage === "idle") {
    return (
      <div style={{
        marginTop: "1rem", padding: "1rem 1.25rem",
        border: "1px dashed rgba(0,255,65,0.18)", background: "rgba(0,255,65,0.01)",
      }}>
        <div style={{ fontSize: "0.58rem", color: "rgba(0,255,65,0.4)", letterSpacing: "0.1em", marginBottom: "0.75rem", ...mono }}>
          OR — VERIFY AS REDACTION
        </div>
        <p style={{ fontSize: "0.65rem", color: "rgba(0,255,65,0.4)", margin: "0 0 0.85rem", lineHeight: 1.6 }}>
          If <strong style={{ color: "rgba(0,255,65,0.7)" }}>{redactedFileName}</strong> is a
          redacted version of a document already on the ledger, you can prove the link
          cryptographically without committing this file separately.
        </p>
        <button type="button" onClick={onStart} style={{
          background: "transparent", border: "1px solid rgba(0,255,65,0.3)",
          color: "rgba(0,255,65,0.7)", ...mono, fontSize: "0.68rem",
          letterSpacing: "0.1em", padding: "0.55rem 1rem", cursor: "pointer",
        }}>
          PROVE AS REDACTION →
        </button>
      </div>
    );
  }

  // --- done: show the result bundle ---
  if (stage === "done" && result) {
    const revealPct = Math.round((result.revealed_count / (result.revealed_count + result.redacted_count)) * 100);
    return (
      <div style={{
        marginTop: "1rem", padding: "1.25rem",
        border: "1px solid rgba(0,255,65,0.45)", background: "rgba(0,255,65,0.03)",
      }}>
        <div style={{ fontSize: "0.58rem", color: "rgba(0,255,65,0.5)", letterSpacing: "0.12em", marginBottom: "1rem", ...mono }}>
          REDACTION_VERIFIED ✓
        </div>

        <div style={dimRow}>
          <span style={{ color: "#00ff41" }}>{result.revealed_count}</span>
          <span>chunks revealed</span>
          <span style={{ color: "rgba(255,80,80,0.8)" }}>{result.redacted_count}</span>
          <span>redacted</span>
          <span style={{ marginLeft: "auto", color: "rgba(0,255,65,0.5)" }}>{revealPct}% disclosed</span>
        </div>

        {/* Reveal mask visualiser */}
        <div style={{ display: "flex", gap: "2px", marginBottom: "1rem", flexWrap: "wrap" }}>
          {result.reveal_mask.map((v: number, i: number) => (
            <div key={i} title={`chunk ${i}: ${v ? "revealed" : "redacted"}`} style={{
              width: "10px", height: "10px",
              background: v ? "rgba(0,255,65,0.55)" : "rgba(255,60,60,0.45)",
              border: `1px solid ${v ? "rgba(0,255,65,0.3)" : "rgba(255,60,60,0.25)"}`,
            }} />
          ))}
        </div>

        <div style={{ marginBottom: "0.75rem" }}>
          <label style={lbl}>ORIGINAL COMMIT</label>
          <code style={{ fontSize: "0.65rem", color: "rgba(0,255,65,0.8)", wordBreak: "break-all", display: "block" }}>
            {result.original_commit_id}
          </code>
        </div>

        <div style={{ marginBottom: "0.75rem" }}>
          <label style={lbl}>ORIGINAL ROOT (POSEIDON)</label>
          <code style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.6)", wordBreak: "break-all", display: "block" }}>
            {result.original_root}
          </code>
        </div>

        <div style={{ marginBottom: "0.75rem" }}>
          <label style={lbl}>REDACTED COMMITMENT</label>
          <code style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.6)", wordBreak: "break-all", display: "block" }}>
            {result.redacted_commitment}
          </code>
        </div>

        <div style={{ marginBottom: "1rem" }}>
          <label style={lbl}>REVEAL MASK COMMITMENT</label>
          <code style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.6)", wordBreak: "break-all", display: "block" }}>
            {result.reveal_mask_commitment}
          </code>
        </div>

        <div style={{
          fontSize: "0.6rem", color: "rgba(0,255,65,0.38)", lineHeight: 1.6,
          borderTop: "1px solid rgba(0,255,65,0.1)", paddingTop: "0.75rem", marginBottom: "1rem",
        }}>
          {result.note}
        </div>

        <div style={{ display: "flex", gap: "0.75rem" }}>
          <button type="button" onClick={() => {
            navigator.clipboard.writeText(JSON.stringify(result, null, 2));
          }} style={{
            flex: 1, padding: "0.6rem", background: "rgba(0,255,65,0.08)",
            border: "1px solid rgba(0,255,65,0.35)", color: "#00ff41",
            ...mono, fontSize: "0.65rem", letterSpacing: "0.08em", cursor: "pointer",
          }}>
            COPY BUNDLE
          </button>
          <button type="button" onClick={onReset} style={{
            flex: 1, padding: "0.6rem", background: "transparent",
            border: "1px solid rgba(0,255,65,0.2)", color: "rgba(0,255,65,0.5)",
            ...mono, fontSize: "0.65rem", letterSpacing: "0.08em", cursor: "pointer",
          }}>
            RESET
          </button>
        </div>
      </div>
    );
  }

  // --- awaiting_original / hashing / ready / linking / error ---
  const busy = stage === "hashing" || stage === "linking";

  return (
    <div style={{
      marginTop: "1rem", padding: "1.25rem",
      border: "1px solid rgba(0,255,65,0.22)", background: "rgba(0,255,65,0.02)",
    }}>
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        marginBottom: "1rem",
      }}>
        <div style={{ fontSize: "0.58rem", color: "rgba(0,255,65,0.5)", letterSpacing: "0.12em", ...mono }}>
          VERIFY AS REDACTION
        </div>
        <button type="button" onClick={onReset} style={{
          background: "transparent", border: "none", color: "rgba(0,255,65,0.35)",
          ...mono, fontSize: "0.6rem", cursor: "pointer", letterSpacing: "0.08em",
        }}>
          ✕ CANCEL
        </button>
      </div>

      {/* Original file drop zone */}
      <div style={{ marginBottom: "1rem" }}>
        <label style={lbl}>DROP ORIGINAL DOCUMENT (e.g. 2.pdf)</label>
        <div
          onClick={() => !busy && inputRef.current?.click()}
          onDragOver={e => e.preventDefault()}
          onDrop={onDrop}
          style={{
            border: "1px dashed rgba(0,255,65,0.3)",
            background: originalFile ? "rgba(0,255,65,0.04)" : "rgba(0,255,65,0.01)",
            padding: "1.25rem 1rem", textAlign: "center",
            cursor: busy ? "default" : "pointer", transition: "all 0.15s",
          }}
        >
          <input ref={inputRef} type="file" onChange={onPick} style={{ display: "none" }} />
          {originalFile ? (
            <div>
              <div style={{ fontSize: "0.78rem", color: "#00ff41", marginBottom: "0.3rem", ...mono }}>
                {originalFile.name}
              </div>
              {originalHash && (
                <div style={{ fontSize: "0.58rem", color: "rgba(0,255,65,0.45)", wordBreak: "break-all" }}>
                  {originalHash.slice(0, 24)}…
                </div>
              )}
              {stage === "hashing" && (
                <div style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.5)", marginTop: "0.3rem" }}>
                  COMPUTING BLAKE3…
                </div>
              )}
            </div>
          ) : (
            <div style={{ fontSize: "0.66rem", color: "rgba(0,255,65,0.35)", letterSpacing: "0.08em", ...mono }}>
              DROP ORIGINAL FILE HERE
            </div>
          )}
        </div>
      </div>

      {/* Commit ID input */}
      <div style={{ marginBottom: "1.25rem" }}>
        <label style={lbl}>ORIGINAL COMMIT ID (from ledger)</label>
        <input
          type="text"
          value={commitId}
          onChange={e => setCommitId(e.target.value)}
          placeholder="0x…"
          style={inp}
          disabled={busy}
        />
      </div>

      {error && (
        <div style={{
          marginBottom: "1rem", padding: "0.7rem 0.9rem",
          border: "1px solid rgba(255,0,85,0.4)", color: "#ff0055",
          fontSize: "0.66rem", background: "rgba(255,0,85,0.05)", ...mono,
        }}>
          {error}
        </div>
      )}

      <button
        type="button"
        onClick={() => void onLink()}
        disabled={busy || !originalFile || !commitId.trim()}
        style={{
          width: "100%", padding: "0.75rem",
          background: busy ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.12)",
          border: "1px solid rgba(0,255,65,0.5)", color: "#00ff41",
          ...mono, fontSize: "0.7rem", letterSpacing: "0.12em",
          cursor: busy || !originalFile || !commitId.trim() ? "not-allowed" : "pointer",
        }}
      >
        {stage === "linking" ? "COMPUTING REDACTION PROOF…" : "LINK TO ORIGINAL"}
      </button>
    </div>
  );
}
