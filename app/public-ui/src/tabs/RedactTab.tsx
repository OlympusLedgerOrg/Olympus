/**
 * RedactTab — producer side of redaction (issuer view).
 *
 * Workflow:
 *   1. Load the ORIGINAL (already-committed) document.
 *   2. Mark byte ranges to hide — either by selecting text in the preview
 *      ("Add selection") or by typing start/end offsets.
 *   3. Set the recipient ID (+ optional fill byte), then REDACT.
 *   4. Download the redacted artifact and the `redaction_validity` bundle and
 *      hand both to the recipient, who audits them in the REDACTION tab.
 *
 * Redaction is whole-chunk (≈ 1/16 of the file per touched chunk); the chunk
 * strip previews exactly which chunks will be hidden before you submit.
 */
import { useCallback, useRef, useState } from "react";
import { useSkin } from "../skins/SkinContext";
import type { useRedactionCreate } from "../hooks/useRedactionCreate";

type Hook = ReturnType<typeof useRedactionCreate>;

interface RedactTabProps {
  hook: Hook;
}

function short(s: string): string {
  if (s.length <= 18) return s;
  return `${s.slice(0, 9)}…${s.slice(-6)}`;
}

/** Byte offset of the first `charCount` characters of `text` when UTF-8 encoded. */
function charToByteOffset(text: string, charCount: number): number {
  return new TextEncoder().encode(text.slice(0, charCount)).length;
}

export default function RedactTab({ hook }: RedactTabProps) {
  const { skin } = useSkin();
  const fileRef = useRef<HTMLInputElement>(null);
  const previewRef = useRef<HTMLTextAreaElement>(null);
  const [manualStart, setManualStart] = useState("");
  const [manualEnd, setManualEnd] = useState("");
  const [dragging, setDragging] = useState(false);

  const busy = hook.stage === "redacting";

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const f = e.dataTransfer.files?.[0];
      if (f) void hook.onFile(f);
    },
    [hook],
  );

  const addSelection = useCallback(() => {
    const el = previewRef.current;
    if (!el || hook.fileText === null) return;
    const { selectionStart, selectionEnd } = el;
    if (selectionStart == null || selectionEnd == null || selectionStart === selectionEnd) {
      return;
    }
    const startByte = charToByteOffset(hook.fileText, selectionStart);
    const endByte = charToByteOffset(hook.fileText, selectionEnd);
    hook.addRange(startByte, endByte);
  }, [hook]);

  const addManual = useCallback(() => {
    const s = Number(manualStart);
    const e = Number(manualEnd);
    hook.addRange(s, e);
    setManualStart("");
    setManualEnd("");
  }, [hook, manualStart, manualEnd]);

  const purple = "rgba(168,85,247,";
  const accent = "#c084fc";

  const hiddenChunks = hook.previewMask.filter((m) => m === 0).length;

  return (
    <div style={{ fontFamily: "'DM Mono', monospace" }}>
      {/* Original file drop zone */}
      <div
        role="region"
        aria-label="Drop the original document here"
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setDragging(false);
        }}
        onDrop={onDrop}
        style={{
          border: `2px dashed ${dragging ? `${purple}0.7)` : `${purple}0.35)`}`,
          borderRadius: "8px",
          padding: "1rem",
          background: dragging ? `${purple}0.06)` : "transparent",
          transition: "border-color 0.15s, background 0.15s",
        }}
      >
        <button
          type="button"
          disabled={busy}
          onClick={() => fileRef.current?.click()}
          style={{
            width: "100%",
            border: `1px dashed ${purple}${hook.fileName ? "0.55)" : "0.25)"}`,
            borderRadius: "6px",
            padding: "0.9rem",
            textAlign: "center",
            cursor: busy ? "default" : "pointer",
            background: hook.fileName ? `${purple}0.04)` : "transparent",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.75rem",
          }}
        >
          <span aria-hidden style={{ fontSize: "1.4rem", display: "block", opacity: 0.7 }}>
            📄
          </span>
          <span style={{ display: "block", color: `${purple}0.75)`, margin: "0.25rem 0" }}>
            ORIGINAL_DOC
          </span>
          {hook.fileName ? (
            <span style={{ color: accent, wordBreak: "break-all" }}>
              {hook.fileName} · {hook.fileSize} bytes
            </span>
          ) : (
            <span style={{ color: `${purple}0.45)` }}>click or drop — text / CSV / JSON / logs</span>
          )}
        </button>
        <p style={{ margin: "0.6rem 0 0", fontSize: "0.6rem", color: `${purple}0.45)`, textAlign: "center" }}>
          The original must already be committed on the ledger. Bytes are blanked
          in place (length preserved) so the redacted file still binds — binary
          formats (PDF / Office / images) are NOT supported.
        </p>
      </div>

      {/* Text preview + selection-to-range */}
      {hook.fileName && hook.fileText !== null && (
        <div style={{ marginTop: "0.85rem" }}>
          <div style={{ fontSize: "0.62rem", color: `${purple}0.6)`, letterSpacing: "0.08em", marginBottom: "0.3rem" }}>
            PREVIEW — select text, then “Add selection”
          </div>
          <textarea
            ref={previewRef}
            readOnly
            aria-label="Document preview"
            value={hook.fileText}
            style={{
              width: "100%",
              minHeight: "9rem",
              resize: "vertical",
              fontFamily: "'DM Mono', monospace",
              fontSize: "0.68rem",
              lineHeight: 1.5,
              color: accent,
              background: "rgba(0,0,0,0.25)",
              border: `1px solid ${purple}0.25)`,
              borderRadius: "6px",
              padding: "0.6rem",
              whiteSpace: "pre",
              overflow: "auto",
            }}
          />
          <button
            type="button"
            className={skin.classes.buttonSecondary}
            onClick={addSelection}
            disabled={busy}
            style={{ marginTop: "0.4rem", fontSize: "0.7rem" }}
          >
            ADD_SELECTION
          </button>
        </div>
      )}

      {hook.fileName && hook.fileText === null && (
        <p className="err-text" style={{ marginTop: "0.6rem", fontSize: "0.7rem" }}>
          File is not valid UTF-8 text — no preview. You can still add byte ranges
          manually, but blanking bytes will corrupt non-text formats.
        </p>
      )}

      {/* Manual range entry */}
      {hook.fileName && (
        <div style={{ marginTop: "0.7rem", display: "flex", gap: "0.4rem", alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ fontSize: "0.62rem", color: `${purple}0.6)` }}>RANGE</span>
          <input
            type="number"
            min={0}
            placeholder="start"
            value={manualStart}
            onChange={(e) => setManualStart(e.target.value)}
            aria-label="Range start byte"
            style={rangeInput(purple, accent)}
          />
          <input
            type="number"
            min={0}
            placeholder="end"
            value={manualEnd}
            onChange={(e) => setManualEnd(e.target.value)}
            aria-label="Range end byte"
            style={rangeInput(purple, accent)}
          />
          <button
            type="button"
            className={skin.classes.buttonSecondary}
            onClick={addManual}
            disabled={busy || manualStart === "" || manualEnd === ""}
            style={{ fontSize: "0.7rem" }}
          >
            ADD_RANGE
          </button>
        </div>
      )}

      {/* Pending ranges + chunk preview */}
      {hook.ranges.length > 0 && (
        <div style={{ marginTop: "0.8rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.35rem" }}>
            <span style={{ fontSize: "0.62rem", color: `${purple}0.6)`, letterSpacing: "0.08em" }}>
              REDACTED_RANGES ({hook.ranges.length})
            </span>
            <button
              type="button"
              onClick={hook.clearRanges}
              disabled={busy}
              style={{ background: "none", border: "none", color: `${purple}0.6)`, cursor: "pointer", fontSize: "0.62rem" }}
            >
              clear all
            </button>
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.3rem" }}>
            {hook.ranges.map((r, i) => (
              <span
                key={`${r.start}-${r.end}-${i}`}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "0.3rem",
                  fontSize: "0.66rem",
                  color: accent,
                  border: `1px solid ${purple}0.4)`,
                  borderRadius: "4px",
                  padding: "0.1rem 0.4rem",
                }}
              >
                [{r.start}, {r.end})
                <button
                  type="button"
                  aria-label={`Remove range ${r.start} to ${r.end}`}
                  onClick={() => hook.removeRange(i)}
                  disabled={busy}
                  style={{ background: "none", border: "none", color: "#ff7676", cursor: "pointer", fontSize: "0.8rem", lineHeight: 1 }}
                >
                  ×
                </button>
              </span>
            ))}
          </div>

          {/* 16-chunk preview strip */}
          <div style={{ marginTop: "0.55rem" }}>
            <div style={{ fontSize: "0.6rem", color: `${purple}0.55)`, marginBottom: "0.25rem" }}>
              CHUNK_PREVIEW — {hiddenChunks}/16 hidden (whole-chunk granularity)
            </div>
            <div style={{ display: "flex", gap: "2px" }}>
              {hook.previewMask.map((m, i) => (
                <span
                  key={i}
                  title={`chunk ${i}: ${m === 0 ? "hidden" : "revealed"}`}
                  style={{
                    flex: 1,
                    height: "0.7rem",
                    borderRadius: "2px",
                    background: m === 0 ? "#ff5050" : `${purple}0.45)`,
                  }}
                />
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Recipient + fill */}
      {hook.fileName && (
        <div style={{ marginTop: "0.85rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <label style={{ flex: "1 1 14rem", minWidth: 0 }}>
            <span style={{ display: "block", fontSize: "0.62rem", color: `${purple}0.6)`, marginBottom: "0.2rem" }}>
              RECIPIENT_ID (field element, decimal)
            </span>
            <input
              type="text"
              value={hook.recipientId}
              onChange={(e) => hook.setRecipientId(e.target.value)}
              placeholder="recipient BJJ pubkey X"
              aria-label="Recipient ID"
              style={{ ...rangeInput(purple, accent), width: "100%" }}
            />
          </label>
          <label style={{ flex: "0 0 8rem" }}>
            <span style={{ display: "block", fontSize: "0.62rem", color: `${purple}0.6)`, marginBottom: "0.2rem" }}>
              FILL (0–255, opt)
            </span>
            <input
              type="number"
              min={0}
              max={255}
              value={hook.fill}
              onChange={(e) => hook.setFill(e.target.value)}
              placeholder="0"
              aria-label="Fill byte"
              style={{ ...rangeInput(purple, accent), width: "100%" }}
            />
          </label>
        </div>
      )}

      {hook.error && (
        <p className="err-text" style={{ marginTop: "0.6rem" }}>
          {hook.error}
        </p>
      )}

      {/* Result */}
      {hook.stage === "done" && hook.result && (
        <div
          className={skin.classes.panel}
          style={{
            marginTop: "0.85rem",
            padding: "0.8rem 1rem",
            borderColor: `${purple}0.55)`,
            background: `${purple}0.04)`,
          }}
        >
          <div style={{ color: accent, letterSpacing: "0.1em", marginBottom: "0.5rem", fontSize: "0.82rem" }}>
            ✓ REDACTED — bundle issued
          </div>
          <div style={{ fontSize: "0.66rem", color: `${purple}0.7)`, display: "grid", gridTemplateColumns: "9rem 1fr", gap: "0.3rem 0.5rem" }}>
            <span>content_hash</span>
            <code style={{ color: accent }} title={hook.result.bundle.contentHash}>
              {short(hook.result.bundle.contentHash)}
            </code>
            <span>original_root</span>
            <code style={{ color: accent }} title={hook.result.bundle.originalRoot}>
              {short(hook.result.bundle.originalRoot)}
            </code>
            <span>chunks_hidden</span>
            <code style={{ color: accent }}>
              {hook.result.bundle.revealMask.filter((m) => m === 0).length}/16
            </code>
          </div>
          <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.7rem", flexWrap: "wrap" }}>
            <button type="button" className={skin.classes.buttonPrimary} onClick={hook.downloadRedacted} style={{ flex: 1 }}>
              DOWNLOAD_REDACTED_FILE
            </button>
            <button type="button" className={skin.classes.buttonPrimary} onClick={hook.downloadBundle} style={{ flex: 1 }}>
              DOWNLOAD_BUNDLE.json
            </button>
          </div>
        </div>
      )}

      <input
        ref={fileRef}
        type="file"
        style={{ display: "none" }}
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) void hook.onFile(f);
          e.target.value = "";
        }}
      />

      <div style={{ display: "flex", gap: "0.6rem", marginTop: "0.9rem" }}>
        <button
          type="button"
          className={skin.classes.buttonPrimary}
          onClick={() => void hook.redact()}
          disabled={busy || !hook.fileName || hook.ranges.length === 0}
          style={{ flex: 1 }}
        >
          {busy ? "REDACTING..." : "REDACT_DOCUMENT"}
        </button>
        <button
          type="button"
          className={skin.classes.buttonSecondary}
          onClick={hook.reset}
          disabled={busy || hook.stage === "idle"}
          style={{ flex: "0 0 8rem" }}
        >
          RESET
        </button>
      </div>
    </div>
  );
}

function rangeInput(purple: string, accent: string): React.CSSProperties {
  return {
    width: "5.5rem",
    fontFamily: "'DM Mono', monospace",
    fontSize: "0.7rem",
    color: accent,
    background: "rgba(0,0,0,0.25)",
    border: `1px solid ${purple}0.3)`,
    borderRadius: "4px",
    padding: "0.3rem 0.4rem",
  };
}
