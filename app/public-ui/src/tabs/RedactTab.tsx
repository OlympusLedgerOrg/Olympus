/**
 * RedactTab — producer side of object-level redaction (issuer view, ADR-0026).
 *
 * Workflow:
 *   1. Load the ORIGINAL (already-committed) PDF.
 *   2. Its committed object manifest is fetched automatically
 *      (GET /redaction/manifest/{content_hash}); check the indirect objects to
 *      hide from the listing.
 *   3. Set the recipient ID, then REDACT.
 *   4. Download the redacted artifact and the `redaction_validity` bundle and
 *      hand both to the recipient, who audits them in the REDACTION tab.
 *
 * Redaction is per-object: selected objects are zero-filled in place so the
 * non-redacted objects stay byte-identical and the artifact still binds to the
 * committed original. (UI matches the design handoff prototype "RedactTab —
 * Object Port".)
 */
import { useCallback, useRef, useState } from "react";
import { useSkin } from "../skins/SkinContext";
import type { useRedactionCreate } from "../hooks/useRedactionCreate";

type Hook = ReturnType<typeof useRedactionCreate>;

interface RedactTabProps {
  hook: Hook;
}

/** Truncate a long hex/decimal string to `head…tail` for compact display. */
function short(s: string): string {
  if (s.length <= 18) return s;
  return `${s.slice(0, 9)}…${s.slice(-6)}`;
}

export default function RedactTab({ hook }: RedactTabProps) {
  const { skin } = useSkin();
  const fileRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  const busy = hook.stage === "redacting" || hook.stage === "loading_manifest";

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const f = e.dataTransfer.files?.[0];
      if (f) void hook.onFile(f);
    },
    [hook],
  );

  const purple = "rgba(168,85,247,";
  const accent = "#c084fc";

  const objects = hook.manifest?.objects ?? [];
  const objectCount = hook.manifest?.objectCount ?? 0;
  const selectedCount = hook.selectedIds.length;
  // Largest object's span — used to scale the proportional size bars.
  const maxByteLength = objects.reduce((m, o) => Math.max(m, o.byteLength), 0);

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
            ORIGINAL_PDF
          </span>
          {hook.fileName ? (
            <span style={{ color: accent, wordBreak: "break-all" }}>
              {hook.fileName} · {hook.fileSize} bytes
            </span>
          ) : (
            <span style={{ color: `${purple}0.45)` }}>click or drop the committed PDF</span>
          )}
        </button>
        <p style={{ margin: "0.6rem 0 0", fontSize: "0.6rem", color: `${purple}0.45)`, textAlign: "center" }}>
          The original PDF must already be committed on the ledger. Selected
          indirect objects are zero-filled in place (length + offsets preserved)
          so the non-redacted objects stay byte-identical and the artifact still
          binds.
        </p>
      </div>

      {hook.stage === "loading_manifest" && (
        <p style={{ marginTop: "0.7rem", fontSize: "0.7rem", color: `${purple}0.6)` }}>
          Loading object manifest…
        </p>
      )}

      {/* Manifest header */}
      {hook.manifest && (
        <div
          style={{
            marginTop: "0.85rem",
            fontSize: "0.64rem",
            color: `${purple}0.7)`,
            display: "grid",
            gridTemplateColumns: "8.5rem 1fr",
            gap: "0.25rem 0.5rem",
          }}
        >
          <span>content_hash</span>
          <code style={{ color: accent }} title={hook.contentHash ?? undefined}>
            {hook.contentHash ? short(hook.contentHash) : "-"}
          </code>
          <span>original_root</span>
          <code style={{ color: accent }} title={hook.manifest.originalRoot}>
            {short(hook.manifest.originalRoot)}
          </code>
          <span>objects</span>
          <code style={{ color: accent }}>{objectCount}</code>
        </div>
      )}

      {/* Object checklist */}
      {hook.manifest && objects.length > 0 && (
        <div style={{ marginTop: "0.85rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.35rem" }}>
            <span style={{ fontSize: "0.62rem", color: `${purple}0.6)`, letterSpacing: "0.08em" }}>
              OBJECTS — check to hide ({selectedCount}/{objectCount} hidden)
            </span>
            {selectedCount > 0 && (
              <button
                type="button"
                onClick={hook.clearSelection}
                disabled={busy}
                style={{ background: "none", border: "none", color: `${purple}0.6)`, cursor: "pointer", fontSize: "0.62rem" }}
              >
                clear all
              </button>
            )}
          </div>
          <div
            style={{
              maxHeight: "16rem",
              overflowY: "auto",
              border: `1px solid ${purple}0.25)`,
              borderRadius: "6px",
              background: "rgba(0,0,0,0.25)",
            }}
          >
            {objects.map((o) => {
              const checked = hook.selectedIds.includes(o.segmentId);
              const widthPct = maxByteLength > 0 ? Math.max(4, (o.byteLength / maxByteLength) * 100) : 0;
              return (
                <label
                  key={o.segmentId}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "0.5rem",
                    padding: "0.4rem 0.6rem",
                    fontSize: "0.68rem",
                    color: checked ? "#ff8a8a" : accent,
                    borderBottom: `1px solid ${purple}0.12)`,
                    cursor: busy ? "default" : "pointer",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={busy}
                    onChange={() => hook.toggleId(o.segmentId)}
                    aria-label={`Hide object ${o.segmentId}`}
                  />
                  <span style={{ flex: "0 0 5rem" }}>#{o.segmentId}</span>
                  {/* Proportional size bar */}
                  <span
                    style={{
                      flex: 1,
                      height: "0.55rem",
                      borderRadius: "2px",
                      background: `${purple}0.12)`,
                      overflow: "hidden",
                    }}
                  >
                    <span
                      style={{
                        display: "block",
                        height: "100%",
                        width: `${widthPct}%`,
                        background: checked
                          ? "repeating-linear-gradient(45deg,#ff5050,#ff5050 3px,rgba(255,80,80,0.35) 3px,rgba(255,80,80,0.35) 6px)"
                          : `${purple}0.5)`,
                      }}
                    />
                  </span>
                  <span style={{ flex: "0 0 6rem", textAlign: "right", color: checked ? "#ff8a8a" : `${purple}0.7)` }}>
                    {o.byteLength} bytes
                  </span>
                </label>
              );
            })}
          </div>
        </div>
      )}

      {/* Recipient */}
      {hook.manifest && (
        <div style={{ marginTop: "0.85rem" }}>
          <label style={{ display: "block" }}>
            <span style={{ display: "block", fontSize: "0.62rem", color: `${purple}0.6)`, marginBottom: "0.2rem" }}>
              RECIPIENT_ID (field element, decimal)
            </span>
            <input
              type="text"
              value={hook.recipientId}
              onChange={(e) => hook.setRecipientId(e.target.value)}
              placeholder="recipient BJJ pubkey X"
              aria-label="Recipient ID"
              style={{ ...textInput(purple, accent), width: "100%" }}
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
            <span>objects_hidden</span>
            <code style={{ color: accent }}>
              {hook.result.bundle.redactedObjIds.length}/{objectCount}
            </code>
          </div>

          {/* Revealed segments + their published blindings */}
          {hook.result.bundle.revealedSegments.length > 0 && (
            <div style={{ marginTop: "0.6rem" }}>
              <div style={{ fontSize: "0.6rem", color: `${purple}0.55)`, letterSpacing: "0.06em", marginBottom: "0.25rem" }}>
                REVEALED_SEGMENTS ({hook.result.bundle.revealedSegments.length}) — id · blinding
              </div>
              <div style={{ maxHeight: "9rem", overflowY: "auto", border: `1px solid ${purple}0.2)`, borderRadius: "4px" }}>
                {hook.result.bundle.revealedSegments.map((s) => (
                  <div
                    key={s.segmentId}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "4rem 1fr",
                      gap: "0.5rem",
                      fontSize: "0.62rem",
                      padding: "0.2rem 0.5rem",
                    }}
                  >
                    <code style={{ color: `${purple}0.7)` }}>#{s.segmentId}</code>
                    <code style={{ color: accent, wordBreak: "break-all" }} title={s.blindingDecimal}>
                      {short(s.blindingDecimal)}
                    </code>
                  </div>
                ))}
              </div>
            </div>
          )}

          <p style={{ margin: "0.6rem 0 0", fontSize: "0.58rem", color: `${purple}0.5)`, lineHeight: 1.5 }}>
            The bundle's proof is verified server-side (POST /zk/verify) — that, not
            a client recompute, is authoritative for the recipient's audit.
          </p>

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
          disabled={busy || !hook.manifest || hook.selectedIds.length === 0}
          style={{ flex: 1 }}
        >
          {hook.stage === "redacting" ? "REDACTING..." : "REDACT_DOCUMENT"}
        </button>
        <button
          type="button"
          className={skin.classes.buttonSecondary}
          onClick={hook.reset}
          disabled={busy || (hook.stage === "idle" && !hook.fileName)}
          style={{ flex: "0 0 8rem" }}
        >
          RESET
        </button>
      </div>
    </div>
  );
}

/** Shared inline style for the recipient text input. */
function textInput(purple: string, accent: string): React.CSSProperties {
  return {
    fontFamily: "'DM Mono', monospace",
    fontSize: "0.7rem",
    color: accent,
    background: "rgba(0,0,0,0.25)",
    border: `1px solid ${purple}0.3)`,
    borderRadius: "4px",
    padding: "0.3rem 0.4rem",
    boxSizing: "border-box",
  };
}
