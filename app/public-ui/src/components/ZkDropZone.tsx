/**
 * ZkDropZone — drag-and-drop target for ZK proof verification.
 *
 * Renders two named slots (document + proof bundle) inside a single combined
 * drop zone.  Files are auto-classified on drop:
 *   - .json / application/json  → proof bundle slot
 *   - anything else             → document slot
 *
 * Each slot also has its own click-to-browse button for accessibility.
 * Styling reuses the project's terminal/monospace token set.
 */

import { useCallback, useRef, useState } from "react";
import { useSkin } from "../skins/SkinContext";
import type { ZkDropStage } from "../hooks/useZkDrop";

interface ZkDropZoneProps {
  stage: ZkDropStage;
  fileName: string | null;
  fileProgress: number;
  proofFileName: string | null;
  hashMatch: boolean | null;
  error: string | null;
  onFiles: (files: File[]) => void;
  onDocumentFile: (file: File) => void;
  onProofFile: (file: File) => void;
}

function SlotIcon({ type }: { type: "doc" | "proof" }) {
  return (
    <span
      aria-hidden
      style={{
        fontSize: "1.5rem",
        display: "block",
        marginBottom: "0.3rem",
        opacity: 0.7,
      }}
    >
      {type === "doc" ? "📄" : "🔐"}
    </span>
  );
}

function HashMatchBadge({ match }: { match: boolean | null }) {
  if (match === null) return null;
  return (
    <span
      style={{
        display: "inline-block",
        marginTop: "0.5rem",
        fontSize: "0.72rem",
        fontFamily: "'DM Mono', monospace",
        padding: "0.15rem 0.5rem",
        borderRadius: "3px",
        background: match ? "rgba(0,255,128,0.12)" : "rgba(255,80,80,0.15)",
        color: match ? "#00ff80" : "#ff5050",
        border: `1px solid ${match ? "rgba(0,255,128,0.3)" : "rgba(255,80,80,0.35)"}`,
      }}
    >
      {match ? "✓ HASH_MATCH" : "✗ HASH_MISMATCH — file differs from proof"}
    </span>
  );
}

export default function ZkDropZone({
  stage,
  fileName,
  fileProgress,
  proofFileName,
  hashMatch,
  error,
  onFiles,
  onDocumentFile,
  onProofFile,
}: ZkDropZoneProps) {
  const { skin } = useSkin();
  const [dragging, setDragging] = useState(false);
  const docInputRef = useRef<HTMLInputElement>(null);
  const proofInputRef = useRef<HTMLInputElement>(null);

  // ── Drag handlers on the combined outer zone ───────────────────────────────

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(true);
  }, []);

  const onDragLeave = useCallback((e: React.DragEvent) => {
    // Only clear when the pointer leaves the outer element entirely.
    if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
      setDragging(false);
    }
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const files = Array.from(e.dataTransfer.files);
      if (files.length > 0) onFiles(files);
    },
    [onFiles],
  );

  // ── Individual slot file-input change handlers ─────────────────────────────

  const onDocInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) onDocumentFile(file);
      e.target.value = "";
    },
    [onDocumentFile],
  );

  const onProofInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) onProofFile(file);
      e.target.value = "";
    },
    [onProofFile],
  );

  const isHashing = stage === "hashing";
  const isVerifying = stage === "verifying";
  const busy = isHashing || isVerifying;

  // ── Slot fill status ───────────────────────────────────────────────────────

  const docFilled = !!fileName;
  const proofFilled = !!proofFileName;

  const slotBase: React.CSSProperties = {
    flex: "1 1 0",
    minWidth: 0,
    border: "1px dashed rgba(0,255,128,0.25)",
    borderRadius: "6px",
    padding: "1rem 0.75rem",
    textAlign: "center",
    cursor: busy ? "default" : "pointer",
    transition: "border-color 0.15s, background 0.15s",
    fontFamily: "'DM Mono', monospace",
    fontSize: "0.75rem",
  };

  const slotFilled: React.CSSProperties = {
    ...slotBase,
    borderColor: "rgba(0,255,128,0.55)",
    background: "rgba(0,255,128,0.04)",
  };

  const slotEmpty: React.CSSProperties = {
    ...slotBase,
    borderColor: "rgba(0,255,128,0.2)",
  };

  return (
    <div>
      {/* Combined outer drop zone */}
      <div
        role="region"
        aria-label="Drop document and proof bundle here"
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        style={{
          border: `2px dashed ${dragging ? "rgba(0,255,128,0.8)" : "rgba(0,255,128,0.3)"}`,
          borderRadius: "8px",
          padding: "1.25rem 1rem",
          background: dragging ? "rgba(0,255,128,0.05)" : "transparent",
          transition: "border-color 0.15s, background 0.15s",
        }}
      >
        <p
          style={{
            margin: "0 0 0.75rem",
            fontSize: "0.72rem",
            fontFamily: "'DM Mono', monospace",
            color: "rgba(0,255,128,0.5)",
            textAlign: "center",
            letterSpacing: "0.06em",
          }}
        >
          {dragging ? "RELEASE_TO_LOAD" : "DROP_FILE + PROOF.json HERE  —  or click a slot below"}
        </p>

        {/* Two-slot row */}
        <div style={{ display: "flex", gap: "0.75rem" }}>

          {/* Document slot */}
          <button
            type="button"
            style={docFilled ? slotFilled : slotEmpty}
            disabled={busy}
            aria-label="Select document file"
            onClick={() => docInputRef.current?.click()}
          >
            <SlotIcon type="doc" />
            <span style={{ display: "block", color: "rgba(0,255,128,0.6)", marginBottom: "0.25rem" }}>
              DOCUMENT
            </span>
            {docFilled ? (
              <>
                <span style={{ display: "block", color: "#00ff80", wordBreak: "break-all" }}>
                  {fileName}
                </span>
                {isHashing && (
                  <span style={{ display: "block", marginTop: "0.35rem", color: "rgba(0,255,128,0.5)" }}>
                    hashing… {fileProgress}%
                  </span>
                )}
                {!isHashing && fileProgress === 100 && (
                  <span style={{ display: "block", marginTop: "0.35rem", color: "#00ff80" }}>
                    ✓ hashed
                  </span>
                )}
              </>
            ) : (
              <span style={{ color: "rgba(0,255,128,0.35)" }}>
                click or drop any file
              </span>
            )}
          </button>

          {/* Proof JSON slot */}
          <button
            type="button"
            style={proofFilled ? slotFilled : slotEmpty}
            disabled={busy}
            aria-label="Select proof bundle JSON"
            onClick={() => proofInputRef.current?.click()}
          >
            <SlotIcon type="proof" />
            <span style={{ display: "block", color: "rgba(0,255,128,0.6)", marginBottom: "0.25rem" }}>
              PROOF BUNDLE
            </span>
            {proofFilled ? (
              <span style={{ display: "block", color: "#00ff80", wordBreak: "break-all" }}>
                {proofFileName}
              </span>
            ) : (
              <span style={{ color: "rgba(0,255,128,0.35)" }}>
                click or drop .json
              </span>
            )}
          </button>

        </div>

        {/* Hash match badge */}
        {hashMatch !== null && (
          <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
            <HashMatchBadge match={hashMatch} />
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <p className="err-text" style={{ marginTop: "0.5rem" }}>
          {error}
        </p>
      )}

      {/* Hidden file inputs */}
      <input
        ref={docInputRef}
        type="file"
        style={{ display: "none" }}
        onChange={onDocInputChange}
      />
      <input
        ref={proofInputRef}
        type="file"
        accept="application/json,.json"
        style={{ display: "none" }}
        onChange={onProofInputChange}
      />

      {/* Mismatch warning (verbose) */}
      {hashMatch === false && (
        <div
          className={skin.classes.panel}
          style={{
            marginTop: "0.75rem",
            padding: "0.65rem 0.9rem",
            fontSize: "0.75rem",
            fontFamily: "'DM Mono', monospace",
            color: "#ff9966",
            borderColor: "rgba(255,80,80,0.3)",
          }}
        >
          <strong>HASH_MISMATCH</strong> — the dropped file's BLAKE3 digest
          does not match the content_hash in the proof bundle.  The server
          will verify using the <em>computed</em> file hash; the result may
          show <code>content_hash_matches_proof: false</code>.  Drop the
          correct file or use the JSON textarea to adjust the bundle manually.
        </div>
      )}
    </div>
  );
}
