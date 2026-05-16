/**
 * ProofTab — ZK proof verification tab.
 *
 * Primary path: drag-and-drop a document file + a proof bundle JSON.
 * Fallback:     paste the proof bundle JSON manually (toggled via button).
 *
 * The drop zone auto-classifies dropped files:
 *   - .json / application/json  → proof bundle slot
 *   - anything else             → document slot (BLAKE3-hashed in-browser)
 */

import { useState } from "react";
import { useSkin } from "../skins/SkinContext";
import { EXAMPLE_PROOF } from "../lib/constants";
import ZkDropZone from "../components/ZkDropZone";
import type { ZkDropStage } from "../hooks/useZkDrop";

interface ProofTabProps {
  // Drop-zone path (useZkDrop)
  zkStage: ZkDropStage;
  fileName: string | null;
  fileProgress: number;
  proofFileName: string | null;
  hashMatch: boolean | null;
  zkError: string | null;
  onFiles: (files: File[]) => void;
  onDocumentFile: (file: File) => void;
  onProofFile: (file: File) => void;
  onProofText: (text: string) => void;
  onVerify: () => void;

  // Legacy JSON-paste path (useProofVerification — kept for power users)
  proofInput: string;
  setProofInput: (v: string) => void;
  proofError: string | null;
  isPending: boolean;
  onSubmitJson: () => void;
}

export default function ProofTab({
  zkStage,
  fileName,
  fileProgress,
  proofFileName,
  hashMatch,
  zkError,
  onFiles,
  onDocumentFile,
  onProofFile,
  onProofText,
  onVerify,
  proofInput,
  setProofInput,
  proofError,
  isPending,
  onSubmitJson,
}: ProofTabProps) {
  const { skin } = useSkin();
  const [showPaste, setShowPaste] = useState(false);

  const isHashing = zkStage === "hashing";
  const isVerifying = zkStage === "verifying";
  const canVerify = zkStage === "ready" || zkStage === "done";
  const busy = isHashing || isVerifying || isPending;

  return (
    <div>
      <ZkDropZone
        stage={zkStage}
        fileName={fileName}
        fileProgress={fileProgress}
        proofFileName={proofFileName}
        hashMatch={hashMatch}
        error={zkError}
        onFiles={onFiles}
        onDocumentFile={onDocumentFile}
        onProofFile={onProofFile}
      />

      {/* Verify button for the drop-zone path */}
      <button
        type="button"
        className={skin.classes.buttonPrimary}
        onClick={onVerify}
        disabled={busy || !canVerify}
        style={{ marginTop: "0.9rem", width: "100%" }}
      >
        {isVerifying
          ? "EXECUTING..."
          : isHashing
            ? "HASHING..."
            : "EXECUTE_VERIFICATION"}
      </button>

      {/* ── Paste JSON toggle ─────────────────────────────────────────────── */}
      <div
        style={{
          marginTop: "1.1rem",
          borderTop: "1px solid rgba(0,255,128,0.12)",
          paddingTop: "0.85rem",
        }}
      >
        <button
          type="button"
          className={skin.classes.buttonSecondary}
          onClick={() => setShowPaste((v) => !v)}
          style={{ fontSize: "0.72rem", letterSpacing: "0.05em" }}
        >
          {showPaste ? "▲ HIDE_JSON_INPUT" : "▼ PASTE_JSON_INSTEAD"}
        </button>

        {showPaste && (
          <div style={{ marginTop: "0.75rem" }}>
            <label htmlFor="proof-input" className="terminal-label">
              Proof bundle JSON
            </label>
            <textarea
              id="proof-input"
              value={proofInput}
              onChange={(e) => {
                setProofInput(e.target.value);
                // Keep the drop-zone proof slot in sync so the hash-match
                // badge updates live as the user types.
                onProofText(e.target.value);
              }}
              rows={8}
              placeholder='{"content_hash":"...","merkle_root":"...","merkle_proof":{}}'
              spellCheck={false}
              className={skin.classes.input}
              style={{ resize: "vertical" }}
            />
            <div className="quick-actions">
              <button
                type="button"
                className={skin.classes.buttonSecondary}
                onClick={() => {
                  const sample = JSON.stringify(EXAMPLE_PROOF, null, 2);
                  setProofInput(sample);
                  onProofText(sample);
                }}
              >
                SAMPLE
              </button>
              <button
                type="button"
                className={skin.classes.buttonSecondary}
                onClick={() => {
                  setProofInput("");
                  onProofText("");
                }}
              >
                CLEAR
              </button>
            </div>
            <button
              type="button"
              className={skin.classes.buttonPrimary}
              onClick={onSubmitJson}
              disabled={busy || !proofInput.trim()}
              style={{ marginTop: "0.75rem" }}
            >
              {isPending ? "EXECUTING..." : "EXECUTE_VERIFICATION"}
            </button>
            {proofError && <p className="err-text">{proofError}</p>}
          </div>
        )}
      </div>
    </div>
  );
}
