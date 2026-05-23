/**
 * AuditProofTab — bundle-only ZK proof audit.
 *
 * Drop a Groth16 proof bundle JSON (or paste it) and execute server-side
 * verification against the embedded vkey for the named circuit.  No file
 * needed — the bundle's public signals fully determine validity.
 *
 * Handles all three circuits the backend exposes today:
 *   - document_existence
 *   - non_existence
 *   - redaction_validity  (when the proof comes from elsewhere; the
 *                         redaction tab is the file-binding flow)
 */
import { useCallback, useRef, useState } from "react";
import { useSkin } from "../skins/SkinContext";
import type { AuditStage } from "../hooks/useAuditProof";
import type { ZkCircuit, ZkVerifyResponse } from "../lib/api";

interface AuditProofTabProps {
  stage: AuditStage;
  bundleName: string | null;
  parsed: {
    circuit: ZkCircuit;
    proofJson: string;
    publicSignals: string[];
  } | null;
  result: ZkVerifyResponse | null;
  error: string | null;
  onBundleFile: (file: File) => void;
  onBundleText: (text: string) => void;
  onAudit: () => void;
  onReset: () => void;
}

const SIGNAL_LABELS: Record<ZkCircuit, string[]> = {
  document_existence: ["root", "leaf", "leafIndex", "treeSize"],
  non_existence: ["root", "keyDigest"],
  redaction_validity: [
    "nullifier",
    "originalRoot",
    "redactedCommitment",
    "revealedCount",
  ],
};

function shortSignal(s: string): string {
  if (s.length <= 18) return s;
  return `${s.slice(0, 9)}…${s.slice(-6)}`;
}

export default function AuditProofTab({
  stage,
  bundleName,
  parsed,
  result,
  error,
  onBundleFile,
  onBundleText,
  onAudit,
  onReset,
}: AuditProofTabProps) {
  const { skin } = useSkin();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(true);
  }, []);
  const onDragLeave = useCallback((e: React.DragEvent) => {
    if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
      setDragging(false);
    }
  }, []);
  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) onBundleFile(file);
    },
    [onBundleFile],
  );

  const onInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) onBundleFile(file);
      e.target.value = "";
    },
    [onBundleFile],
  );

  const isVerifying = stage === "verifying";
  const canAudit = stage === "ready" || stage === "done";

  const labels = parsed ? SIGNAL_LABELS[parsed.circuit] : [];

  return (
    <div>
      <div
        role="region"
        aria-label="Drop ZK proof bundle here"
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        style={{
          border: `2px dashed ${dragging ? "rgba(0,255,128,0.8)" : "rgba(0,255,128,0.3)"}`,
          borderRadius: "8px",
          padding: "1.25rem 1rem",
          background: dragging ? "rgba(0,255,128,0.05)" : "transparent",
          transition: "border-color 0.15s, background 0.15s",
          fontFamily: "'DM Mono', monospace",
          fontSize: "0.75rem",
        }}
      >
        <p
          style={{
            margin: "0 0 0.75rem",
            color: "rgba(0,255,128,0.5)",
            textAlign: "center",
            letterSpacing: "0.06em",
          }}
        >
          {dragging ? "RELEASE_TO_LOAD" : "DROP_PROOF_BUNDLE.json HERE  —  or click to browse"}
        </p>

        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          disabled={isVerifying}
          style={{
            display: "block",
            width: "100%",
            border: "1px dashed rgba(0,255,128,0.25)",
            background: bundleName ? "rgba(0,255,128,0.04)" : "transparent",
            borderColor: bundleName ? "rgba(0,255,128,0.55)" : "rgba(0,255,128,0.2)",
            borderRadius: "6px",
            padding: "1rem 0.75rem",
            textAlign: "center",
            cursor: isVerifying ? "default" : "pointer",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.75rem",
            color: bundleName ? "#00ff80" : "rgba(0,255,128,0.35)",
            wordBreak: "break-all",
          }}
        >
          <span aria-hidden style={{ fontSize: "1.5rem", display: "block", marginBottom: "0.3rem", opacity: 0.7 }}>
            🔐
          </span>
          <span style={{ display: "block", color: "rgba(0,255,128,0.6)", marginBottom: "0.25rem" }}>
            PROOF BUNDLE
          </span>
          {bundleName ?? "click or drop .json"}
        </button>

        {parsed && (
          <div
            style={{
              marginTop: "0.75rem",
              fontSize: "0.7rem",
              color: "rgba(0,255,128,0.7)",
              textAlign: "center",
            }}
          >
            CIRCUIT_<strong>{parsed.circuit.toUpperCase()}</strong>
            {" · "}
            {parsed.publicSignals.length} PUBLIC_SIGNALS
          </div>
        )}
      </div>

      <details style={{ marginTop: "0.75rem" }}>
        <summary
          style={{
            cursor: "pointer",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.7rem",
            color: "rgba(0,255,128,0.5)",
            letterSpacing: "0.06em",
          }}
        >
          PASTE_RAW_JSON
        </summary>
        <textarea
          placeholder='{"circuit":"document_existence","proof_json":"…","public_signals":["…"]}'
          onChange={(e) => onBundleText(e.target.value)}
          rows={6}
          style={{
            marginTop: "0.5rem",
            width: "100%",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.72rem",
            background: "rgba(0,0,0,0.4)",
            color: "#00ff80",
            border: "1px solid rgba(0,255,128,0.25)",
            borderRadius: "4px",
            padding: "0.5rem 0.6rem",
          }}
        />
      </details>

      {error && (
        <p className="err-text" style={{ marginTop: "0.5rem" }}>
          {error}
        </p>
      )}

      {result && (
        <div
          className={skin.classes.panel}
          style={{
            marginTop: "0.75rem",
            padding: "0.8rem 1rem",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.78rem",
            borderColor: result.valid
              ? "rgba(0,255,128,0.55)"
              : "rgba(255,80,80,0.45)",
            background: result.valid
              ? "rgba(0,255,128,0.04)"
              : "rgba(255,80,80,0.04)",
          }}
        >
          <div
            style={{
              fontSize: "0.85rem",
              letterSpacing: "0.1em",
              color: result.valid ? "#00ff80" : "#ff5050",
              marginBottom: "0.5rem",
            }}
          >
            {result.valid ? "✓ ZK_PROOF_VALID" : "✗ ZK_PROOF_INVALID"}
          </div>
          <div style={{ color: "rgba(0,255,128,0.7)", marginBottom: "0.5rem" }}>
            CIRCUIT: {result.circuit}
          </div>
          {parsed && parsed.publicSignals.length > 0 && (
            <div style={{ marginTop: "0.5rem" }}>
              <div
                style={{
                  fontSize: "0.65rem",
                  color: "rgba(0,255,128,0.5)",
                  letterSpacing: "0.08em",
                  marginBottom: "0.3rem",
                }}
              >
                PUBLIC_SIGNALS
              </div>
              {parsed.publicSignals.map((sig, i) => (
                <div
                  key={i}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "9rem 1fr",
                    gap: "0.5rem",
                    fontSize: "0.7rem",
                    padding: "0.15rem 0",
                  }}
                >
                  <code style={{ color: "rgba(0,255,128,0.55)" }}>
                    [{i}] {labels[i] ?? "signal"}
                  </code>
                  <code style={{ color: "#00ff80", wordBreak: "break-all" }} title={sig}>
                    {shortSignal(sig)}
                  </code>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <input
        ref={fileInputRef}
        type="file"
        accept="application/json,.json"
        style={{ display: "none" }}
        onChange={onInputChange}
      />

      <div style={{ display: "flex", gap: "0.6rem", marginTop: "0.9rem" }}>
        <button
          type="button"
          className={skin.classes.buttonPrimary}
          onClick={onAudit}
          disabled={isVerifying || !canAudit}
          style={{ flex: 1 }}
        >
          {isVerifying ? "VERIFYING_ZK..." : "AUDIT_BUNDLE"}
        </button>
        <button
          type="button"
          className={skin.classes.buttonSecondary}
          onClick={onReset}
          disabled={isVerifying || stage === "idle"}
          style={{ flex: "0 0 8rem" }}
        >
          RESET
        </button>
      </div>
    </div>
  );
}
