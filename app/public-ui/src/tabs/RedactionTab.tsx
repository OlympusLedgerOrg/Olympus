/**
 * RedactionTab — file + bundle audit for the redaction_validity circuit.
 *
 * Two slots:
 *   1. Redacted document file — BLAKE3-hashed in-browser so the operator can
 *      confirm they loaded the file they think they did, and IPC-forwarded
 *      to the Rust hot path for the file→commitment binding check.
 *   2. Redaction proof bundle JSON — parsed and sent to /zk/verify with
 *      circuit="redaction_validity".
 *
 * `bindingValid` is the second half of a real redaction audit: the Rust
 * path re-chunks the dropped file, applies the bundle's reveal_mask, and
 * recomputes `redactedCommitment`. Only when both proof-math AND binding
 * pass is the audit cryptographically meaningful.
 */
import { useCallback, useRef, useState } from "react";
import { useSkin } from "../skins/SkinContext";
import type { RedactionAuditStage } from "../hooks/useRedactionAudit";
import type { ZkVerifyResponse } from "../lib/api";

interface RedactionTabProps {
  stage: RedactionAuditStage;
  fileName: string | null;
  fileHash: string | null;
  fileProgress: number;
  bundleName: string | null;
  parsed: { publicSignals: string[] } | null;
  result: ZkVerifyResponse | null;
  bindingValid: boolean | null;
  error: string | null;
  onFile: (file: File) => void;
  onBundleFile: (file: File) => void;
  onAudit: () => void;
  onReset: () => void;
}

// 6-signal layout post-audit M-2. Older 4-signal bundles still render —
// the extra labels just go unused.
const REDACTION_SIGNAL_LABELS = [
  "nullifier",
  "originalRoot",
  "redactedCommitment",
  "revealedCount",
  "issuerAx",
  "issuerAy",
];

function short(s: string): string {
  if (s.length <= 18) return s;
  return `${s.slice(0, 9)}…${s.slice(-6)}`;
}

export default function RedactionTab({
  stage,
  fileName,
  fileHash,
  fileProgress,
  bundleName,
  parsed,
  result,
  bindingValid,
  error,
  onFile,
  onBundleFile,
  onAudit,
  onReset,
}: RedactionTabProps) {
  const { skin } = useSkin();
  const fileRef = useRef<HTMLInputElement>(null);
  const bundleRef = useRef<HTMLInputElement>(null);
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
      for (const file of Array.from(e.dataTransfer.files)) {
        if (file.type === "application/json" || file.name.endsWith(".json")) {
          onBundleFile(file);
        } else {
          onFile(file);
        }
      }
    },
    [onFile, onBundleFile],
  );

  const isHashing = stage === "hashing";
  const isVerifying = stage === "verifying";
  const busy = isHashing || isVerifying;
  const canAudit = stage === "ready" || stage === "done";

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
  const slotFilled = (filled: boolean): React.CSSProperties =>
    filled
      ? { ...slotBase, borderColor: "rgba(0,255,128,0.55)", background: "rgba(0,255,128,0.04)" }
      : { ...slotBase, borderColor: "rgba(0,255,128,0.2)" };

  return (
    <div>
      <div
        role="region"
        aria-label="Drop redacted file and redaction proof bundle here"
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        style={{
          border: `2px dashed ${dragging ? "rgba(168,85,247,0.7)" : "rgba(168,85,247,0.35)"}`,
          borderRadius: "8px",
          padding: "1.25rem 1rem",
          background: dragging ? "rgba(168,85,247,0.06)" : "transparent",
          transition: "border-color 0.15s, background 0.15s",
        }}
      >
        <p
          style={{
            margin: "0 0 0.75rem",
            fontSize: "0.72rem",
            fontFamily: "'DM Mono', monospace",
            color: "rgba(168,85,247,0.7)",
            textAlign: "center",
            letterSpacing: "0.06em",
          }}
        >
          {dragging
            ? "RELEASE_TO_LOAD"
            : "DROP_REDACTED_FILE + REDACTION_PROOF.json  —  or click a slot"}
        </p>

        <div style={{ display: "flex", gap: "0.75rem" }}>
          {/* Redacted file slot */}
          <button
            type="button"
            disabled={busy}
            onClick={() => fileRef.current?.click()}
            style={slotFilled(!!fileName)}
          >
            <span aria-hidden style={{ fontSize: "1.5rem", display: "block", marginBottom: "0.3rem", opacity: 0.7 }}>
              📄
            </span>
            <span style={{ display: "block", color: "rgba(168,85,247,0.75)", marginBottom: "0.25rem" }}>
              REDACTED_DOC
            </span>
            {fileName ? (
              <>
                <span style={{ display: "block", color: "#c084fc", wordBreak: "break-all" }}>
                  {fileName}
                </span>
                {isHashing && (
                  <span style={{ display: "block", marginTop: "0.35rem", color: "rgba(168,85,247,0.6)" }}>
                    hashing… {fileProgress}%
                  </span>
                )}
                {fileHash && (
                  <code
                    style={{
                      display: "block",
                      marginTop: "0.3rem",
                      fontSize: "0.62rem",
                      color: "rgba(168,85,247,0.55)",
                    }}
                    title={fileHash}
                  >
                    {short(fileHash)}
                  </code>
                )}
              </>
            ) : (
              <span style={{ color: "rgba(168,85,247,0.45)" }}>
                click or drop any file
              </span>
            )}
          </button>

          {/* Redaction proof bundle slot */}
          <button
            type="button"
            disabled={busy}
            onClick={() => bundleRef.current?.click()}
            style={slotFilled(!!bundleName)}
          >
            <span aria-hidden style={{ fontSize: "1.5rem", display: "block", marginBottom: "0.3rem", opacity: 0.7 }}>
              🔐
            </span>
            <span style={{ display: "block", color: "rgba(168,85,247,0.75)", marginBottom: "0.25rem" }}>
              REDACTION_PROOF
            </span>
            {bundleName ? (
              <span style={{ display: "block", color: "#c084fc", wordBreak: "break-all" }}>
                {bundleName}
              </span>
            ) : (
              <span style={{ color: "rgba(168,85,247,0.45)" }}>
                click or drop .json
              </span>
            )}
          </button>
        </div>

        <p
          style={{
            margin: "0.75rem 0 0",
            fontSize: "0.62rem",
            color: "rgba(168,85,247,0.45)",
            textAlign: "center",
            letterSpacing: "0.04em",
          }}
        >
          AUDIT — proof math (Groth16) is verified server-side; file→commitment
          binding is recomputed in the Rust hot path via Tauri IPC.
        </p>
      </div>

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
              ? "rgba(168,85,247,0.55)"
              : "rgba(255,80,80,0.45)",
            background: result.valid
              ? "rgba(168,85,247,0.04)"
              : "rgba(255,80,80,0.04)",
          }}
        >
          <div
            style={{
              fontSize: "0.85rem",
              letterSpacing: "0.1em",
              color: result.valid ? "#c084fc" : "#ff5050",
              marginBottom: "0.5rem",
            }}
          >
            {result.valid ? "✓ PROOF_MATH_VALID" : "✗ PROOF_MATH_INVALID"}
          </div>
          {result.valid && (
            <div
              style={{
                fontSize: "0.75rem",
                letterSpacing: "0.08em",
                color:
                  bindingValid === true
                    ? "#c084fc"
                    : bindingValid === false
                      ? "#ff5050"
                      : "rgba(168,85,247,0.55)",
                marginBottom: "0.5rem",
              }}
              title={
                bindingValid === true
                  ? "Re-derived the bundle's redactedCommitment from the dropped file. Desktop uses the Rust hot path via Tauri IPC; web auditor uses a JS implementation pinned to the Rust reference (redactionBinding.conformance.test.ts)."
                  : bindingValid === false
                    ? "Proof math passes but the dropped file does NOT produce the bundle's redactedCommitment — wrong file, tampered bundle, or mismatched reveal_mask."
                    : "File→commitment binding check did not run or could not complete."
              }
            >
              {bindingValid === true
                ? "✓ FILE_BINDS_TO_COMMITMENT"
                : bindingValid === false
                  ? "✗ FILE_DOES_NOT_BIND  —  proof is valid but for a DIFFERENT file"
                  : "⊘ FILE_BINDING_UNCHECKED"}
            </div>
          )}
          {parsed && (
            <div style={{ marginTop: "0.5rem" }}>
              <div
                style={{
                  fontSize: "0.65rem",
                  color: "rgba(168,85,247,0.6)",
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
                    gridTemplateColumns: "10rem 1fr",
                    gap: "0.5rem",
                    fontSize: "0.7rem",
                    padding: "0.15rem 0",
                  }}
                >
                  <code style={{ color: "rgba(168,85,247,0.65)" }}>
                    [{i}] {REDACTION_SIGNAL_LABELS[i] ?? "signal"}
                  </code>
                  <code style={{ color: "#c084fc", wordBreak: "break-all" }} title={sig}>
                    {short(sig)}
                  </code>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <input
        ref={fileRef}
        type="file"
        style={{ display: "none" }}
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) onFile(f);
          e.target.value = "";
        }}
      />
      <input
        ref={bundleRef}
        type="file"
        accept="application/json,.json"
        style={{ display: "none" }}
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) onBundleFile(f);
          e.target.value = "";
        }}
      />

      <div style={{ display: "flex", gap: "0.6rem", marginTop: "0.9rem" }}>
        <button
          type="button"
          className={skin.classes.buttonPrimary}
          onClick={onAudit}
          disabled={busy || !canAudit}
          style={{ flex: 1 }}
        >
          {isVerifying
            ? "VERIFYING_REDACTION..."
            : isHashing
              ? "HASHING_FILE..."
              : "AUDIT_REDACTION"}
        </button>
        <button
          type="button"
          className={skin.classes.buttonSecondary}
          onClick={onReset}
          disabled={busy || stage === "idle"}
          style={{ flex: "0 0 8rem" }}
        >
          RESET
        </button>
      </div>
    </div>
  );
}
