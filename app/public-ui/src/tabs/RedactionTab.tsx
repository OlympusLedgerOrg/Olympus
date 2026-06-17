/**
 * RedactionTab — in-app offline verifier for the ADR-0030 V3 signed-Merkle
 * redaction bundle.
 *
 * Three inputs:
 *   1. Redacted artifact file — BLAKE3-hashed in-browser so the operator can
 *      confirm they loaded the right file; its bytes drive revealed-segment
 *      reconstruction in the fold check.
 *   2. V3 bundle JSON — `{original_root, format, segment_count, recipient_id,
 *      segments, nullifier, signature_hex, ...}`.
 *   3. Issuer Ed25519 public key (hex) — the trust anchor the signature is
 *      checked against.
 *
 * AUDIT runs `verifyRedactionBundleV3` entirely client-side (no server, no
 * Tauri IPC): structural rules + canonical-form rejects + variable-depth fold
 * == original_root + Ed25519 signature + nullifier.
 */
import { useCallback, useRef, useState } from "react";
import { useSkin } from "../skins/SkinContext";
import type { RedactionAuditStage } from "../hooks/useRedactionAudit";
import type { V3Bundle } from "../lib/redactionBinding";

interface RedactionTabProps {
  stage: RedactionAuditStage;
  fileName: string | null;
  fileHash: string | null;
  fileProgress: number;
  bundleName: string | null;
  parsed: V3Bundle | null;
  issuerPubkeyHex: string;
  verified: boolean | null;
  verifyReason: string | null;
  error: string | null;
  onFile: (file: File) => void;
  onBundleFile: (file: File) => void;
  onIssuerPubkey: (hex: string) => void;
  onAudit: () => void;
  onReset: () => void;
}

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
  issuerPubkeyHex,
  verified,
  verifyReason,
  error,
  onFile,
  onBundleFile,
  onIssuerPubkey,
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
  const canAudit =
    (stage === "ready" || stage === "done") &&
    !!fileHash &&
    !!parsed &&
    issuerPubkeyHex.trim().length > 0;

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

  const purple = "rgba(168,85,247,";
  const accent = "#c084fc";

  return (
    <div>
      <div
        role="region"
        aria-label="Drop redacted file and redaction bundle here"
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        style={{
          border: `2px dashed ${dragging ? `${purple}0.7)` : `${purple}0.35)`}`,
          borderRadius: "8px",
          padding: "1.25rem 1rem",
          background: dragging ? `${purple}0.06)` : "transparent",
          transition: "border-color 0.15s, background 0.15s",
        }}
      >
        <p
          style={{
            margin: "0 0 0.75rem",
            fontSize: "0.72rem",
            fontFamily: "'DM Mono', monospace",
            color: `${purple}0.7)`,
            textAlign: "center",
            letterSpacing: "0.06em",
          }}
        >
          {dragging
            ? "RELEASE_TO_LOAD"
            : "DROP_REDACTED_FILE + REDACTION_BUNDLE.json  —  or click a slot"}
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
            <span style={{ display: "block", color: `${purple}0.75)`, marginBottom: "0.25rem" }}>
              REDACTED_DOC
            </span>
            {fileName ? (
              <>
                <span style={{ display: "block", color: accent, wordBreak: "break-all" }}>
                  {fileName}
                </span>
                {isHashing && (
                  <span style={{ display: "block", marginTop: "0.35rem", color: `${purple}0.6)` }}>
                    hashing… {fileProgress}%
                  </span>
                )}
                {fileHash && (
                  <code
                    style={{
                      display: "block",
                      marginTop: "0.3rem",
                      fontSize: "0.62rem",
                      color: `${purple}0.55)`,
                    }}
                    title={fileHash}
                  >
                    {short(fileHash)}
                  </code>
                )}
              </>
            ) : (
              <span style={{ color: `${purple}0.45)` }}>click or drop any file</span>
            )}
          </button>

          {/* Redaction bundle slot */}
          <button
            type="button"
            disabled={busy}
            onClick={() => bundleRef.current?.click()}
            style={slotFilled(!!bundleName)}
          >
            <span aria-hidden style={{ fontSize: "1.5rem", display: "block", marginBottom: "0.3rem", opacity: 0.7 }}>
              🔐
            </span>
            <span style={{ display: "block", color: `${purple}0.75)`, marginBottom: "0.25rem" }}>
              REDACTION_BUNDLE
            </span>
            {bundleName ? (
              <span style={{ display: "block", color: accent, wordBreak: "break-all" }}>
                {bundleName}
              </span>
            ) : (
              <span style={{ color: `${purple}0.45)` }}>click or drop .json</span>
            )}
          </button>
        </div>

        {/* Issuer Ed25519 pubkey (trust anchor) */}
        <div style={{ marginTop: "0.85rem" }}>
          <label style={{ display: "block" }}>
            <span style={{ display: "block", fontSize: "0.62rem", color: `${purple}0.6)`, marginBottom: "0.2rem" }}>
              ISSUER_ED25519_PUBKEY (hex)
            </span>
            <input
              type="text"
              value={issuerPubkeyHex}
              onChange={(e) => onIssuerPubkey(e.target.value)}
              placeholder="64-hex issuer verifying key"
              aria-label="Issuer Ed25519 public key"
              style={{
                fontFamily: "'DM Mono', monospace",
                fontSize: "0.7rem",
                color: accent,
                background: "rgba(0,0,0,0.25)",
                border: `1px solid ${purple}0.3)`,
                borderRadius: "4px",
                padding: "0.3rem 0.4rem",
                boxSizing: "border-box",
                width: "100%",
              }}
            />
          </label>
        </div>

        <p
          style={{
            margin: "0.75rem 0 0",
            fontSize: "0.62rem",
            color: `${purple}0.45)`,
            textAlign: "center",
            letterSpacing: "0.04em",
          }}
        >
          AUDIT runs entirely in-app (ADR-0030 V3): the variable-depth fold over
          the artifact, the Ed25519 issuer signature, and the nullifier are all
          checked locally — no server round-trip.
        </p>
      </div>

      {error && (
        <p className="err-text" style={{ marginTop: "0.5rem" }}>
          {error}
        </p>
      )}

      {stage === "done" && verified !== null && (
        <div
          className={skin.classes.panel}
          style={{
            marginTop: "0.75rem",
            padding: "0.8rem 1rem",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.78rem",
            borderColor: verified ? `${purple}0.55)` : "rgba(255,80,80,0.45)",
            background: verified ? `${purple}0.04)` : "rgba(255,80,80,0.04)",
          }}
        >
          <div
            style={{
              fontSize: "0.85rem",
              letterSpacing: "0.1em",
              color: verified ? accent : "#ff5050",
              marginBottom: "0.5rem",
            }}
          >
            {verified ? "✓ BUNDLE_VERIFIED" : "✗ BUNDLE_REJECTED"}
          </div>
          {!verified && verifyReason && (
            <p className="err-text" style={{ margin: "0 0 0.5rem" }}>
              {verifyReason}
            </p>
          )}
          {parsed && (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "9rem 1fr",
                gap: "0.3rem 0.5rem",
                fontSize: "0.66rem",
                color: `${purple}0.7)`,
              }}
            >
              <span>format</span>
              <code style={{ color: accent }}>{parsed.format}</code>
              <span>original_root</span>
              <code style={{ color: accent }} title={parsed.original_root}>
                {short(parsed.original_root)}
              </code>
              <span>recipient_id</span>
              <code style={{ color: accent }} title={parsed.recipient_id}>
                {short(parsed.recipient_id)}
              </code>
              <span>segments</span>
              <code style={{ color: accent }}>
                {parsed.segment_count} ({parsed.segments.filter((s) => s.redacted).length} redacted)
              </code>
              <span>nullifier</span>
              <code style={{ color: accent }} title={parsed.nullifier}>
                {short(parsed.nullifier)}
              </code>
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
