/**
 * RedactionTab — ZK redaction prove/verify UI.
 *
 * GENERATE mode: prover has both files → server computes Groth16 proof → download bundle.
 * VERIFY mode:   verifier has redacted file + bundle → server confirms, no original needed.
 */

import { useCallback, useRef, useState } from "react";
import { useRedactionZk, type RedactionZkMode } from "../hooks/useRedactionZk";

interface Props {
  apiKey?: string;
}

const mono: React.CSSProperties = { fontFamily: "'DM Mono', monospace" };

const DIM = "rgba(0,255,65,0.35)";
const MID = "rgba(0,255,65,0.55)";
const BRIGHT = "#00ff41";
const BORDER_DIM = "rgba(0,255,65,0.18)";
const BORDER_MED = "rgba(0,255,65,0.4)";

// ─── Shared sub-components ────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontSize: "0.56rem", letterSpacing: "0.12em", color: DIM, marginBottom: "0.4rem", ...mono }}>
      {children}
    </div>
  );
}

function DropZone({
  label,
  file,
  accept,
  onFile,
}: {
  label: string;
  file: File | null;
  accept?: string;
  onFile: (f: File) => void;
}) {
  const ref = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) onFile(f);
  }, [onFile]);

  return (
    <div
      onClick={() => ref.current?.click()}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={(e) => { if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setDragging(false); }}
      onDrop={handleDrop}
      style={{
        border: `1px dashed ${dragging ? BORDER_MED : file ? BORDER_MED : BORDER_DIM}`,
        background: file ? "rgba(0,255,65,0.04)" : "rgba(0,255,65,0.01)",
        padding: "1.1rem 1rem",
        textAlign: "center",
        cursor: "pointer",
        transition: "all 0.15s",
        marginBottom: "0.9rem",
      }}
    >
      <input
        ref={ref}
        type="file"
        accept={accept}
        onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f); e.target.value = ""; }}
        style={{ display: "none" }}
      />
      {file ? (
        <div>
          <div style={{ fontSize: "0.75rem", color: BRIGHT, marginBottom: "0.2rem", ...mono }}>{file.name}</div>
          <div style={{ fontSize: "0.58rem", color: DIM, ...mono }}>{(file.size / 1024).toFixed(1)} KB — click to change</div>
        </div>
      ) : (
        <div style={{ fontSize: "0.62rem", color: DIM, letterSpacing: "0.08em", ...mono }}>📄 {label}</div>
      )}
    </div>
  );
}

// ─── Reveal mask grid ─────────────────────────────────────────────────────────

function RevealMaskGrid({ mask }: { mask: number[] }) {
  return (
    <div style={{ marginBottom: "1rem" }}>
      <SectionLabel>SECTION MASK ({mask.filter(Boolean).length}/{mask.length} revealed)</SectionLabel>
      <div style={{ display: "flex", gap: "0.35rem" }}>
        {mask.map((bit, i) => (
          <div
            key={i}
            title={`Section ${i.toString()}: ${bit ? "REVEALED" : "REDACTED"}`}
            style={{
              flex: 1,
              height: "2rem",
              background: bit ? "rgba(0,255,65,0.18)" : "rgba(255,40,40,0.18)",
              border: `1px solid ${bit ? "rgba(0,255,65,0.5)" : "rgba(255,40,40,0.4)"}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: "0.5rem",
              color: bit ? BRIGHT : "rgba(255,80,80,0.9)",
              ...mono,
            }}
          >
            {bit ? "✓" : "✗"}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Main tab ─────────────────────────────────────────────────────────────────

export default function RedactionTab({ apiKey }: Props) {
  const zk = useRedactionZk(apiKey);
  const { state } = zk;

  const canProve =
    !!(state.originalFile && state.redactedFile && state.commitId.trim()) &&
    state.stage !== "proving";
  const canVerify =
    !!(state.verifyRedactedFile && state.parsedBundle) && state.stage !== "verifying";

  return (
    <div>
      {/* Mode toggle */}
      <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1.25rem" }}>
        {(["generate", "verify"] as RedactionZkMode[]).map((m) => (
          <button
            key={m}
            onClick={() => zk.setMode(m)}
            style={{
              flex: 1,
              padding: "0.5rem",
              background: state.mode === m ? "rgba(0,255,65,0.12)" : "transparent",
              border: `1px solid ${state.mode === m ? BORDER_MED : BORDER_DIM}`,
              color: state.mode === m ? BRIGHT : DIM,
              fontSize: "0.6rem",
              letterSpacing: "0.1em",
              cursor: "pointer",
              ...mono,
            }}
          >
            {m === "generate" ? "GENERATE_PROOF" : "VERIFY_PROOF"}
          </button>
        ))}
      </div>

      {state.mode === "generate" ? (
        <GeneratePane zk={zk} canProve={canProve} />
      ) : (
        <VerifyPane zk={zk} canVerify={canVerify} />
      )}
    </div>
  );
}

// ─── GENERATE pane ────────────────────────────────────────────────────────────

function GeneratePane({
  zk,
  canProve,
}: {
  zk: ReturnType<typeof useRedactionZk>;
  canProve: boolean;
}) {
  const { state } = zk;
  const busy = state.stage === "proving";

  return (
    <div>
      <p style={{ fontSize: "0.68rem", color: DIM, margin: "0 0 1rem", lineHeight: 1.6, ...mono }}>
        Supply both files and the original commit ID. The server computes a Groth16 proof; the
        verifier never needs the original.
      </p>

      <SectionLabel>STEP 1 — ORIGINAL DOCUMENT</SectionLabel>
      <DropZone label="DROP ORIGINAL FILE" file={state.originalFile} onFile={zk.setOriginalFile} />

      <SectionLabel>STEP 2 — REDACTED DOCUMENT</SectionLabel>
      <DropZone label="DROP REDACTED FILE" file={state.redactedFile} onFile={zk.setRedactedFile} />

      <SectionLabel>STEP 3 — ORIGINAL COMMIT ID</SectionLabel>
      <input
        value={state.commitId}
        onChange={(e) => zk.setCommitId(e.target.value)}
        placeholder="0x..."
        style={{
          width: "100%",
          background: "rgba(0,255,65,0.04)",
          border: `1px solid ${state.commitId ? BORDER_MED : BORDER_DIM}`,
          color: BRIGHT,
          padding: "0.55rem 0.7rem",
          fontSize: "0.7rem",
          boxSizing: "border-box",
          marginBottom: "1rem",
          outline: "none",
          ...mono,
        }}
      />

      <button
        onClick={() => void zk.prove()}
        disabled={!canProve || busy}
        style={{
          width: "100%",
          padding: "0.7rem",
          background: canProve && !busy ? "rgba(0,255,65,0.1)" : "transparent",
          border: `1px solid ${canProve && !busy ? BORDER_MED : BORDER_DIM}`,
          color: canProve && !busy ? BRIGHT : DIM,
          fontSize: "0.65rem",
          letterSpacing: "0.12em",
          cursor: canProve && !busy ? "pointer" : "default",
          marginBottom: "1rem",
          ...mono,
        }}
      >
        {busy ? "COMPUTING — may take 60 s…" : "GENERATE ZK PROOF"}
      </button>

      {state.stage === "error" && (
        <div
          style={{
            padding: "0.75rem",
            border: "1px solid rgba(255,40,40,0.35)",
            color: "rgba(255,80,80,0.9)",
            fontSize: "0.63rem",
            marginBottom: "0.75rem",
            ...mono,
          }}
        >
          ERROR: {state.error}
        </div>
      )}

      {state.stage === "done" && state.proofBundle && (
        <div>
          <RevealMaskGrid mask={state.proofBundle.reveal_mask} />
          <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.75rem" }}>
            <button
              onClick={zk.downloadBundle}
              style={{
                flex: 1,
                padding: "0.6rem",
                background: "rgba(0,255,65,0.1)",
                border: `1px solid ${BORDER_MED}`,
                color: BRIGHT,
                fontSize: "0.62rem",
                letterSpacing: "0.1em",
                cursor: "pointer",
                ...mono,
              }}
            >
              ↓ DOWNLOAD PROOF BUNDLE
            </button>
            <button
              onClick={zk.reset}
              style={{
                padding: "0.6rem 1rem",
                background: "transparent",
                border: `1px solid ${BORDER_DIM}`,
                color: DIM,
                fontSize: "0.62rem",
                cursor: "pointer",
                ...mono,
              }}
            >
              RESET
            </button>
          </div>
          <div style={{ fontSize: "0.6rem", color: DIM, ...mono }}>
            {state.proofBundle.revealed_count}/{state.proofBundle.revealed_count + state.proofBundle.redacted_count} sections revealed —{" "}
            {state.proofBundle.redacted_count} redacted
          </div>
        </div>
      )}
    </div>
  );
}

// ─── VERIFY pane ─────────────────────────────────────────────────────────────

function VerifyPane({
  zk,
  canVerify,
}: {
  zk: ReturnType<typeof useRedactionZk>;
  canVerify: boolean;
}) {
  const { state } = zk;
  const busy = state.stage === "verifying";

  return (
    <div>
      <p style={{ fontSize: "0.68rem", color: DIM, margin: "0 0 1rem", lineHeight: 1.6, ...mono }}>
        Drop the redacted file and the proof bundle JSON. No original document required.
      </p>

      <SectionLabel>STEP 1 — REDACTED DOCUMENT</SectionLabel>
      <DropZone
        label="DROP REDACTED FILE"
        file={state.verifyRedactedFile}
        onFile={zk.setVerifyRedactedFile}
      />

      <SectionLabel>STEP 2 — PROOF BUNDLE JSON</SectionLabel>
      <DropZone
        label="DROP PROOF BUNDLE (.json)"
        file={state.bundleFile}
        accept=".json,application/json"
        onFile={zk.setBundleFile}
      />

      {state.bundleFile && !state.parsedBundle && (
        <div style={{ fontSize: "0.6rem", color: "rgba(255,80,80,0.8)", marginBottom: "0.5rem", ...mono }}>
          Invalid proof bundle JSON
        </div>
      )}

      {state.parsedBundle && (
        <div style={{ fontSize: "0.6rem", color: MID, marginBottom: "0.75rem", ...mono }}>
          Bundle: {state.parsedBundle.revealed_count}/{state.parsedBundle.revealed_count + state.parsedBundle.redacted_count} sections revealed
        </div>
      )}

      <button
        onClick={() => void zk.verifyZk()}
        disabled={!canVerify || busy}
        style={{
          width: "100%",
          padding: "0.7rem",
          background: canVerify && !busy ? "rgba(0,255,65,0.1)" : "transparent",
          border: `1px solid ${canVerify && !busy ? BORDER_MED : BORDER_DIM}`,
          color: canVerify && !busy ? BRIGHT : DIM,
          fontSize: "0.65rem",
          letterSpacing: "0.12em",
          cursor: canVerify && !busy ? "pointer" : "default",
          marginBottom: "1rem",
          ...mono,
        }}
      >
        {busy ? "VERIFYING…" : "VERIFY REDACTION"}
      </button>

      {state.stage === "error" && (
        <div
          style={{
            padding: "0.75rem",
            border: "1px solid rgba(255,40,40,0.35)",
            color: "rgba(255,80,80,0.9)",
            fontSize: "0.63rem",
            marginBottom: "0.75rem",
            ...mono,
          }}
        >
          ERROR: {state.error}
        </div>
      )}

      {state.stage === "done" && state.verifyResult && (
        <div>
          <div
            style={{
              padding: "1rem",
              border: `1px solid ${state.verifyResult.verified ? "rgba(0,255,65,0.5)" : "rgba(255,40,40,0.5)"}`,
              background: state.verifyResult.verified
                ? "rgba(0,255,65,0.06)"
                : "rgba(255,40,40,0.06)",
              marginBottom: "0.75rem",
            }}
          >
            <div
              style={{
                fontSize: "0.78rem",
                color: state.verifyResult.verified ? BRIGHT : "rgba(255,80,80,0.9)",
                letterSpacing: "0.1em",
                marginBottom: "0.75rem",
                ...mono,
              }}
            >
              {state.verifyResult.verified
                ? "✓ ACCESS_GRANTED — PROOF VALID"
                : "✗ ACCESS_DENIED — PROOF INVALID"}
            </div>
            {state.verifyResult.verified && state.parsedBundle && (
              <RevealMaskGrid mask={state.parsedBundle.reveal_mask} />
            )}
            <div style={{ fontSize: "0.6rem", color: DIM, lineHeight: 1.8, ...mono }}>
              <div>original_root: {state.verifyResult.original_root.slice(0, 22)}…</div>
              <div>redacted_commitment: {state.verifyResult.redacted_commitment.slice(0, 22)}…</div>
              <div>
                revealed: {state.verifyResult.revealed_count} /{" "}
                {state.verifyResult.revealed_count + state.verifyResult.redacted_count} sections
              </div>
            </div>
          </div>
          <button
            onClick={zk.reset}
            style={{
              padding: "0.5rem 1.2rem",
              background: "transparent",
              border: `1px solid ${BORDER_DIM}`,
              color: DIM,
              fontSize: "0.6rem",
              cursor: "pointer",
              ...mono,
            }}
          >
            RESET
          </button>
        </div>
      )}
    </div>
  );
}
