import { useCallback, useRef, useState } from "react";
import { useSkin } from "../skins/SkinContext";

interface ProofTabProps {
  proofInput: string;
  setProofInput: (v: string) => void;
  proofError: string | null;
  isPending: boolean;
  onSubmit: () => void;
}

export default function ProofTab({
  proofInput,
  setProofInput,
  proofError,
  isPending,
  onSubmit,
}: ProofTabProps) {
  const { skin } = useSkin();
  const [docFile, setDocFile] = useState<File | null>(null);
  const [bundleFile, setBundleFile] = useState<File | null>(null);
  const [bundleReadError, setBundleReadError] = useState<string | null>(null);
  const docInputRef = useRef<HTMLInputElement>(null);
  const bundleInputRef = useRef<HTMLInputElement>(null);

  const handleDocDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      const file = e.dataTransfer.files[0];
      if (file) setDocFile(file);
    },
    [],
  );

  const handleBundleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      const file = e.dataTransfer.files[0];
      if (!file) return;
      setBundleFile(file);
      setBundleReadError(null);
      const reader = new FileReader();
      reader.onload = (evt) => {
        const text = evt.target?.result;
        if (typeof text === "string") {
          setProofInput(text);
        }
      };
      reader.onerror = () => {
        setBundleReadError("Could not read the file — try again");
      };
      reader.readAsText(file);
    },
    [setProofInput],
  );

  const handleBundleFile = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;
      setBundleFile(file);
      setBundleReadError(null);
      const reader = new FileReader();
      reader.onload = (evt) => {
        const text = evt.target?.result;
        if (typeof text === "string") {
          setProofInput(text);
        }
      };
      reader.onerror = () => {
        setBundleReadError("Could not read the file — try again");
      };
      reader.readAsText(file);
    },
    [setProofInput],
  );

  const dropStyle: React.CSSProperties = {
    border: "1px dashed rgba(0,255,65,0.35)",
    borderRadius: "2px",
    padding: "1.25rem 1rem",
    textAlign: "center",
    cursor: "pointer",
    marginBottom: "0.75rem",
    transition: "border-color 0.15s",
    fontSize: "0.7rem",
    letterSpacing: "0.08em",
  };

  return (
    <div>
      <p
        className={skin.classes.mutedText}
        style={{ fontSize: "0.65rem", marginBottom: "1.25rem", lineHeight: 1.6 }}
      >
        Drop the original document file and its proof bundle JSON to verify the
        ZK inclusion proof. No API key required.
      </p>

      {/* Slot 1 — Source document */}
      <div style={{ marginBottom: "1rem" }}>
        <div className="terminal-label" style={{ marginBottom: "0.4rem" }}>
          SLOT 1 — Source document
        </div>
        <div
          role="button"
          tabIndex={0}
          style={{
            ...dropStyle,
            borderColor: docFile ? "rgba(0,255,65,0.7)" : "rgba(0,255,65,0.35)",
          }}
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleDocDrop}
          onClick={() => docInputRef.current?.click()}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") docInputRef.current?.click();
          }}
        >
          {docFile ? (
            <span className={skin.classes.accentText}>{docFile.name}</span>
          ) : (
            <span className={skin.classes.mutedText}>
              Drop file here or click to browse
            </span>
          )}
        </div>
        <input
          ref={docInputRef}
          type="file"
          style={{ display: "none" }}
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) setDocFile(f);
          }}
        />
      </div>

      {/* Slot 2 — Proof bundle JSON */}
      <div style={{ marginBottom: "1rem" }}>
        <div className="terminal-label" style={{ marginBottom: "0.4rem" }}>
          SLOT 2 — Proof bundle JSON
        </div>
        <div
          role="button"
          tabIndex={0}
          style={{
            ...dropStyle,
            borderColor: bundleFile ? "rgba(0,255,65,0.7)" : "rgba(0,255,65,0.35)",
          }}
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleBundleDrop}
          onClick={() => bundleInputRef.current?.click()}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") bundleInputRef.current?.click();
          }}
        >
          {bundleFile ? (
            <span className={skin.classes.accentText}>{bundleFile.name}</span>
          ) : (
            <span className={skin.classes.mutedText}>
              Drop proof_bundle.json here or click to browse
            </span>
          )}
        </div>
        <input
          ref={bundleInputRef}
          type="file"
          accept=".json,application/json"
          style={{ display: "none" }}
          onChange={handleBundleFile}
        />
        {bundleReadError && (
          <p className="err-text" style={{ marginTop: "0.35rem" }}>
            {bundleReadError}
          </p>
        )}
        {bundleFile && proofInput && (
          <p
            className={skin.classes.mutedText}
            style={{ fontSize: "0.6rem", marginTop: "0.35rem" }}
          >
            LOADED: {proofInput.length.toLocaleString()} bytes
          </p>
        )}
      </div>

      <button
        type="button"
        className={skin.classes.buttonPrimary}
        onClick={onSubmit}
        disabled={isPending || !proofInput.trim()}
        style={{ marginTop: "0.25rem" }}
      >
        {isPending ? "EXECUTING..." : "EXECUTE_VERIFICATION"}
      </button>
      {proofError && <p className="err-text" style={{ marginTop: "0.5rem" }}>{proofError}</p>}
    </div>
  );
}
