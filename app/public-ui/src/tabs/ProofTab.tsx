import { useRef, useState } from "react";
import { useSkin } from "../skins/SkinContext";
import { EXAMPLE_PROOF } from "../lib/constants";
import {
  formatProofBundleSize,
  MAX_PROOF_BUNDLE_BYTES,
} from "../lib/proofBundle";

interface ProofTabProps {
  proofInput: string;
  setProofInput: (v: string) => void;
  proofError: string | null;
  proofBundleJson?: string;
  isPending: boolean;
  onSubmit: () => void;
  onDownloadBundle?: () => void;
}

export default function ProofTab({
  proofInput,
  setProofInput,
  proofError,
  proofBundleJson,
  isPending,
  onSubmit,
  onDownloadBundle,
}: ProofTabProps) {
  const { skin } = useSkin();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const [loadedFile, setLoadedFile] = useState<string | null>(null);

  const loadProofFile = async (file: File) => {
    setFileError(null);
    setLoadedFile(null);

    if (file.size > MAX_PROOF_BUNDLE_BYTES) {
      setFileError(
        `Proof package is ${formatProofBundleSize(file.size)}; limit is ${formatProofBundleSize(MAX_PROOF_BUNDLE_BYTES)}.`,
      );
      return;
    }

    try {
      const text = await file.text();
      setProofInput(text.trim());
      setLoadedFile(`${file.name} // ${formatProofBundleSize(file.size)}`);
    } catch {
      setFileError("Could not read proof package file.");
    }
  };

  const handleFile = (file?: File) => {
    if (file) void loadProofFile(file);
  };

  return (
    <div>
      <label htmlFor="proof-input" className="terminal-label">
        Proof bundle JSON
      </label>
      <div
        role="button"
        tabIndex={0}
        onClick={() => fileInputRef.current?.click()}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            fileInputRef.current?.click();
          }
        }}
        onDragOver={(event) => {
          event.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setIsDragging(false);
          handleFile(event.dataTransfer.files[0]);
        }}
        className={skin.classes.input}
        style={{
          cursor: "pointer",
          marginBottom: "0.75rem",
          padding: "0.85rem",
          borderStyle: "dashed",
          opacity: isDragging ? 1 : 0.86,
        }}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept="application/json,.json,.proof,.bundle"
          onChange={(event) => handleFile(event.target.files?.[0])}
          style={{ display: "none" }}
        />
        <div style={{ fontSize: "0.68rem", lineHeight: 1.5 }}>
          {loadedFile ?? "DROP PROOF PACKAGE JSON HERE or click to browse"}
        </div>
        <div style={{ fontSize: "0.58rem", opacity: 0.68, marginTop: "0.25rem" }}>
          LIMIT {formatProofBundleSize(MAX_PROOF_BUNDLE_BYTES)}
        </div>
      </div>
      <textarea
        id="proof-input"
        value={proofInput}
        onChange={(event) => {
          setProofInput(event.target.value);
        }}
        rows={9}
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
            setFileError(null);
            setLoadedFile(null);
            setProofInput(JSON.stringify(EXAMPLE_PROOF, null, 2));
          }}
        >
          SAMPLE
        </button>
        <button
          type="button"
          className={skin.classes.buttonSecondary}
          onClick={() => {
            setFileError(null);
            setLoadedFile(null);
            setProofInput("");
          }}
        >
          CLEAR
        </button>
        {proofBundleJson && (
          <>
            <button
              type="button"
              className={skin.classes.buttonSecondary}
              onClick={() => {
                setFileError(null);
                setLoadedFile("VERIFIED_BUNDLE // in memory");
                setProofInput(proofBundleJson);
              }}
            >
              LOAD_VERIFIED_BUNDLE
            </button>
            <button
              type="button"
              className={skin.classes.buttonSecondary}
              onClick={onDownloadBundle}
            >
              DOWNLOAD_JSON
            </button>
          </>
        )}
      </div>
      <button
        type="button"
        className={skin.classes.buttonPrimary}
        onClick={onSubmit}
        disabled={isPending || !proofInput.trim()}
        style={{ marginTop: "0.75rem" }}
      >
        {isPending ? "EXECUTING..." : "EXECUTE_VERIFICATION"}
      </button>
      {fileError && <p className="err-text">{fileError}</p>}
      {proofError && <p className="err-text">{proofError}</p>}
    </div>
  );
}
