/**
 * ProofTab — ZK proof verification tab.
 *
 * Drop a document file + a proof bundle JSON.  The drop zone auto-classifies:
 *   - .json / application/json  → proof bundle slot
 *   - anything else             → document slot (BLAKE3-hashed in-browser)
 *
 * The JSON textarea has been removed.  All verification goes through the
 * drop zone so the server always validates the actual file rather than a
 * hash the user typed by hand.
 */

import { useSkin } from "../skins/SkinContext";
import ZkDropZone from "../components/ZkDropZone";
import type { ZkDropStage } from "../hooks/useZkDrop";

interface ProofTabProps {
  zkStage: ZkDropStage;
  fileName: string | null;
  fileProgress: number;
  proofFileName: string | null;
  hashMatch: boolean | null;
  zkError: string | null;
  onFiles: (files: File[]) => void;
  onDocumentFile: (file: File) => void;
  onProofFile: (file: File) => void;
  onVerify: () => void;
  isPending: boolean;
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
  onVerify,
  isPending,
}: ProofTabProps) {
  const { skin } = useSkin();

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
    </div>
  );
}
