import { useSkin } from "../skins/SkinContext";
import FileHasher from "../components/FileHasher";
import HashDisplay from "../components/HashDisplay";

interface FileTabProps {
  fileHash: string | null;
  fileProgress: number;
  commitContentHash: string | null;
  isPending: boolean;
  onHash: (hex: string) => void;
  onProgress: (p: number) => void;
  onFile: (f: File) => void;
  onVerify: () => void;
}

export default function FileTab({
  fileHash,
  fileProgress,
  commitContentHash,
  isPending,
  onHash,
  onProgress,
  onFile,
  onVerify,
}: FileTabProps) {
  const { skin } = useSkin();
  return (
    <div>
      <FileHasher onHash={onHash} onProgress={onProgress} onFile={onFile} />
      {fileProgress > 0 && fileProgress < 100 && (
        <p className={skin.classes.mutedText} style={{ fontSize: "0.65rem" }}>
          HASHING... {fileProgress}%
        </p>
      )}
      {fileHash && (
        <div style={{ marginTop: "1rem" }}>
          <p
            className={skin.classes.mutedText}
            style={{
              fontSize: "0.55rem",
              letterSpacing: "0.1em",
              margin: "0 0 0.25rem",
            }}
          >
            FILE BLAKE3
          </p>
          <HashDisplay hash={fileHash} />
          {commitContentHash && (
            <div style={{ marginTop: "0.85rem" }}>
              <p
                className={skin.classes.mutedText}
                style={{
                  fontSize: "0.55rem",
                  letterSpacing: "0.1em",
                  margin: "0 0 0.25rem",
                }}
              >
                LEDGER CONTENT HASH
              </p>
              <HashDisplay hash={commitContentHash} />
            </div>
          )}
          <button
            type="button"
            className={skin.classes.buttonPrimary}
            onClick={onVerify}
            disabled={isPending}
            style={{ marginTop: "1rem" }}
          >
            {isPending ? "EXECUTING..." : "VERIFY_ON_LEDGER"}
          </button>
        </div>
      )}
    </div>
  );
}
