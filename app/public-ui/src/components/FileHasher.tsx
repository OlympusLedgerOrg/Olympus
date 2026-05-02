import {
  useCallback,
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
  type KeyboardEvent,
} from "react";
import { hashFile } from "../lib/blake3";

interface FileHasherProps {
  onHash: (hex: string) => void;
  onProgress: (pct: number) => void;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024 * 1024) {
    return `${Math.max(1, Math.round(bytes / 1024)).toLocaleString()} KB`;
  }
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export default function FileHasher({ onHash, onProgress }: FileHasherProps) {
  const [dragging, setDragging] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileSize, setFileSize] = useState<number | null>(null);
  const [progress, setProgress] = useState(0);
  const [hashing, setHashing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const processFile = useCallback(
    async (file: File) => {
      setFileName(file.name);
      setFileSize(file.size);
      setHashing(true);
      setError(null);
      setProgress(0);
      onProgress(0);
      try {
        const hex = await hashFile(file, (pct) => {
          setProgress(pct);
          onProgress(pct);
        });
        setProgress(100);
        onHash(hex);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Hashing failed");
      } finally {
        setHashing(false);
      }
    },
    [onHash, onProgress],
  );

  const handleDrop = useCallback(
    (event: DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      setDragging(false);
      const file = event.dataTransfer.files[0];
      if (file) void processFile(file);
    },
    [processFile],
  );

  const handleChange = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (file) void processFile(file);
    },
    [processFile],
  );

  return (
    <div
      onDragOver={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
      role="button"
      tabIndex={0}
      onKeyDown={(event: KeyboardEvent<HTMLDivElement>) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          inputRef.current?.click();
        }
      }}
      style={{
        border: `1px solid ${dragging ? "#00FF41" : "rgba(0,255,65,0.25)"}`,
        borderRadius: 6,
        padding: "1.75rem",
        textAlign: "center",
        cursor: "pointer",
        background: dragging ? "rgba(0,255,65,0.08)" : "rgba(0,20,0,0.4)",
        transition: "all 0.15s",
        clipPath: "polygon(0 0, 97% 0, 100% 3%, 100% 100%, 3% 100%, 0 97%)",
      }}
    >
      <input
        ref={inputRef}
        type="file"
        style={{ display: "none" }}
        onChange={handleChange}
        aria-label="Select file for BLAKE3 WASM hashing"
      />
      {hashing ? (
        <>
          <p style={{ color: "#00FF41", fontSize: "0.85rem", margin: 0 }}>
            HASHING:{" "}
            <span style={{ fontFamily: "'DM Mono', monospace" }}>{fileName}</span>
          </p>
          <div className="progress-track" style={{ marginTop: "0.85rem" }}>
            <div className="progress-fill" style={{ width: `${progress}%` }} />
          </div>
        </>
      ) : fileName ? (
        <>
          <p
            style={{
              color: "rgba(0,255,65,0.72)",
              fontSize: "0.85rem",
              margin: "0 0 0.25rem",
            }}
          >
            <span style={{ fontFamily: "'DM Mono', monospace" }}>{fileName}</span>
          </p>
          <p
            style={{
              color: "rgba(0,255,65,0.38)",
              fontSize: "0.68rem",
              margin: 0,
            }}
          >
            {fileSize !== null ? formatBytes(fileSize) : "FILE"} // drop another file or
            click to change
          </p>
        </>
      ) : (
        <>
          <p
            style={{
              color: "rgba(0,255,65,0.7)",
              fontSize: "0.85rem",
              margin: "0 0 0.3rem",
            }}
          >
            DROP_FILE_HERE or click to browse
          </p>
          <p
            style={{ color: "rgba(0,255,65,0.35)", fontSize: "0.7rem", margin: 0 }}
          >
            Hashed locally with BLAKE3 WASM. File bytes stay in this browser.
          </p>
        </>
      )}
      {error && (
        <p style={{ color: "#ff0055", fontSize: "0.85rem", margin: "0.5rem 0 0" }}>
          {error}
        </p>
      )}
    </div>
  );
}
