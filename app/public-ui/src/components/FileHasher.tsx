import { useState, useCallback, useRef, type DragEvent, type ChangeEvent, type KeyboardEvent } from "react";
import { hashFile } from "../lib/blake3";

interface FileHasherProps {
  onHash: (hex: string) => void;
  onProgress: (pct: number) => void;
  onFile?: (file: File) => void;
}

export default function FileHasher({ onHash, onProgress, onFile }: FileHasherProps) {
  const [dragging, setDragging] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [hashing, setHashing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const processFile = useCallback(
    async (file: File) => {
      setFileName(file.name);
      setHashing(true);
      setError(null);
      onProgress(0);
      onFile?.(file);
      try {
        const hex = await hashFile(file, onProgress);
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
    (e: DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) void processFile(file);
    },
    [processFile],
  );

  const handleChange = useCallback(
    (e: ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) void processFile(file);
    },
    [processFile],
  );

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
      role="button"
      tabIndex={0}
      onKeyDown={(e: KeyboardEvent<HTMLDivElement>) => {
        if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
      }}
      style={{
        border: `1px solid ${dragging ? "#00FF41" : "rgba(0,255,65,0.25)"}`,
        borderRadius: 3,
        padding: "1.75rem",
        textAlign: "center",
        cursor: "pointer",
        background: dragging ? "rgba(0,255,65,0.06)" : "rgba(0,20,0,0.4)",
        transition: "all 0.15s",
        clipPath:
          "polygon(0 0, 97% 0, 100% 3%, 100% 100%, 3% 100%, 0 97%)",
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
        <p style={{ color: "#00FF41", fontSize: "0.85rem", margin: 0 }}>
          HASHING:{" "}
          <span style={{ fontFamily: "'DM Mono', monospace" }}>{fileName}</span>
          …
        </p>
      ) : fileName ? (
        <p
          style={{ color: "rgba(0,255,65,0.6)", fontSize: "0.85rem", margin: 0 }}
        >
          <span style={{ fontFamily: "'DM Mono', monospace" }}>{fileName}</span>{" "}
          — drop another or click to change
        </p>
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
            Hashed locally with BLAKE3 WASM — file never leaves your device
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
