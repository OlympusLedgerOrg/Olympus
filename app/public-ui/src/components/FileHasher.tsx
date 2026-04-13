import { useState, useCallback, useRef } from "react";
import { hashFile } from "../lib/blake3";

interface FileHasherProps {
  onHash: (hex: string) => void;
  onProgress: (pct: number) => void;
}

export default function FileHasher({ onHash, onProgress }: FileHasherProps) {
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
      try {
        const hex = await hashFile(file, onProgress);
        onHash(hex);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Hashing failed");
      } finally {
        setHashing(false);
      }
    },
    [onHash, onProgress]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) void processFile(file);
    },
    [processFile]
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) void processFile(file);
    },
    [processFile]
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
      className={`border-2 border-dashed rounded-sm p-8 text-center cursor-pointer transition-colors ${
        dragging
          ? "border-gold bg-gold/5"
          : "border-ink/20 hover:border-ink/40"
      }`}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
      }}
    >
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        onChange={handleChange}
        aria-label="Select file to hash"
      />
      {hashing ? (
        <p className="text-sm font-ui text-ink/60">
          Hashing <span className="font-mono">{fileName}</span>…
        </p>
      ) : fileName ? (
        <p className="text-sm font-ui text-ink/60">
          <span className="font-mono">{fileName}</span> — drop another or click
          to change
        </p>
      ) : (
        <div>
          <p className="text-sm font-ui text-ink/60 mb-1">
            Drop a file here or click to browse
          </p>
          <p className="text-xs font-ui text-ink/40">
            File never leaves your device — hashed locally with BLAKE3
          </p>
        </div>
      )}
      {error && (
        <p className="text-xs text-failed mt-2 font-ui">{error}</p>
      )}
    </div>
  );
}
