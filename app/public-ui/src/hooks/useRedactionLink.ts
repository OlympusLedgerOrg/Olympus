import { useState, useCallback, useRef } from "react";
import { hashFile, hashChunks } from "../lib/blake3";

const API_BASE =
  (typeof import.meta !== "undefined" &&
    (import.meta as { env?: { VITE_API_BASE?: string } }).env?.VITE_API_BASE) ||
  (typeof window !== "undefined" ? window.location.origin : "");

const CHUNK_COUNT = 64;

export type RedactionStage =
  | "idle"
  | "awaiting_original"
  | "hashing"
  | "ready"
  | "linking"
  | "done"
  | "error";

export interface RedactionLinkResult {
  original_commit_id: string;
  original_blake3: string;
  original_root: string;
  redacted_commitment: string;
  reveal_mask_commitment: string;
  reveal_mask: number[];
  revealed_count: number;
  redacted_count: number;
  verified: boolean;
  note: string;
}

/**
 * Split a byte array into CHUNK_COUNT equal-sized chunks using a fixed chunkSize.
 *
 * chunkSize MUST be derived from the original file's byte length and shared with
 * both the original and redacted file.  If each file were chunked with its own
 * length-derived size, files of different byte lengths would produce different
 * chunk boundaries, making chunk-by-chunk hash comparison meaningless even for
 * bytes that were not changed by the redaction.
 */
function chunkBytes(bytes: Uint8Array, chunkSize: number): Uint8Array[] {
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < CHUNK_COUNT; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, bytes.length);
    const chunk = new Uint8Array(chunkSize);
    if (start < bytes.length) chunk.set(bytes.slice(start, end));
    chunks.push(chunk);
  }
  return chunks;
}

export function useRedactionLink(redactedFile: File | null, redactedHash: string) {
  const [stage, setStage] = useState<RedactionStage>("idle");
  const [originalFile, setOriginalFile] = useState<File | null>(null);
  const [originalHash, setOriginalHash] = useState("");
  const [commitId, setCommitId] = useState("");
  const [result, setResult] = useState<RedactionLinkResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const originalInputRef = useRef<HTMLInputElement>(null);

  const reset = useCallback(() => {
    setStage("idle");
    setOriginalFile(null);
    setOriginalHash("");
    setCommitId("");
    setResult(null);
    setError(null);
  }, []);

  const start = useCallback(() => {
    setStage("awaiting_original");
    setError(null);
  }, []);

  const onOriginalFile = useCallback(async (f: File) => {
    setOriginalFile(f);
    setStage("hashing");
    setError(null);
    try {
      const h = await hashFile(f);
      setOriginalHash(h);
      setStage("ready");
    } catch (e) {
      setError(String(e));
      setStage("error");
    }
  }, []);

  const link = useCallback(async () => {
    if (!redactedFile || !originalFile || !commitId.trim()) return;
    setStage("linking");
    setError(null);

    try {
      // Read both files up front so we can derive a shared chunk size.
      const [origBuf, redactBuf] = await Promise.all([
        originalFile.arrayBuffer(),
        redactedFile.arrayBuffer(),
      ]);
      const origBytes = new Uint8Array(origBuf);
      const redactBytes = new Uint8Array(redactBuf);

      // Chunk size is derived from the ORIGINAL file only, then applied to both.
      // This ensures identical byte positions are compared across both files
      // regardless of any size difference introduced by the redaction tool.
      const chunkSize = Math.ceil(origBytes.length / CHUNK_COUNT);
      const origChunks = chunkBytes(origBytes, chunkSize);
      const redactChunks = chunkBytes(redactBytes, chunkSize);

      const [originalChunkHashes, redactedChunkHashes] = await Promise.all([
        hashChunks(origChunks),
        hashChunks(redactChunks),
      ]);

      const res = await fetch(`${API_BASE}/redaction/link`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          original_commit_id: commitId.trim(),
          original_chunks: originalChunkHashes,
          redacted_chunks: redactedChunkHashes,
        }),
      });

      const data = await res.json() as Record<string, unknown>;
      if (!res.ok) {
        const d = (data as { detail?: unknown }).detail;
        setError(typeof d === "string" ? d : JSON.stringify(d));
        setStage("error");
        return;
      }

      setResult(data as unknown as RedactionLinkResult);
      setStage("done");
    } catch (e) {
      setError(String(e));
      setStage("error");
    }
  }, [redactedFile, originalFile, commitId, redactedHash]);

  return {
    stage, originalFile, originalHash, originalInputRef,
    commitId, setCommitId,
    result, error,
    start, reset, onOriginalFile, link,
  };
}
