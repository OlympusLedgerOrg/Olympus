import { useCallback, useState } from "react";
import { hashBytes } from "../lib/blake3";

// Number of equal-sized chunks the API expects (must match _MAX_LEAVES on the server)
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

/** Split a file into CHUNK_COUNT equal-sized chunks and BLAKE3-hash each one.
 *
 * chunkSize must be derived from the original file so that original and
 * redacted files use identical boundaries — passing each file's own length
 * produces different chunk sizes and makes changed-chunk detection meaningless.
 */
async function chunkAndHash(file: File, chunkSize: number): Promise<string[]> {
  const buf = await file.arrayBuffer();
  const bytes = new Uint8Array(buf);
  const hashes: string[] = [];
  for (let i = 0; i < CHUNK_COUNT; i++) {
    const slice = bytes.slice(i * chunkSize, (i + 1) * chunkSize);
    const padded =
      slice.length === chunkSize
        ? slice
        : Object.assign(new Uint8Array(chunkSize), slice);
    hashes.push(await hashBytes(padded));
  }
  return hashes;
}

export function useRedactionLink(redactedFile: File | null) {
  const [stage, setStage] = useState<RedactionStage>("idle");
  const [originalFile, setOriginalFile] = useState<File | null>(null);
  const [originalHash, setOriginalHash] = useState("");
  const [commitId, setCommitId] = useState("");
  const [result, setResult] = useState<RedactionLinkResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const onStart = useCallback(() => {
    setStage("awaiting_original");
    setOriginalFile(null);
    setOriginalHash("");
    setCommitId("");
    setResult(null);
    setError(null);
  }, []);

  const onOriginalFile = useCallback(async (f: File) => {
    setOriginalFile(f);
    setStage("hashing");
    try {
      const buf = await f.arrayBuffer();
      const hex = await hashBytes(new Uint8Array(buf));
      setOriginalHash(hex);
      setStage("ready");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setStage("error");
    }
  }, []);

  const onLink = useCallback(async () => {
    if (!redactedFile || !originalFile || !commitId.trim()) return;
    setStage("linking");
    setError(null);
    try {
      const originalBuf = await originalFile.arrayBuffer();
      const chunkSize = Math.ceil(originalBuf.byteLength / CHUNK_COUNT);
      const [originalChunks, redactedChunks] = await Promise.all([
        chunkAndHash(originalFile, chunkSize),
        chunkAndHash(redactedFile, chunkSize),
      ]);

      const resp = await fetch("/redaction/link", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          original_commit_id: commitId.trim(),
          original_chunks: originalChunks,
          redacted_chunks: redactedChunks,
        }),
      });

      if (!resp.ok) {
        const text = await resp.text();
        let msg = `Server error ${resp.status}`;
        try {
          const json = JSON.parse(text) as { detail?: string };
          if (json.detail) msg = json.detail;
        } catch {
          /* ignore */
        }
        throw new Error(msg);
      }

      const data = (await resp.json()) as RedactionLinkResult;
      setResult(data);
      setStage("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setStage("error");
    }
  }, [redactedFile, originalFile, commitId]);

  const onReset = useCallback(() => {
    setStage("idle");
    setOriginalFile(null);
    setOriginalHash("");
    setCommitId("");
    setResult(null);
    setError(null);
  }, []);

  return {
    stage,
    originalFile,
    originalHash,
    commitId,
    setCommitId,
    result,
    error,
    onStart,
    onOriginalFile,
    onLink,
    onReset,
  };
}
