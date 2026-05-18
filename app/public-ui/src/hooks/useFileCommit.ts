import { useCallback, useState } from "react";
import type { VerdictState } from "../lib/types";
import { API_BASE, sanitizeId } from "../lib/constants";
import { getStoredApiKey, setStoredApiKey } from "../lib/storage";

export type CommitStage = "idle" | "committing" | "done" | "error";

export function useFileCommit(
  setVerdictResult: (r: VerdictState | null) => void,
  submitHash: (hash: string) => void,
) {
  const [droppedFile, setDroppedFile] = useState<File | null>(null);
  const [fileHash, setFileHash] = useState<string | null>(null);
  const [fileProgress, setFileProgress] = useState(0);
  const [apiKey, setApiKeyState] = useState(() => getStoredApiKey());
  const setApiKey = useCallback((k: string) => {
    setApiKeyState(k);
    setStoredApiKey(k);
  }, []);
  const [commitStage, setCommitStage] = useState<CommitStage>("idle");
  const [commitError, setCommitError] = useState<string | null>(null);
  const [commitContentHash, setCommitContentHash] = useState<string | null>(null);

  const onHash = useCallback(
    (hex: string) => {
      setFileHash(hex);
      setFileProgress(100);
      setVerdictResult(null);
      setCommitStage("idle");
      setCommitError(null);
      setCommitContentHash(null);
    },
    [setVerdictResult],
  );

  const onFile = useCallback(
    (f: File) => {
      setDroppedFile(f);
      setFileHash(null);
      setVerdictResult(null);
      setCommitStage("idle");
      setCommitError(null);
      setCommitContentHash(null);
    },
    [setVerdictResult],
  );

  const commitFile = useCallback(async () => {
    if (!droppedFile || !fileHash || !apiKey.trim()) return;
    setCommitStage("committing");
    setCommitError(null);
    setCommitContentHash(null);
    setStoredApiKey(apiKey.trim());

    // POST raw bytes to /ingest/files. The server stores content_hash =
    // plain BLAKE3 of file bytes (no JSON wrapper, no canonicalization),
    // so re-dropping the same file produces the same hash and verifies.
    const recordId = sanitizeId(droppedFile.name.replace(/\.[^.]+$/, ""));
    const form = new FormData();
    form.append("file", droppedFile, droppedFile.name);
    form.append("shard_id", "files");
    form.append("record_id", recordId);
    form.append("version", "1");
    try {
      const res = await fetch(`${API_BASE}/ingest/files`, {
        method: "POST",
        headers: { "X-API-Key": apiKey.trim() },
        body: form,
      });
      const data = (await res.json()) as Record<string, unknown>;
      if (!res.ok) {
        const d = (data as { detail?: unknown }).detail;
        let msg: string;
        let code: unknown;
        if (typeof d === "string") {
          msg = d;
        } else if (d && typeof d === "object" && "detail" in d) {
          // FastAPI nested detail: {"detail": "...", "code": "..."}
          const inner = (d as { detail?: unknown }).detail;
          code = (d as { code?: unknown }).code;
          msg = typeof inner === "string" ? inner : JSON.stringify(d);
        } else {
          msg = JSON.stringify(d);
        }
        // Apply the friendly auth message for any 401 regardless of detail shape.
        if (res.status === 401 || code === "AUTH_INVALID" || code === "AUTH_EXPIRED") {
          msg = `Authentication failed (${msg}) — paste a valid API key in the box above and try again.`;
        }
        setCommitError(msg);
        setCommitStage("error");
        return;
      }
      const contentHash = (data as { content_hash?: string }).content_hash;
      if (!contentHash) {
        setCommitError("Server response missing content_hash — cannot verify");
        setCommitStage("error");
        return;
      }
      // Sanity check: server's content_hash must equal what we hashed locally,
      // since both are plain BLAKE3 of the same bytes.
      if (contentHash.toLowerCase() !== fileHash.toLowerCase()) {
        setCommitError(
          `Server hash ${contentHash.slice(0, 12)}… disagrees with local ${fileHash.slice(0, 12)}…`,
        );
        setCommitStage("error");
        return;
      }
      setCommitContentHash(contentHash);
      setCommitStage("done");
      submitHash(contentHash);
    } catch (e) {
      setCommitError(String(e));
      setCommitStage("error");
    }
  }, [droppedFile, fileHash, apiKey, submitHash]);

  const resetCommit = useCallback(() => {
    setCommitStage("idle");
    setCommitError(null);
    setCommitContentHash(null);
  }, []);

  const reset = useCallback(() => {
    setDroppedFile(null);
    setFileHash(null);
    setFileProgress(0);
    setCommitStage("idle");
    setCommitError(null);
    setCommitContentHash(null);
  }, []);

  return {
    droppedFile,
    fileHash,
    fileProgress,
    apiKey,
    setApiKey,
    commitStage,
    commitError,
    commitContentHash,
    onHash,
    onProgress: setFileProgress,
    onFile,
    commitFile,
    resetCommit,
    reset,
  };
}
