import { useCallback, useState } from "react";
import type { VerdictState } from "../lib/types";
import { API_BASE, sanitizeId } from "../lib/constants";

export type CommitStage = "idle" | "committing" | "done" | "error";

export function useFileCommit(
  setVerdictResult: (r: VerdictState | null) => void,
  submitHash: (hash: string) => void,
) {
  const [droppedFile, setDroppedFile] = useState<File | null>(null);
  const [fileHash, setFileHash] = useState<string | null>(null);
  const [fileProgress, setFileProgress] = useState(0);
  const [apiKey, setApiKey] = useState(
    () => localStorage.getItem("olympus_api_key") ?? "",
  );
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
    localStorage.setItem("olympus_api_key", apiKey.trim());

    const recordId = sanitizeId(droppedFile.name.replace(/\.[^.]+$/, ""));
    const content = {
      filename: droppedFile.name,
      size: droppedFile.size,
      type: droppedFile.type || "application/octet-stream",
      blake3: fileHash,
    };
    try {
      const res = await fetch(`${API_BASE}/ingest/records`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": apiKey.trim() },
        body: JSON.stringify({
          records: [
            { shard_id: "files", record_type: "file", record_id: recordId, version: 1, content },
          ],
        }),
      });
      const data = (await res.json()) as Record<string, unknown>;
      if (!res.ok) {
        const d = (data as { detail?: unknown }).detail;
        setCommitError(typeof d === "string" ? d : JSON.stringify(d));
        setCommitStage("error");
        return;
      }
      const results = (data as { results?: Array<{ content_hash: string }> }).results;
      const contentHash = results?.[0]?.content_hash;
      if (!contentHash) {
        setCommitError("Server response missing content_hash — cannot verify");
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
