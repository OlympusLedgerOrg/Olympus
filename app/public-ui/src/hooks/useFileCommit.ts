import { useCallback, useState } from "react";
import type { VerdictState } from "../lib/types";
import type { HashVerificationSource } from "./useHashVerification";
import { API_BASE, sanitizeId } from "../lib/constants";
import {
  apiKeyProblem,
  getStoredApiKey,
  normalizeApiKey,
  setStoredApiKey,
} from "../lib/storage";

export type CommitStage = "idle" | "committing" | "done" | "error";

function commitEndpointCandidates(): string[] {
  const endpoints = ["/ingest/files"];
  if (API_BASE && API_BASE !== window.location.origin) {
    endpoints.push(`${API_BASE}/ingest/files`);
  }
  return endpoints;
}

export function useFileCommit(
  setVerdictResult: (r: VerdictState | null) => void,
  submitHash: (hash: string, source?: HashVerificationSource) => void,
) {
  const [droppedFile, setDroppedFile] = useState<File | null>(null);
  const [fileHash, setFileHash] = useState<string | null>(null);
  const [fileProgress, setFileProgress] = useState(0);
  const [apiKey, setApiKey] = useState(() => getStoredApiKey());
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
    const normalizedApiKey = normalizeApiKey(apiKey);
    const keyProblem = apiKeyProblem(normalizedApiKey);
    if (keyProblem) {
      setCommitError(keyProblem);
      setCommitStage("error");
      return;
    }

    setCommitStage("committing");
    setCommitError(null);
    setCommitContentHash(null);
    setStoredApiKey(normalizedApiKey);

    // POST raw bytes to /ingest/files. The server stores content_hash =
    // plain BLAKE3 of file bytes (no JSON wrapper, no canonicalization),
    // so re-dropping the same file produces the same hash and verifies.
    const baseRecordId = sanitizeId(droppedFile.name.replace(/\.[^.]+$/, ""));
    const recordId = sanitizeId(`${baseRecordId}-${fileHash.slice(0, 12)}`);
    const form = new FormData();
    form.append("file", droppedFile, droppedFile.name);
    form.append("shard_id", "files");
    form.append("record_id", recordId);
    form.append("version", "1");
    try {
      let res: Response | null = null;
      let failedEndpoint = "";
      let networkError = "";

      for (const endpoint of commitEndpointCandidates()) {
        try {
          res = await fetch(endpoint, {
            method: "POST",
            headers: { "X-API-Key": normalizedApiKey },
            body: form,
          });
          break;
        } catch (error) {
          failedEndpoint = endpoint;
          networkError = error instanceof Error ? error.message : String(error);
        }
      }

      if (!res) {
        setCommitError(
          `Could not reach /ingest/files${failedEndpoint ? ` via ${failedEndpoint}` : ""}: ${networkError || "network request failed"}`,
        );
        setCommitStage("error");
        return;
      }

      const text = await res.text();
      let data: Record<string, unknown> = {};
      try {
        data = text ? (JSON.parse(text) as Record<string, unknown>) : {};
      } catch {
        data = { detail: text || res.statusText };
      }
      if (!res.ok) {
        const d = (data as { detail?: unknown }).detail;
        setCommitError(typeof d === "string" ? d : JSON.stringify(d));
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
      submitHash(contentHash, "file");
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
