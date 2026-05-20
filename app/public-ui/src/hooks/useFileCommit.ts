import { useCallback, useState } from "react";
import type { VerdictState } from "../lib/types";
import type { HashVerificationSource } from "./useHashVerification";
import { sanitizeId } from "../lib/constants";
import { getApiBase } from "../lib/api";
import {
  apiKeyProblem,
  getStoredApiKey,
  normalizeApiKey,
  setStoredApiKey,
} from "../lib/storage";

export type CommitStage = "idle" | "committing" | "done" | "error";

export function useFileCommit(
  setVerdictResult: (r: VerdictState | null) => void,
  submitHash: (hash: string, source?: HashVerificationSource) => void,
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

    // POST multipart form to /ingest/records. The server stores
    // content_hash = plain BLAKE3 of file bytes, so re-dropping the same
    // file produces the same hash and verifies.
    const baseRecordId = sanitizeId(droppedFile.name.replace(/\.[^.]+$/, ""));
    const recordId = sanitizeId(`${baseRecordId}-${fileHash.slice(0, 12)}`);
    const form = new FormData();
    form.append("file", droppedFile, droppedFile.name);
    form.append("shard_id", "files");
    form.append("record_id", recordId);
    form.append("version", "1");
    try {
      const base = await getApiBase();
      let res: Response;
      try {
        res = await fetch(`${base}/ingest/files`, {
          method: "POST",
          headers: { "X-API-Key": normalizedApiKey },
          body: form,
        });
      } catch (error) {
        setCommitError(
          `Could not reach ${base}/ingest/files: ${error instanceof Error ? error.message : String(error)}`,
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
