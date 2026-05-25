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
  const [originalHash, setOriginalHash] = useState("");

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

    const baseRecordId = sanitizeId(droppedFile.name.replace(/\.[^.]+$/, ""));
    const recordId = sanitizeId(`${baseRecordId}-${fileHash.slice(0, 12)}`);

    try {
      // Read file into ArrayBuffer for Tauri IPC transfer
      const arrayBuf = await droppedFile.arrayBuffer();
      const fileBytes = Array.from(new Uint8Array(arrayBuf));

      // Check if running inside Tauri — use IPC to bypass browser CORS/mixed-content
      const isTauri =
        typeof window !== "undefined" &&
        typeof (window as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== "undefined";

      let data: Record<string, unknown>;

      const trimmedOriginal = originalHash.trim().toLowerCase();
      const hasOriginal = /^[0-9a-f]{64}$/.test(trimmedOriginal);

      if (isTauri) {
        const { invoke } = await import("@tauri-apps/api/core");
        data = await invoke<Record<string, unknown>>("commit_file", {
          apiKey: normalizedApiKey,
          fileBytes,
          fileName: droppedFile.name,
          shardId: "files",
          recordId,
          version: 1,
          originalHash: hasOriginal ? trimmedOriginal : null,
        });
      } else {
        // Browser path — direct fetch (works in dev with Vite proxy)
        const base = await getApiBase();
        const form = new FormData();
        form.append("file", droppedFile, droppedFile.name);
        form.append("shard_id", "files");
        form.append("record_id", recordId);
        form.append("version", "1");
        if (hasOriginal) form.append("original_hash", trimmedOriginal);
        const res = await fetch(`${base}/ingest/files`, {
          method: "POST",
          headers: { "X-API-Key": normalizedApiKey },
          body: form,
        });
        const text = await res.text();
        data = text ? (JSON.parse(text) as Record<string, unknown>) : {};
        if (!res.ok) {
          // Audit M-UI-1: do not surface the backend `detail` on 401 — it may
          // include identifying auth-failure context (key prefix, expiry
          // reason, etc.) that we don't want visible to onlookers or any
          // screen-recording layer.
          if (res.status === 401) {
            throw new Error(
              "Authentication failed — paste a valid API key in the box above and try again.",
            );
          }
          const detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
          throw new Error(detail);
        }
      }

      const contentHash = (data as { content_hash?: string }).content_hash;
      if (!contentHash) {
        setCommitError("Server response missing content_hash — cannot verify");
        setCommitStage("error");
        return;
      }
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
      setCommitError(e instanceof Error ? e.message : String(e));
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
    setOriginalHash("");
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
    originalHash,
    setOriginalHash,
  };
}
