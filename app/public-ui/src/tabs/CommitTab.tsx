/**
 * CommitTab — Ingest a document (source or redacted) into the SMT ledger.
 *
 * Accessible only to API key holders (CommandDeck 03 / COMMIT_LEDGER tab).
 * Flow: drop file → POST /ingest/files → show proof anchor → download attestation.
 */

import { useCallback, useRef, useState } from "react";
import type { IngestFileResponse } from "../lib/types";
import { API_BASE, sanitizeId } from "../lib/constants";
import { getStoredApiKey, setStoredApiKey } from "../lib/storage";
import { useSkin } from "../skins/SkinContext";

type CommitStage = "idle" | "committing" | "done" | "error";

// ─── Attestation download ────────────────────────────────────────────────────

function downloadAttestation(result: IngestFileResponse): void {
  const attestation = {
    olympus_attestation: "v1",
    proof_id: result.proof_id,
    committed_at: result.timestamp,
    content_hash: result.content_hash,
    merkle_root: result.merkle_root,
    shard_id: result.shard_id,
    record_id: result.record_id,
  };
  const blob = new Blob([JSON.stringify(attestation, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `olympus-attestation-${result.proof_id.slice(0, 8)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Monospace label ─────────────────────────────────────────────────────────

function FieldRow({ label, value, dim }: { label: string; value: string; dim?: boolean }) {
  return (
    <div style={{ display: "flex", gap: "1rem", alignItems: "baseline", marginBottom: "0.4rem" }}>
      <span
        style={{
          fontSize: "0.55rem",
          letterSpacing: "0.1em",
          color: "rgba(0,255,136,0.45)",
          minWidth: "9rem",
          flexShrink: 0,
        }}
      >
        {label}
      </span>
      <span
        style={{
          fontSize: "0.72rem",
          color: dim ? "rgba(0,255,136,0.55)" : "rgba(0,255,136,0.9)",
          wordBreak: "break-all",
          fontFamily: "'DM Mono', monospace",
        }}
      >
        {value}
      </span>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function CommitTab() {
  const { skin } = useSkin();
  const [droppedFile, setDroppedFile] = useState<File | null>(null);
  const [apiKey, setApiKeyState] = useState(() => getStoredApiKey());
  const [stage, setStage] = useState<CommitStage>("idle");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<IngestFileResponse | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const setApiKey = useCallback((k: string) => {
    setApiKeyState(k);
    setStoredApiKey(k);
  }, []);

  const acceptFile = useCallback((f: File) => {
    setDroppedFile(f);
    setStage("idle");
    setError(null);
    setResult(null);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragOver(false);
      const f = e.dataTransfer.files[0];
      if (f) acceptFile(f);
    },
    [acceptFile],
  );

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const f = e.target.files?.[0];
      if (f) acceptFile(f);
    },
    [acceptFile],
  );

  const commit = useCallback(async () => {
    if (!droppedFile || !apiKey.trim()) return;
    setStage("committing");
    setError(null);
    setResult(null);
    setStoredApiKey(apiKey.trim());

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
        if (typeof d === "string") {
          msg = d;
        } else if (d && typeof d === "object" && "detail" in d) {
          const inner = (d as { detail?: unknown }).detail;
          msg = typeof inner === "string" ? inner : JSON.stringify(d);
        } else {
          msg = JSON.stringify(d ?? data);
        }
        if (res.status === 401) {
          msg = `Authentication failed — check your API key. (${msg})`;
        }
        setError(msg);
        setStage("error");
        return;
      }
      setResult(data as unknown as IngestFileResponse);
      setStage("done");
    } catch (e) {
      setError(String(e));
      setStage("error");
    }
  }, [droppedFile, apiKey]);

  const reset = useCallback(() => {
    setDroppedFile(null);
    setStage("idle");
    setError(null);
    setResult(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }, []);

  const isAuthError =
    error?.toLowerCase().includes("authentication") ||
    error?.toLowerCase().includes("auth_invalid") ||
    error?.toLowerCase().includes("auth_expired");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      {/* Header */}
      <div>
        <div
          style={{
            fontSize: "0.55rem",
            letterSpacing: "0.14em",
            color: "rgba(0,255,136,0.45)",
            marginBottom: "0.35rem",
          }}
        >
          COMMIT_LEDGER // SMT_INGEST
        </div>
        <p style={{ margin: 0, fontSize: "0.78rem", color: "rgba(0,255,136,0.6)", lineHeight: 1.6 }}>
          Drop a document to ingest it into the Sparse Merkle Tree. Source or redacted — each
          commits independently with its own BLAKE3 hash.
        </p>
      </div>

      {/* Drop zone */}
      <div
        onDrop={handleDrop}
        onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
        onDragLeave={() => setIsDragOver(false)}
        onClick={() => fileInputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") fileInputRef.current?.click(); }}
        style={{
          border: `1px dashed ${isDragOver ? "rgba(0,255,136,0.7)" : "rgba(0,255,136,0.25)"}`,
          background: isDragOver ? "rgba(0,255,136,0.04)" : "transparent",
          padding: "2rem",
          textAlign: "center",
          cursor: "pointer",
          transition: "border-color 0.15s, background 0.15s",
        }}
      >
        <input
          ref={fileInputRef}
          type="file"
          style={{ display: "none" }}
          onChange={handleFileInput}
        />
        {droppedFile ? (
          <div>
            <div style={{ fontSize: "0.65rem", color: "rgba(0,255,136,0.8)", letterSpacing: "0.08em" }}>
              📄 {droppedFile.name}
            </div>
            <div style={{ fontSize: "0.55rem", color: "rgba(0,255,136,0.4)", marginTop: "0.35rem" }}>
              {(droppedFile.size / 1024).toFixed(1)} KB — click or drop to replace
            </div>
          </div>
        ) : (
          <div style={{ fontSize: "0.65rem", color: "rgba(0,255,136,0.35)", letterSpacing: "0.1em" }}>
            DROP_FILE_HERE — or click to browse
          </div>
        )}
      </div>

      {/* API key input */}
      <div>
        <label
          style={{
            display: "block",
            fontSize: "0.55rem",
            letterSpacing: "0.1em",
            color: "rgba(0,255,136,0.45)",
            marginBottom: "0.35rem",
          }}
        >
          API_KEY
        </label>
        <input
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="paste your API key"
          style={{
            width: "100%",
            background: "rgba(0,0,0,0.55)",
            border: `1px solid ${isAuthError ? "rgba(255,0,85,0.5)" : "rgba(0,255,136,0.25)"}`,
            color: isAuthError ? "#ff0055" : "rgba(0,255,136,0.85)",
            fontFamily: "'DM Mono', monospace",
            fontSize: "0.78rem",
            padding: "0.6rem 0.75rem",
            outline: "none",
            boxSizing: "border-box",
          }}
        />
      </div>

      {/* Commit + Reset buttons */}
      <div style={{ display: "flex", gap: "0.75rem" }}>
        <button
          type="button"
          onClick={() => void commit()}
          disabled={!droppedFile || !apiKey.trim() || stage === "committing"}
          className={skin.classes.buttonPrimary}
          style={{ flex: 1 }}
        >
          {stage === "committing" ? "COMMITTING..." : "COMMIT TO LEDGER →"}
        </button>
        {(droppedFile || stage !== "idle") && (
          <button
            type="button"
            onClick={reset}
            style={{
              background: "none",
              border: "none",
              color: "rgba(0,255,136,0.4)",
              fontFamily: "'DM Mono', monospace",
              fontSize: "0.65rem",
              letterSpacing: "0.08em",
              cursor: "pointer",
              padding: "0 0.5rem",
            }}
          >
            RESET
          </button>
        )}
      </div>

      {/* Error */}
      {error && (
        <div
          style={{
            padding: "0.75rem 1rem",
            border: "1px solid rgba(255,0,85,0.4)",
            background: "rgba(255,0,85,0.05)",
            color: "#ff0055",
            fontSize: "0.72rem",
          }}
        >
          {error}
        </div>
      )}

      {/* Success result */}
      {stage === "done" && result && (
        <div
          style={{
            padding: "1.25rem 1.5rem",
            border: "1px solid rgba(0,255,136,0.25)",
            background: "rgba(0,255,136,0.03)",
          }}
        >
          <div
            style={{
              fontSize: "0.55rem",
              letterSpacing: "0.14em",
              color: "rgba(0,255,136,0.5)",
              marginBottom: "1rem",
            }}
          >
            ✓ COMMITTED_TO_LEDGER
          </div>

          <FieldRow label="PROOF_ID" value={result.proof_id} />
          <FieldRow label="RECORD_ID" value={result.record_id} />
          <FieldRow label="SHARD_ID" value={result.shard_id} />
          <FieldRow label="CONTENT_HASH" value={result.content_hash} />
          <FieldRow label="MERKLE_ROOT" value={result.merkle_root} />
          <FieldRow label="COMMITTED_AT" value={result.timestamp} />
          <FieldRow
            label="SIZE"
            value={`${result.size_bytes.toLocaleString()} bytes`}
            dim
          />

          <div style={{ display: "flex", gap: "0.75rem", marginTop: "1.25rem" }}>
            <button
              type="button"
              onClick={() => downloadAttestation(result)}
              className={skin.classes.buttonPrimary}
              style={{ flex: 1 }}
            >
              DOWNLOAD ATTESTATION →
            </button>
            <button
              type="button"
              onClick={reset}
              style={{
                background: "none",
                border: "none",
                color: "rgba(0,255,136,0.4)",
                fontFamily: "'DM Mono', monospace",
                fontSize: "0.65rem",
                letterSpacing: "0.08em",
                cursor: "pointer",
                padding: "0 0.5rem",
              }}
            >
              COMMIT_ANOTHER
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
