import { useCallback, useRef, useState } from "react";
import { hashFile } from "../lib/blake3";

const API_BASE =
  (typeof import.meta !== "undefined" &&
    (import.meta as { env?: { VITE_API_BASE?: string } }).env?.VITE_API_BASE) ||
  (typeof window !== "undefined" ? window.location.origin : "");

type Stage = "idle" | "hashing" | "ready" | "committing" | "done" | "error";

type CommitResult = {
  proof_id: string;
  content_hash: string;
  record_id: string;
  shard_id: string;
  deduplicated: boolean;
};

function sanitizeId(s: string) {
  return s.replace(/[^a-zA-Z0-9_.:\-]/g, "-").replace(/^-+|-+$/g, "").slice(0, 200) || "record";
}

export default function IngestPage() {
  const [stage, setStage] = useState<Stage>("idle");
  const [file, setFile] = useState<File | null>(null);
  const [hash, setHash] = useState("");
  const [apiKey, setApiKey] = useState(() => localStorage.getItem("olympus_api_key") ?? "");
  const [shardId, setShardId] = useState("files");
  const [recordType, setRecordType] = useState("file");
  const [recordId, setRecordId] = useState("");
  const [result, setResult] = useState<CommitResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const processFile = useCallback(async (f: File) => {
    setFile(f);
    setStage("hashing");
    setHash("");
    setResult(null);
    setError(null);
    const auto = sanitizeId(f.name.replace(/\.[^.]+$/, ""));
    setRecordId(auto);
    try {
      const bytes = new Uint8Array(await f.arrayBuffer());
      const h = await hashFile(bytes);
      setHash(h);
      setStage("ready");
    } catch (e) {
      setError(String(e));
      setStage("error");
    }
  }, []);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) void processFile(f);
  }, [processFile]);

  const onPick = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) void processFile(f);
  }, [processFile]);

  async function commit() {
    if (!file || !hash || !apiKey.trim()) return;
    setStage("committing");
    setError(null);

    if (apiKey.trim()) localStorage.setItem("olympus_api_key", apiKey.trim());

    const content = {
      filename: file.name,
      size: file.size,
      type: file.type || "application/octet-stream",
      blake3: hash,
    };

    try {
      const res = await fetch(`${API_BASE}/ingest/records`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": apiKey.trim(),
        },
        body: JSON.stringify({
          records: [{
            shard_id: shardId.trim() || "files",
            record_type: recordType.trim() || "file",
            record_id: recordId.trim() || sanitizeId(file.name),
            version: 1,
            content,
          }],
        }),
      });

      const data = await res.json() as Record<string, unknown>;
      if (!res.ok) {
        const d = (data as { detail?: unknown }).detail;
        setError(typeof d === "string" ? d : typeof d === "object" && d !== null && "detail" in d ? String((d as { detail: unknown }).detail) : JSON.stringify(d));
        setStage("error");
        return;
      }

      const results = (data as { results?: CommitResult[] }).results;
      if (results?.[0]) {
        setResult(results[0]);
        setStage("done");
      }
    } catch (e) {
      setError(String(e));
      setStage("error");
    }
  }

  const inp: React.CSSProperties = {
    width: "100%",
    background: "rgba(0,0,0,0.65)",
    border: "1px solid rgba(0,255,65,0.22)",
    color: "#00ff41",
    fontFamily: "'DM Mono', monospace",
    fontSize: "0.78rem",
    padding: "0.6rem 0.75rem",
    outline: "none",
    boxSizing: "border-box",
  };

  const lbl: React.CSSProperties = {
    display: "block",
    fontSize: "0.58rem",
    letterSpacing: "0.1em",
    color: "rgba(0,255,65,0.5)",
    marginBottom: "0.35rem",
  };

  return (
    <div style={{ maxWidth: "600px", margin: "0 auto" }}>
      <div style={{ marginBottom: "2.5rem" }}>
        <div style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.4)", letterSpacing: "0.15em", marginBottom: "0.5rem" }}>
          OLYMPUS_PROTOCØL // INGEST
        </div>
        <h1 style={{ fontSize: "1.4rem", fontWeight: 400, margin: "0 0 0.6rem", letterSpacing: "0.04em" }}>
          COMMIT TO LEDGER
        </h1>
        <p style={{ fontSize: "0.7rem", color: "rgba(0,255,65,0.45)", margin: 0, lineHeight: 1.65 }}>
          Drop a file to hash it and commit the record to the append-only ledger. Once committed, the hash is permanently verifiable.
        </p>
      </div>

      {/* Drop zone */}
      <div
        onClick={() => inputRef.current?.click()}
        onDragOver={e => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        style={{
          border: `1px dashed ${dragging ? "rgba(0,255,65,0.7)" : "rgba(0,255,65,0.28)"}`,
          background: dragging ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.02)",
          padding: "2.5rem 1rem",
          textAlign: "center",
          cursor: "pointer",
          marginBottom: "1.5rem",
          transition: "all 0.15s",
        }}
      >
        <input ref={inputRef} type="file" onChange={onPick} style={{ display: "none" }} />
        {file ? (
          <div>
            <div style={{ fontSize: "0.85rem", color: "#00ff41", marginBottom: "0.4rem" }}>{file.name}</div>
            <div style={{ fontSize: "0.62rem", color: "rgba(0,255,65,0.45)" }}>
              {(file.size / 1024).toFixed(1)} KB · click to change
            </div>
          </div>
        ) : (
          <div style={{ fontSize: "0.72rem", color: "rgba(0,255,65,0.4)", letterSpacing: "0.08em" }}>
            DROP FILE HERE or click to browse
          </div>
        )}
      </div>

      {stage === "hashing" && (
        <div style={{ fontSize: "0.7rem", color: "rgba(0,255,65,0.6)", marginBottom: "1.5rem", letterSpacing: "0.08em" }}>
          COMPUTING BLAKE3...
        </div>
      )}

      {hash && (
        <div style={{ marginBottom: "1.5rem" }}>
          <div style={lbl}>BLAKE3 DIGEST</div>
          <code style={{
            display: "block",
            background: "rgba(0,255,65,0.05)",
            border: "1px solid rgba(0,255,65,0.18)",
            padding: "0.6rem 0.85rem",
            fontSize: "0.72rem",
            wordBreak: "break-all",
            color: "#00ff41",
            lineHeight: 1.5,
          }}>
            {hash}
          </code>
        </div>
      )}

      {(stage === "ready" || stage === "committing" || stage === "error") && (
        <div style={{ padding: "1.5rem", border: "1px solid rgba(0,255,65,0.14)", background: "rgba(0,255,65,0.02)", marginBottom: "1.5rem" }}>
          <div style={{ fontSize: "0.58rem", letterSpacing: "0.12em", color: "rgba(0,255,65,0.45)", marginBottom: "1.2rem" }}>
            COMMIT DETAILS
          </div>

          <div style={{ marginBottom: "1rem" }}>
            <label style={lbl}>API KEY</label>
            <input
              type="password"
              value={apiKey}
              onChange={e => setApiKey(e.target.value)}
              placeholder="your API key from registration"
              style={inp}
            />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1rem" }}>
            <div>
              <label style={lbl}>SHARD</label>
              <input type="text" value={shardId} onChange={e => setShardId(e.target.value)} style={inp} />
            </div>
            <div>
              <label style={lbl}>TYPE</label>
              <input type="text" value={recordType} onChange={e => setRecordType(e.target.value)} style={inp} />
            </div>
          </div>

          <div style={{ marginBottom: "1.5rem" }}>
            <label style={lbl}>RECORD ID</label>
            <input type="text" value={recordId} onChange={e => setRecordId(e.target.value)} style={inp} />
          </div>

          <button
            type="button"
            onClick={() => void commit()}
            disabled={stage === "committing" || !apiKey.trim()}
            style={{
              width: "100%",
              padding: "0.8rem",
              background: stage === "committing" ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.13)",
              border: "1px solid rgba(0,255,65,0.55)",
              color: "#00ff41",
              fontFamily: "'DM Mono', monospace",
              fontSize: "0.72rem",
              letterSpacing: "0.14em",
              cursor: stage === "committing" || !apiKey.trim() ? "not-allowed" : "pointer",
            }}
          >
            {stage === "committing" ? "COMMITTING..." : "COMMIT TO LEDGER"}
          </button>

          {error && (
            <div style={{ marginTop: "1rem", padding: "0.75rem 1rem", border: "1px solid rgba(255,0,85,0.4)", color: "#ff0055", fontSize: "0.7rem", background: "rgba(255,0,85,0.05)" }}>
              {error}
            </div>
          )}
        </div>
      )}

      {stage === "done" && result && (
        <div style={{ padding: "1.5rem", border: "1px solid rgba(0,255,65,0.35)", background: "rgba(0,255,65,0.03)" }}>
          <div style={{ fontSize: "0.58rem", letterSpacing: "0.12em", color: "rgba(0,255,65,0.5)", marginBottom: "1.2rem" }}>
            {result.deduplicated ? "ALREADY ON LEDGER" : "COMMITTED TO LEDGER"}
          </div>

          <div style={{ marginBottom: "0.8rem" }}>
            <div style={lbl}>CONTENT HASH</div>
            <code style={{ fontSize: "0.7rem", color: "#00ff41", wordBreak: "break-all", lineHeight: 1.5, display: "block" }}>
              {result.content_hash}
            </code>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1.5rem", fontSize: "0.65rem", color: "rgba(0,255,65,0.6)" }}>
            <div>
              <div style={lbl}>PROOF ID</div>
              <code style={{ fontSize: "0.65rem", color: "rgba(0,255,65,0.8)", wordBreak: "break-all" }}>{result.proof_id}</code>
            </div>
            <div>
              <div style={lbl}>SHARD</div>
              <code style={{ fontSize: "0.65rem", color: "rgba(0,255,65,0.8)" }}>{result.shard_id}</code>
            </div>
          </div>

          <a
            href={`/verify#${result.content_hash}`}
            style={{
              display: "block",
              padding: "0.75rem",
              border: "1px solid rgba(0,255,65,0.4)",
              color: "#00ff41",
              textDecoration: "none",
              fontFamily: "'DM Mono', monospace",
              fontSize: "0.7rem",
              letterSpacing: "0.1em",
              textAlign: "center",
              background: "rgba(0,255,65,0.08)",
            }}
          >
            VERIFY THIS RECORD
          </a>
        </div>
      )}
    </div>
  );
}
