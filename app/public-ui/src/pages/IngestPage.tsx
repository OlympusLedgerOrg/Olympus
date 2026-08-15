import { useCallback, useRef, useState } from "react";
import { hashFile } from "../lib/blake3";
import {
  apiKeyProblem,
  clearStoredApiKey,
  getStoredApiKey,
  normalizeApiKey,
  setStoredApiKey,
} from "../lib/storage";

import { apiFetch, isTauri, tauriInvoke } from "../lib/api";

type Stage = "idle" | "hashing" | "ready" | "committing" | "done" | "error";

type CommitResult = {
  proof_id: string;
  content_hash: string;
  record_id: string;
  shard_id: string;
  deduplicated: boolean;
  /** Segmentation format this request committed; null when nothing was
   *  segmented (deduplicated upload, or a document with no segmenter). */
  redaction_format: string | null;
};

/** Redaction granularity offered at ingest (ADR-0029 B1). Object is the
 *  conservative default; word is strictly opt-in and can be declined by the
 *  server — see the notice rendered from `redaction_format` below. */
type Granularity = "object" | "word";

function sanitizeId(s: string) {
  return (
    s
      .replace(/[^a-zA-Z0-9_.:-]/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 200) || "record"
  );
}

const inp: React.CSSProperties = {
  width: "100%",
  background: "rgba(0,0,0,0.65)",
  border: "1px solid rgba(0,255,65,0.22)",
  color: "#00ff41",
  fontFamily: "var(--font-terminal)",
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

/** Amber panel for "committed, but not the way you asked" outcomes on the
 *  result screen. Shared so the three redaction-format notices cannot drift
 *  into looking like different severities of the same thing. */
const notice: React.CSSProperties = {
  marginBottom: "1.2rem",
  padding: "0.6rem",
  fontSize: "0.68rem",
  color: "rgba(255,196,0,0.9)",
  border: "1px solid rgba(255,196,0,0.35)",
  background: "rgba(255,196,0,0.05)",
};

export default function IngestPage() {
  const [stage, setStage] = useState<Stage>("idle");
  const [file, setFile] = useState<File | null>(null);
  const [hash, setHash] = useState("");
  const [apiKey, setApiKey] = useState(() => getStoredApiKey());
  const [shardId, setShardId] = useState("files");
  const [recordType, setRecordType] = useState("file");
  const [recordId, setRecordId] = useState("");
  const [granularity, setGranularity] = useState<Granularity>("object");
  const [result, setResult] = useState<CommitResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [keySaved, setKeySaved] = useState(false);
  const [dragDropHint, setDragDropHint] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  // Validate the *normalized* key so a pasted key with leading/trailing
  // whitespace isn't falsely flagged as invalid by the UI gating — save/commit
  // already normalize before sending.
  const currentKeyProblem = apiKey.trim() ? apiKeyProblem(normalizeApiKey(apiKey)) : null;

  function saveKey() {
    const normalized = normalizeApiKey(apiKey);
    const problem = apiKeyProblem(normalized);
    if (problem) {
      setError(problem);
      // Don't transition the ingest workflow stage on Save-Key validation —
      // it's a key-form problem, not a commit failure.
      return;
    }
    setApiKey(normalized);
    setStoredApiKey(normalized);
    setKeySaved(true);
    setTimeout(() => setKeySaved(false), 2000);
  }

  const processFile = useCallback(async (f: File) => {
    setFile(f);
    setStage("hashing");
    setHash("");
    setResult(null);
    setError(null);
    setRecordId(sanitizeId(f.name.replace(/\.[^.]+$/, "")));
    try {
      const h = await hashFile(f);
      setHash(h);
      setStage("ready");
    } catch (e) {
      setError(String(e));
      setStage("error");
    }
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const f = e.dataTransfer.files[0];
      // WSLg's RDP drag bridge between Windows Explorer and webkit2gtk
      // frequently delivers either no file or a zero-byte / unreadable
      // File object. Surface a clear error pointing at the picker instead
      // of silently doing nothing — that's the single most-reported papercut.
      if (!f || f.size === 0) {
        setDragDropHint(
          "Drag-drop from Windows Explorer can't reach the WSL window — " +
            "click the drop zone instead and use Ctrl+L in the picker to type " +
            "a path like /mnt/c/Users/<your-windows-name>/Documents/.",
        );
        return;
      }
      setDragDropHint(null);
      void processFile(f);
    },
    [processFile],
  );

  const onPick = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const f = e.target.files?.[0];
      if (f) void processFile(f);
    },
    [processFile],
  );

  /// Tauri native file dialog — preferred over the HTML <input> because
  /// the GTK chooser (and Win32 picker) navigate outside the webview
  /// sandbox by default, e.g. straight to /mnt/c/Users/... under WSLg.
  /// The Rust side reads the bytes too so we don't need a separate FS
  /// plugin on the JS side. Falls back silently when not under Tauri
  /// (browser dev mode).
  const pickViaNativeDialog = useCallback(async () => {
    if (!isTauri()) {
      inputRef.current?.click();
      return;
    }
    try {
      const picked = await tauriInvoke<{
        name: string;
        path: string;
        bytes: number[];
      } | null>("open_file_dialog");
      if (!picked) return;
      const file = new File([new Uint8Array(picked.bytes)], picked.name);
      void processFile(file);
    } catch (e) {
      setError(`open file failed: ${String(e)}`);
      setStage("error");
    }
  }, [processFile]);

  async function commit() {
    if (!file || !hash || !apiKey.trim()) return;
    const normalizedApiKey = normalizeApiKey(apiKey);
    const keyProblem = apiKeyProblem(normalizedApiKey);
    if (keyProblem) {
      setError(keyProblem);
      setStage("error");
      return;
    }

    setStage("committing");
    setError(null);
    setStoredApiKey(normalizedApiKey);

    // Audit H-5: the JSON `POST /ingest/records` endpoint was removed —
    // it accepted a client-supplied blake3 attestation, which broke the
    // ledger's headline integrity claim (the server never saw the
    // preimage of the hash it was committing to). All commits now go
    // through `POST /ingest/files`, which uploads the bytes so the
    // server can hash them itself. The local `hash` computed above is
    // kept only as a UI sanity check — the canonical hash is whatever
    // the server returns.
    try {
      // The `/ingest/files` multipart contract: file + optional
      // shard_id/record_id/version/original_hash. record_type is
      // server-derived (file vs redaction). Unknown fields are silently
      // discarded — the locally-computed `hash` above is shown to the
      // user as a UI sanity check but the server's own BLAKE3 of the
      // uploaded bytes is canonical, so we don't send it on the wire.
      const form = new FormData();
      form.append("file", file, file.name);
      form.append("shard_id", shardId.trim() || "files");
      form.append("record_id", recordId.trim() || sanitizeId(file.name));
      form.append("version", "1");
      form.append("granularity", granularity);

      const data = await apiFetch<CommitResult>("/ingest/files", {
        method: "POST",
        headers: { "X-API-Key": normalizedApiKey },
        body: form,
      });

      setResult(data);
      setStage("done");
    } catch (e) {
      setError(String(e));
      setStage("error");
    }
  }

  return (
    <div style={{ maxWidth: "600px", margin: "0 auto" }}>
      <div style={{ marginBottom: "2rem" }}>
        <div
          style={{
            fontSize: "0.6rem",
            color: "rgba(0,255,65,0.4)",
            letterSpacing: "0.15em",
            marginBottom: "0.5rem",
          }}
        >
          OLYMPUS_PROTOCØL // LEDGER
        </div>
        <h1
          style={{
            fontSize: "1.4rem",
            fontWeight: 400,
            margin: "0 0 0.5rem",
            letterSpacing: "0.04em",
          }}
        >
          COMMIT TO LEDGER
        </h1>
        <p
          style={{ fontSize: "0.7rem", color: "rgba(0,255,65,0.45)", margin: 0, lineHeight: 1.65 }}
        >
          Drop a file — it gets BLAKE3-hashed locally, then committed to the append-only ledger.
          Once sealed, permanently verifiable.
        </p>
      </div>

      {/* API Key — always visible */}
      <div
        style={{
          marginBottom: "1.5rem",
          padding: "1rem 1.25rem",
          border: "1px solid rgba(0,255,65,0.18)",
          background: "rgba(0,255,65,0.02)",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "0.5rem",
          }}
        >
          <label style={lbl}>API KEY</label>
          <button
            type="button"
            onClick={saveKey}
            style={{
              background: keySaved ? "rgba(0,255,65,0.18)" : "transparent",
              border: "1px solid rgba(0,255,65,0.3)",
              color: "rgba(0,255,65,0.7)",
              fontFamily: "var(--font-terminal)",
              fontSize: "0.55rem",
              letterSpacing: "0.08em",
              padding: "0.2rem 0.6rem",
              cursor: "pointer",
            }}
          >
            {keySaved ? "SAVED" : "SAVE KEY"}
          </button>
          <button
            type="button"
            onClick={() => {
              clearStoredApiKey();
              setApiKey("");
            }}
            style={{
              background: "transparent",
              border: "1px solid rgba(0,255,65,0.2)",
              color: "rgba(0,255,65,0.55)",
              fontFamily: "var(--font-terminal)",
              fontSize: "0.55rem",
              letterSpacing: "0.08em",
              padding: "0.2rem 0.6rem",
              cursor: "pointer",
              marginLeft: "0.5rem",
            }}
          >
            CLEAR KEY
          </button>
        </div>
        <input
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value.slice(0, 68))}
          placeholder="paste your API key (64-hex, with or without `oly_` prefix)"
          style={inp}
          maxLength={68}
          spellCheck={false}
          autoComplete="off"
        />
        {!apiKey.trim() && (
          <div style={{ fontSize: "0.6rem", color: "rgba(255,165,0,0.65)", marginTop: "0.4rem" }}>
            No key found — paste your API key above. Get one on the KEYS tab.
          </div>
        )}
        {currentKeyProblem && (
          <div
            style={{ fontSize: "0.6rem", color: "#ff0055", marginTop: "0.4rem", lineHeight: 1.4 }}
          >
            {currentKeyProblem}
          </div>
        )}
      </div>

      {/* Drop zone */}
      <div
        onClick={() => inputRef.current?.click()}
        onDragEnter={(e) => {
          // Surface the WSL/foreign-drag hint BEFORE the user releases.
          // Windows Explorer drags into webkit2gtk-under-WSLg arrive
          // without "Files" in dataTransfer.types — only "text/uri-list"
          // or empty — because the RDP drag bridge doesn't translate
          // CF_HDROP. Detecting at dragenter collapses the failure loop
          // from "drag, drop, fail, retry, fail, finally see banner" to
          // "drag, see banner, click picker".
          const types = Array.from(e.dataTransfer.types);
          if (!types.includes("Files")) {
            setDragDropHint(
              "Drag-drop from Windows Explorer can't reach the WSL window — " +
                "click the drop zone instead and use Ctrl+L in the picker to type " +
                "a path like /mnt/c/Users/<your-windows-name>/Documents/.",
            );
            setDragging(false);
          } else {
            setDragging(true);
          }
        }}
        onDragOver={(e) => {
          e.preventDefault();
        }}
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
            <div style={{ fontSize: "0.85rem", color: "#00ff41", marginBottom: "0.4rem" }}>
              {file.name}
            </div>
            <div style={{ fontSize: "0.62rem", color: "rgba(0,255,65,0.45)" }}>
              {(file.size / 1024).toFixed(1)} KB · click to change
            </div>
          </div>
        ) : (
          <div
            style={{ fontSize: "0.72rem", color: "rgba(0,255,65,0.4)", letterSpacing: "0.08em" }}
          >
            DROP FILE HERE or click to browse
          </div>
        )}
      </div>
      {/* Native file picker — opens the GTK chooser under WSLg and the
          Win32 picker on Windows. Both can navigate to /mnt/c/Users/
          (or C:\) which the HTML <input> cannot. */}
      <div style={{ marginTop: "-1rem", marginBottom: "1.5rem", textAlign: "center" }}>
        <button
          type="button"
          onClick={pickViaNativeDialog}
          style={{
            background: "rgba(0,255,65,0.05)",
            border: "1px dashed rgba(0,255,65,0.3)",
            color: "rgba(0,255,65,0.8)",
            fontFamily: "var(--font-terminal)",
            fontSize: "0.6rem",
            letterSpacing: "0.1em",
            padding: "0.35rem 0.9rem",
            cursor: "pointer",
          }}
        >
          OPEN FILE…
        </button>
        <span style={{ marginLeft: "0.6rem", fontSize: "0.55rem", color: "rgba(0,255,65,0.4)" }}>
          (recommended on WSL — opens the native chooser)
        </span>
      </div>

      {dragDropHint && (
        <div
          style={{
            marginTop: "-1rem",
            marginBottom: "1.5rem",
            padding: "0.6rem 0.8rem",
            border: "1px solid rgba(255,165,0,0.35)",
            background: "rgba(255,165,0,0.06)",
            color: "rgba(255,200,120,0.9)",
            fontSize: "0.65rem",
            lineHeight: 1.5,
            letterSpacing: "0.04em",
          }}
        >
          {dragDropHint}
        </div>
      )}

      {stage === "hashing" && (
        <div
          style={{
            fontSize: "0.7rem",
            color: "rgba(0,255,65,0.6)",
            marginBottom: "1.5rem",
            letterSpacing: "0.08em",
          }}
        >
          COMPUTING BLAKE3...
        </div>
      )}

      {hash && (
        <div style={{ marginBottom: "1.5rem" }}>
          <label style={lbl}>BLAKE3 DIGEST</label>
          <code
            style={{
              display: "block",
              background: "rgba(0,255,65,0.05)",
              border: "1px solid rgba(0,255,65,0.18)",
              padding: "0.6rem 0.85rem",
              fontSize: "0.72rem",
              wordBreak: "break-all",
              color: "#00ff41",
              lineHeight: 1.5,
            }}
          >
            {hash}
          </code>
        </div>
      )}

      {(stage === "ready" || stage === "committing" || stage === "error") && (
        <div
          style={{
            padding: "1.5rem",
            border: "1px solid rgba(0,255,65,0.14)",
            background: "rgba(0,255,65,0.02)",
            marginBottom: "1.5rem",
          }}
        >
          <div
            style={{
              fontSize: "0.58rem",
              letterSpacing: "0.12em",
              color: "rgba(0,255,65,0.45)",
              marginBottom: "1.2rem",
            }}
          >
            COMMIT DETAILS
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "1rem",
              marginBottom: "1rem",
            }}
          >
            <div>
              <label style={lbl}>SHARD</label>
              <input
                type="text"
                value={shardId}
                onChange={(e) => setShardId(e.target.value)}
                style={inp}
              />
            </div>
            <div>
              <label style={lbl}>TYPE</label>
              <input
                type="text"
                value={recordType}
                onChange={(e) => setRecordType(e.target.value)}
                style={inp}
              />
            </div>
            <div>
              <label style={lbl}>REDACTION GRANULARITY</label>
              <select
                value={granularity}
                onChange={(e) => {
                  setGranularity(e.target.value as Granularity);
                }}
                style={inp}
                aria-label="Redaction granularity"
              >
                <option value="object">object — whole PDF objects</option>
                <option value="word">word — individual words (PDF only)</option>
              </select>
            </div>
          </div>

          <div style={{ marginBottom: "1.5rem" }}>
            <label style={lbl}>RECORD ID</label>
            <input
              type="text"
              value={recordId}
              onChange={(e) => setRecordId(e.target.value)}
              style={inp}
            />
          </div>

          <button
            type="button"
            onClick={() => void commit()}
            disabled={stage === "committing" || !apiKey.trim() || Boolean(currentKeyProblem)}
            style={{
              width: "100%",
              padding: "0.8rem",
              background: stage === "committing" ? "rgba(0,255,65,0.06)" : "rgba(0,255,65,0.13)",
              border: "1px solid rgba(0,255,65,0.55)",
              color: "#00ff41",
              fontFamily: "var(--font-terminal)",
              fontSize: "0.72rem",
              letterSpacing: "0.14em",
              cursor:
                stage === "committing" || !apiKey.trim() || Boolean(currentKeyProblem)
                  ? "not-allowed"
                  : "pointer",
            }}
          >
            {stage === "committing"
              ? "COMMITTING..."
              : !apiKey.trim()
                ? "ENTER API KEY ABOVE TO COMMIT"
                : "COMMIT TO LEDGER"}
          </button>

          {error && (
            <div
              style={{
                marginTop: "1rem",
                padding: "0.75rem 1rem",
                border: "1px solid rgba(255,0,85,0.4)",
                color: "#ff0055",
                fontSize: "0.7rem",
                background: "rgba(255,0,85,0.05)",
              }}
            >
              {error}
            </div>
          )}
        </div>
      )}

      {stage === "done" && result && (
        <div
          style={{
            padding: "1.5rem",
            border: "1px solid rgba(0,255,65,0.35)",
            background: "rgba(0,255,65,0.03)",
          }}
        >
          <div
            style={{
              fontSize: "0.58rem",
              letterSpacing: "0.12em",
              color: "rgba(0,255,65,0.5)",
              marginBottom: "1.2rem",
            }}
          >
            {result.deduplicated ? "ALREADY ON LEDGER" : "COMMITTED TO LEDGER ✓"}
          </div>

          {/* The server may decline word granularity and commit at object
              granularity instead — a scanned PDF with no extractable text, a
              document past the segment cap, an unparsable structure. The
              document may also never have been a candidate: `granularity`
              steers only the PDF branch of segmentation, so a text or OOXML
              upload commits at its own format regardless. Either way the
              operator asked for something they did not get, so say so rather
              than let them find out in the redaction tab — and NAME the
              committed format rather than describing what it offers, because
              `text-line` and `ooxml-part` are not object redaction.
              A null `redaction_format` means nothing was segmented on this
              request; the two situations it covers get their own notices
              below, because neither is a demotion and claiming one would be
              wrong. */}
          {granularity === "word" &&
            !!result.redaction_format &&
            result.redaction_format !== "pdf-textrun" && (
              <div style={notice}>
                Word granularity was requested but could not be applied to this document; it was
                committed at <code>{result.redaction_format}</code> instead, so redaction will not
                offer individual words.
              </div>
            )}

          {/* Nothing segmented, content already on the ledger. The record keeps
              whatever its FIRST ingest committed, and no re-upload can change
              that: the ledger is insert-only (ADR-0031 §2), so re-segmenting at
              a new granularity would have to rewrite a committed root. Silence
              here sent the operator to the redaction tab to discover for
              themselves that their word request did nothing. We do not name the
              committed format because this response does not carry it — the
              redaction tab reads it from the manifest.

              Name the way out, or this reads as a dead end: the ingest row is
              keyed `ON CONFLICT (content_hash, shard_id)`, so a distinct record
              means different content OR this same file under a different shard
              — and the shard is a field on this very page. */}
          {granularity === "word" && !result.redaction_format && result.deduplicated && (
            <div style={notice}>
              This content was already on the ledger, so nothing was segmented on this upload and
              the word request had no effect. Granularity is fixed by a record&apos;s first ingest —
              the ledger is insert-only, so re-uploading the same file cannot re-segment it.
              Reaching word granularity needs a distinct record: this file under a different shard,
              or different content. Open the existing record in the redaction tab to see what it
              offers.
            </div>
          )}

          {/* Nothing segmented, and this WAS a fresh commit — no segmenter took
              the document, so the chunk root stands and it has no redactable
              segments at all: not words, not objects. Worth saying
              whatever granularity was asked for, because "COMMITTED TO LEDGER
              ✓" otherwise implies a redaction affordance that does not exist.
              The record is still committed and still provable; only redaction
              is unavailable. */}
          {!result.redaction_format && !result.deduplicated && (
            <div style={notice}>
              This document could not be segmented for redaction. It is on the ledger and provable,
              but the redaction tab will not offer words or objects for it.
            </div>
          )}

          <div style={{ marginBottom: "0.8rem" }}>
            <label style={lbl}>CONTENT HASH</label>
            <code
              style={{
                fontSize: "0.7rem",
                color: "#00ff41",
                wordBreak: "break-all",
                lineHeight: 1.5,
                display: "block",
              }}
            >
              {result.content_hash}
            </code>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "1rem",
              marginBottom: "1.5rem",
              fontSize: "0.65rem",
              color: "rgba(0,255,65,0.6)",
            }}
          >
            <div>
              <label style={lbl}>PROOF ID</label>
              <code
                style={{ fontSize: "0.65rem", color: "rgba(0,255,65,0.8)", wordBreak: "break-all" }}
              >
                {result.proof_id}
              </code>
            </div>
            <div>
              <label style={lbl}>SHARD</label>
              <code style={{ fontSize: "0.65rem", color: "rgba(0,255,65,0.8)" }}>
                {result.shard_id}
              </code>
            </div>
          </div>

          <div style={{ display: "flex", gap: "0.75rem" }}>
            <a
              href={`/verify#${result.content_hash}`}
              style={{
                flex: 1,
                display: "block",
                padding: "0.75rem",
                border: "1px solid rgba(0,255,65,0.4)",
                color: "#00ff41",
                textDecoration: "none",
                fontFamily: "var(--font-terminal)",
                fontSize: "0.7rem",
                letterSpacing: "0.1em",
                textAlign: "center",
                background: "rgba(0,255,65,0.08)",
              }}
            >
              VERIFY THIS RECORD
            </a>
            <button
              type="button"
              onClick={() => {
                setStage("idle");
                setFile(null);
                setHash("");
                setResult(null);
                setError(null);
              }}
              style={{
                flex: 1,
                padding: "0.75rem",
                background: "transparent",
                border: "1px solid rgba(0,255,65,0.2)",
                color: "rgba(0,255,65,0.5)",
                fontFamily: "var(--font-terminal)",
                fontSize: "0.7rem",
                letterSpacing: "0.1em",
                cursor: "pointer",
              }}
            >
              COMMIT ANOTHER
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
