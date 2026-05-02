import { useCallback, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  getPublicStats,
  verifyHash,
  verifyProofBundle,
  type PublicStatsResponse,
} from "../lib/api";
import { addRecentVerification } from "../lib/storage";
import { hashBytes } from "../lib/blake3";
import { canonicalJsonEncode, type CanonicalJsonValue } from "../lib/crypto";
import { playGlitchSound } from "../lib/audio";
import type {
  HashVerificationResponse,
  ProofVerificationRequest,
  ProofVerificationResponse,
  RecentVerificationEntry,
  Verdict,
  VerdictDetail,
} from "../lib/types";
import AnimatedNumber from "../components/AnimatedNumber";
import FileHasher from "../components/FileHasher";
import HashDisplay from "../components/HashDisplay";
import RecentVerifications from "../components/RecentVerifications";
import TiltContainer from "../components/TiltContainer";
import VerdictCard from "../components/VerdictCard";

const API_BASE =
  (typeof import.meta !== "undefined" &&
    (import.meta as { env?: { VITE_API_BASE?: string } }).env?.VITE_API_BASE) ||
  (typeof window !== "undefined" ? window.location.origin : "");

function sanitizeId(s: string) {
  return s.replace(/[^a-zA-Z0-9_.:\-]/g, "-").replace(/^-+|-+$/g, "").slice(0, 200) || "record";
}

type CommitStage = "idle" | "committing" | "done" | "error";

type Tab = "hash" | "file" | "json" | "proof";

const HASH_RE = /^[0-9a-f]{64}$/i;
const SAMPLE_HASH = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const FALLBACK_STATS: PublicStatsResponse = {
  copies: 0,
  shards: 0,
  proofs: 0,
  uptime: "0s",
  uptime_seconds: 0,
};

const EXAMPLE_PROOF = {
  content_hash: SAMPLE_HASH,
  merkle_root: SAMPLE_HASH,
  merkle_proof: {
    leaf_hash: SAMPLE_HASH,
    siblings: [],
    root_hash: SAMPLE_HASH,
  },
};

function hashVerificationToVerdict(
  resp: HashVerificationResponse,
): { verdict: Verdict; details: VerdictDetail[] } {
  const verdict: Verdict = resp.merkle_proof_valid ? "verified" : "failed";
  return {
    verdict,
    details: [
      { key: "Content Hash", value: resp.content_hash, status: "ok", copyable: true },
      { key: "Proof ID", value: resp.proof_id, status: "neutral", copyable: true },
      { key: "Record ID", value: resp.record_id, status: "neutral", copyable: true },
      { key: "Shard ID", value: resp.shard_id, status: "neutral" },
      { key: "Merkle Root", value: resp.merkle_root, status: "neutral", copyable: true },
      {
        key: "Merkle Proof",
        value: resp.merkle_proof_valid ? "Valid" : "Invalid",
        status: resp.merkle_proof_valid ? "ok" : "err",
      },
      {
        key: "Ledger Entry Hash",
        value: resp.ledger_entry_hash,
        status: "neutral",
        copyable: true,
      },
      {
        key: "Committed",
        value: new Date(resp.timestamp).toLocaleString(),
        status: "neutral",
      },
      ...(resp.poseidon_root
        ? [
            {
              key: "Poseidon Root",
              value: resp.poseidon_root,
              status: "neutral" as const,
              copyable: true,
            },
          ]
        : []),
    ],
  };
}

function proofVerificationToVerdict(
  resp: ProofVerificationResponse,
): { verdict: Verdict; details: VerdictDetail[] } {
  const allValid =
    resp.content_hash_matches_proof &&
    resp.merkle_proof_valid &&
    resp.known_to_server;
  const verdict: Verdict = allValid
    ? "verified"
    : resp.known_to_server
      ? "failed"
      : "unknown";
  return {
    verdict,
    details: [
      { key: "Content Hash", value: resp.content_hash, status: "neutral", copyable: true },
      { key: "Merkle Root", value: resp.merkle_root, status: "neutral", copyable: true },
      {
        key: "Hash Matches Proof",
        value: resp.content_hash_matches_proof ? "Yes" : "No",
        status: resp.content_hash_matches_proof ? "ok" : "err",
      },
      {
        key: "Merkle Proof Valid",
        value: resp.merkle_proof_valid ? "Yes" : "No",
        status: resp.merkle_proof_valid ? "ok" : "err",
      },
      {
        key: "Known to Server",
        value: resp.known_to_server ? "Yes" : "No",
        status: resp.known_to_server ? "ok" : "warn",
      },
    ],
  };
}

export default function HomePage() {
  const [activeTab, setActiveTab] = useState<Tab>("hash");
  const [hashInput, setHashInput] = useState("");
  const [hashError, setHashError] = useState<string | null>(null);
  const [fileHash, setFileHash] = useState<string | null>(null);
  const [fileProgress, setFileProgress] = useState(0);
  const [jsonInput, setJsonInput] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [jsonCanonical, setJsonCanonical] = useState<string | null>(null);
  const [proofInput, setProofInput] = useState("");
  const [proofError, setProofError] = useState<string | null>(null);
  const [verdictResult, setVerdictResult] = useState<{
    verdict: Verdict;
    details: VerdictDetail[];
    displayHash?: string;
  } | null>(null);

  const [droppedFile, setDroppedFile] = useState<File | null>(null);
  const [apiKey, setApiKey] = useState(() => localStorage.getItem("olympus_api_key") ?? "");
  const [commitStage, setCommitStage] = useState<CommitStage>("idle");
  const [commitError, setCommitError] = useState<string | null>(null);
  const [commitContentHash, setCommitContentHash] = useState<string | null>(null);

  const statsQuery = useQuery({
    queryKey: ["public-stats"],
    queryFn: getPublicStats,
    staleTime: 15_000,
    refetchInterval: 30_000,
  });
  const stats = statsQuery.data ?? FALLBACK_STATS;

  const normalizedHash = hashInput.trim().toLowerCase();
  const hashStatus = useMemo(() => {
    if (!normalizedHash) return { label: "WAITING", tone: "neutral" as const };
    if (normalizedHash.length !== 64) {
      return { label: `${normalizedHash.length}/64`, tone: "warn" as const };
    }
    if (!HASH_RE.test(normalizedHash)) {
      return { label: "BAD_HEX", tone: "err" as const };
    }
    return { label: "READY", tone: "ok" as const };
  }, [normalizedHash]);

  const switchTab = (id: Tab) => {
    setActiveTab(id);
    setVerdictResult(null);
    setHashError(null);
    setProofError(null);
    setJsonError(null);
    setCommitStage("idle");
    setCommitError(null);
    setCommitContentHash(null);
    playGlitchSound("blip");
  };

  const hashMutation = useMutation({
    mutationFn: verifyHash,
    onSuccess: (data) => {
      const result = hashVerificationToVerdict(data);
      setVerdictResult({ ...result, displayHash: data.content_hash });
      addRecentVerification({
        hash: data.content_hash,
        type: activeTab === "file" ? "file" : activeTab === "json" ? "json" : "hash",
        verdict: result.verdict,
        timestamp: Date.now(),
      } satisfies RecentVerificationEntry);
    },
    onError: (err) => {
      if (err instanceof Error && err.message.includes("404")) {
        const qHash = hashInput || fileHash || "";
        setVerdictResult({
          verdict: "unknown",
          details: [{ key: "Queried Hash", value: qHash, status: "warn", copyable: true }],
          displayHash: qHash || undefined,
        });
        addRecentVerification({
          hash: qHash,
          type: activeTab === "file" ? "file" : activeTab === "json" ? "json" : "hash",
          verdict: "unknown",
          timestamp: Date.now(),
        });
      } else {
        setHashError(err instanceof Error ? err.message : "Verification failed");
      }
    },
  });

  const proofMutation = useMutation({
    mutationFn: verifyProofBundle,
    onSuccess: (data) => {
      const result = proofVerificationToVerdict(data);
      setVerdictResult({ ...result, displayHash: data.content_hash });
      addRecentVerification({
        hash: data.content_hash,
        type: "proof",
        verdict: result.verdict,
        timestamp: Date.now(),
      });
    },
    onError: (err) => {
      setProofError(err instanceof Error ? err.message : "Verification failed");
    },
  });

  const submitHash = useCallback(
    (hash: string) => {
      setHashError(null);
      setVerdictResult(null);
      const normalized = hash.trim().toLowerCase();
      if (!HASH_RE.test(normalized)) {
        setHashError("Enter a valid 64-character hexadecimal BLAKE3 hash");
        return;
      }
      setHashInput(normalized);
      hashMutation.mutate(normalized);
    },
    [hashMutation],
  );

  const commitFile = useCallback(async () => {
    if (!droppedFile || !fileHash || !apiKey.trim()) return;
    setCommitStage("committing");
    setCommitError(null);
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
          records: [{ shard_id: "files", record_type: "file", record_id: recordId, version: 1, content }],
        }),
      });
      const data = await res.json() as Record<string, unknown>;
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

  const pasteHash = useCallback(async () => {
    try {
      const text = await navigator.clipboard.readText();
      setHashInput(text.trim());
      setHashError(null);
    } catch {
      setHashError("Clipboard read was blocked by the browser");
    }
  }, []);

  const submitJsonDoc = useCallback(async () => {
    setJsonError(null);
    setJsonCanonical(null);
    setVerdictResult(null);

    try {
      const parsed = JSON.parse(jsonInput) as CanonicalJsonValue;
      const canon = canonicalJsonEncode(parsed);
      const hex = await hashBytes(new TextEncoder().encode(canon));
      setJsonCanonical(canon);
      setHashInput(hex);
      submitHash(hex);
    } catch (err) {
      setJsonError(err instanceof Error ? err.message : String(err));
    }
  }, [jsonInput, submitHash]);

  const formatJson = useCallback(() => {
    try {
      setJsonInput(JSON.stringify(JSON.parse(jsonInput) as CanonicalJsonValue, null, 2));
      setJsonError(null);
    } catch (err) {
      setJsonError(err instanceof Error ? err.message : String(err));
    }
  }, [jsonInput]);

  const minifyJson = useCallback(() => {
    try {
      setJsonInput(JSON.stringify(JSON.parse(jsonInput) as CanonicalJsonValue));
      setJsonError(null);
    } catch (err) {
      setJsonError(err instanceof Error ? err.message : String(err));
    }
  }, [jsonInput]);

  const submitProof = useCallback(() => {
    setProofError(null);
    setVerdictResult(null);
    try {
      const parsed = JSON.parse(proofInput) as ProofVerificationRequest;
      if (!parsed.content_hash || !parsed.merkle_root || !parsed.merkle_proof) {
        setProofError("Bundle must include content_hash, merkle_root, and merkle_proof");
        return;
      }
      proofMutation.mutate(parsed);
    } catch {
      setProofError("Invalid JSON: paste the full proof bundle");
    }
  }, [proofInput, proofMutation]);

  const clearWorkspace = () => {
    setHashInput("");
    setHashError(null);
    setFileHash(null);
    setFileProgress(0);
    setJsonInput("");
    setJsonError(null);
    setJsonCanonical(null);
    setProofInput("");
    setProofError(null);
    setVerdictResult(null);
    setCommitContentHash(null);
  };

  const isPending = hashMutation.isPending || proofMutation.isPending;
  const operationLabel = isPending
    ? "VERIFYING"
    : verdictResult
      ? verdictResult.verdict.toUpperCase()
      : "IDLE";
  const tabs: { id: Tab; label: string }[] = [
    { id: "hash", label: "HASH" },
    { id: "file", label: "FILE" },
    { id: "json", label: "JSON_DOC" },
    { id: "proof", label: "PROOF_BUNDLE" },
  ];
  const statCards = [
    { label: "COPIES", value: stats.copies },
    { label: "SHARDS", value: stats.shards },
    { label: "PROOFS", value: stats.proofs },
    { label: "UPTIME", value: stats.uptime, raw: true },
  ];

  return (
    <div>
      <div className="console-hero">
        <div>
          <h1
            style={{
              fontSize: "clamp(1.8rem, 5vw, 3rem)",
              margin: "0 0 0.75rem",
              textShadow: "0 0 12px #00FF41",
              fontFamily: "'DM Mono', monospace",
            }}
          >
            VERIFY_TRUTH
          </h1>
          <p
            style={{
              color: "rgba(0,255,65,0.55)",
              maxWidth: "600px",
              fontSize: "0.82rem",
              margin: 0,
              lineHeight: 1.65,
            }}
          >
            Independently verify Olympus hashes, documents, and proof bundles
            against the append-only ledger.
          </p>
        </div>
        <div className="status-stack">
          <span className={`status-pill status-${statsQuery.isError ? "err" : "ok"}`}>
            API_{statsQuery.isError ? "OFFLINE" : "LIVE"}
          </span>
          <span className={`status-pill status-${isPending ? "warn" : "neutral"}`}>
            {operationLabel}
          </span>
        </div>
      </div>

      <div className="stats-grid">
        {statCards.map((s) => (
          <button
            key={s.label}
            type="button"
            className="cyber-panel-sm stat-card"
            onClick={() => void statsQuery.refetch()}
          >
            <div style={{ fontSize: "1.1rem", color: "#00FF41" }}>
              {s.raw ? String(s.value) : <AnimatedNumber value={Number(s.value)} />}
            </div>
            <div className="stat-label">{s.label}</div>
          </button>
        ))}
      </div>

      <div className="verify-grid">
        <div style={{ minWidth: 0 }}>
          <TiltContainer>
            <div className="cyber-panel" style={{ padding: 0 }}>
              <div role="tablist" className="tab-list">
                {tabs.map((tab) => (
                  <button
                    key={tab.id}
                    role="tab"
                    aria-selected={activeTab === tab.id}
                    className="tab-btn"
                    onClick={() => switchTab(tab.id)}
                    type="button"
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              <div style={{ padding: "1.5rem" }}>
                {activeTab === "hash" && (
                  <div>
                    <div className="field-head">
                      <label htmlFor="hash-input" className="terminal-label">
                        BLAKE3 content hash
                      </label>
                      <span className={`status-pill status-${hashStatus.tone}`}>
                        {hashStatus.label}
                      </span>
                    </div>
                    <div className="input-row">
                      <input
                        id="hash-input"
                        type="text"
                        value={hashInput}
                        onChange={(event) => {
                          setHashInput(event.target.value);
                          setHashError(null);
                        }}
                        onKeyDown={(event) => {
                          if (event.key === "Enter") submitHash(hashInput);
                        }}
                        placeholder="ENTER_BLAKE3_HASH..."
                        maxLength={64}
                        spellCheck={false}
                        autoComplete="off"
                        className="cyber-input"
                      />
                      <button
                        type="button"
                        className="cyber-button"
                        onClick={() => submitHash(hashInput)}
                        disabled={isPending || hashStatus.tone !== "ok"}
                      >
                        {isPending ? "EXECUTING..." : "VERIFY"}
                      </button>
                    </div>
                    <div className="quick-actions">
                      <button type="button" className="icon-text-btn" onClick={pasteHash}>
                        PASTE
                      </button>
                      <button
                        type="button"
                        className="icon-text-btn"
                        onClick={() => {
                          setHashInput(SAMPLE_HASH);
                          setHashError(null);
                        }}
                      >
                        SAMPLE
                      </button>
                      <button
                        type="button"
                        className="icon-text-btn"
                        onClick={() => {
                          setHashInput("");
                          setHashError(null);
                          setVerdictResult(null);
                        }}
                      >
                        CLEAR
                      </button>
                    </div>
                    {hashError && <p className="err-text">{hashError}</p>}
                  </div>
                )}

                {activeTab === "file" && (
                  <div>
                    <FileHasher
                      onHash={(hex) => {
                        setFileHash(hex);
                        setFileProgress(100);
                        setVerdictResult(null);
                        setCommitStage("idle");
                        setCommitError(null);
                        setCommitContentHash(null);
                      }}
                      onProgress={setFileProgress}
                      onFile={(f) => {
                        setDroppedFile(f);
                        setVerdictResult(null);
                        setCommitStage("idle");
                        setCommitError(null);
                        setCommitContentHash(null);
                      }}
                    />
                    {fileProgress > 0 && fileProgress < 100 && (
                      <p style={{ fontSize: "0.65rem", color: "rgba(0,255,65,0.45)" }}>
                        HASHING... {fileProgress}%
                      </p>
                    )}
                    {fileHash && (
                      <div style={{ marginTop: "1rem" }}>
                        <p style={{ fontSize: "0.55rem", letterSpacing: "0.1em", color: "rgba(0,255,65,0.45)", margin: "0 0 0.25rem" }}>
                          FILE BLAKE3
                        </p>
                        <HashDisplay hash={fileHash} />
                        {commitContentHash && (
                          <div style={{ marginTop: "0.85rem" }}>
                            <p style={{ fontSize: "0.55rem", letterSpacing: "0.1em", color: "rgba(0,255,65,0.65)", margin: "0 0 0.25rem" }}>
                              LEDGER CONTENT HASH
                            </p>
                            <HashDisplay hash={commitContentHash} />
                          </div>
                        )}
                        <button
                          type="button"
                          className="cyber-button"
                          onClick={() => submitHash(fileHash)}
                          disabled={isPending}
                          style={{ marginTop: "1rem" }}
                        >
                          {isPending ? "EXECUTING..." : "VERIFY_ON_LEDGER"}
                        </button>
                      </div>
                    )}
                  </div>
                )}

                {activeTab === "json" && (
                  <div>
                    <div className="field-head">
                      <label htmlFor="json-input" className="terminal-label">
                        JSON document
                      </label>
                      <span className="status-pill status-neutral">
                        {jsonInput.length.toLocaleString()}B
                      </span>
                    </div>
                    <textarea
                      id="json-input"
                      value={jsonInput}
                      onChange={(event) => {
                        setJsonInput(event.target.value);
                        setJsonError(null);
                      }}
                      rows={7}
                      placeholder='{"title":"Budget 2025","amount":1000000}'
                      spellCheck={false}
                      className="cyber-input"
                      style={{ resize: "vertical" }}
                    />
                    <div className="quick-actions">
                      <button type="button" className="icon-text-btn" onClick={formatJson}>
                        FORMAT
                      </button>
                      <button type="button" className="icon-text-btn" onClick={minifyJson}>
                        MINIFY
                      </button>
                      <button
                        type="button"
                        className="icon-text-btn"
                        onClick={() =>
                          setJsonInput(
                            JSON.stringify(
                              { title: "Budget 2025", amount: 1000000, agency: "demo" },
                              null,
                              2,
                            ),
                          )
                        }
                      >
                        SAMPLE
                      </button>
                    </div>
                    {jsonCanonical && (
                      <p className="preview-line">
                        CANONICAL:{" "}
                        {jsonCanonical.length > 160
                          ? `${jsonCanonical.slice(0, 160)}...`
                          : jsonCanonical}
                      </p>
                    )}
                    {jsonError && <p className="err-text">{jsonError}</p>}
                    <button
                      type="button"
                      className="cyber-button"
                      onClick={() => void submitJsonDoc()}
                      disabled={isPending || !jsonInput.trim()}
                      style={{ marginTop: "0.75rem" }}
                    >
                      {isPending ? "EXECUTING..." : "CANONICALIZE_AND_HASH"}
                    </button>
                  </div>
                )}

                {activeTab === "proof" && (
                  <div>
                    <label htmlFor="proof-input" className="terminal-label">
                      Proof bundle JSON
                    </label>
                    <textarea
                      id="proof-input"
                      value={proofInput}
                      onChange={(event) => {
                        setProofInput(event.target.value);
                        setProofError(null);
                      }}
                      rows={9}
                      placeholder='{"content_hash":"...","merkle_root":"...","merkle_proof":{}}'
                      spellCheck={false}
                      className="cyber-input"
                      style={{ resize: "vertical" }}
                    />
                    <div className="quick-actions">
                      <button
                        type="button"
                        className="icon-text-btn"
                        onClick={() => setProofInput(JSON.stringify(EXAMPLE_PROOF, null, 2))}
                      >
                        SAMPLE
                      </button>
                      <button
                        type="button"
                        className="icon-text-btn"
                        onClick={() => setProofInput("")}
                      >
                        CLEAR
                      </button>
                    </div>
                    <button
                      type="button"
                      className="cyber-button"
                      onClick={submitProof}
                      disabled={isPending || !proofInput.trim()}
                      style={{ marginTop: "0.75rem" }}
                    >
                      {isPending ? "EXECUTING..." : "EXECUTE_VERIFICATION"}
                    </button>
                    {proofError && <p className="err-text">{proofError}</p>}
                  </div>
                )}
              </div>
            </div>
          </TiltContainer>

          {verdictResult ? (
            <div>
              {verdictResult.displayHash && (
                <div style={{ marginTop: "1.5rem" }}>
                  <HashDisplay hash={verdictResult.displayHash} />
                </div>
              )}
              <VerdictCard
                verdict={verdictResult.verdict}
                details={verdictResult.details}
              />
              {verdictResult.verdict === "unknown" && droppedFile && commitStage !== "done" && (
                <div
                  style={{
                    marginTop: "1rem",
                    padding: "1.25rem 1.5rem",
                    border: "1px solid rgba(245,158,11,0.35)",
                    background: "rgba(245,158,11,0.03)",
                  }}
                >
                  <div style={{ fontSize: "0.55rem", letterSpacing: "0.12em", color: "rgba(245,158,11,0.6)", marginBottom: "1rem" }}>
                    COMMIT THIS FILE TO THE LEDGER
                  </div>
                  <div style={{ marginBottom: "0.85rem" }}>
                    <label style={{ display: "block", fontSize: "0.55rem", letterSpacing: "0.1em", color: "rgba(245,158,11,0.5)", marginBottom: "0.35rem" }}>
                      API KEY
                    </label>
                    <input
                      type="password"
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      placeholder="your API key from registration"
                      style={{
                        width: "100%",
                        background: "rgba(0,0,0,0.65)",
                        border: "1px solid rgba(245,158,11,0.3)",
                        color: "#f59e0b",
                        fontFamily: "'DM Mono', monospace",
                        fontSize: "0.78rem",
                        padding: "0.6rem 0.75rem",
                        outline: "none",
                        boxSizing: "border-box",
                      }}
                    />
                  </div>
                  <button
                    type="button"
                    onClick={() => void commitFile()}
                    disabled={commitStage === "committing" || !apiKey.trim()}
                    style={{
                      width: "100%",
                      padding: "0.75rem",
                      background: commitStage === "committing" ? "rgba(245,158,11,0.06)" : "rgba(245,158,11,0.12)",
                      border: "1px solid rgba(245,158,11,0.5)",
                      color: "#f59e0b",
                      fontFamily: "'DM Mono', monospace",
                      fontSize: "0.72rem",
                      letterSpacing: "0.12em",
                      cursor: commitStage === "committing" || !apiKey.trim() ? "not-allowed" : "pointer",
                    }}
                  >
                    {commitStage === "committing" ? "COMMITTING..." : "COMMIT TO LEDGER →"}
                  </button>
                  {commitError && (
                    <div style={{ marginTop: "0.75rem", padding: "0.65rem 0.85rem", border: "1px solid rgba(255,0,85,0.4)", color: "#ff0055", fontSize: "0.7rem", background: "rgba(255,0,85,0.05)" }}>
                      {commitError}
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="ready-panel">
              <span className="ready-dot" />
              <span>READY_FOR_INPUT</span>
            </div>
          )}
        </div>

        <aside className="console-side">
          <div className="side-panel">
            <div className="side-title">SESSION</div>
            <div className="flow-step" data-active={activeTab === "hash"}>
              <span>01</span>
              <strong>Hash lookup</strong>
            </div>
            <div className="flow-step" data-active={activeTab === "file"}>
              <span>02</span>
              <strong>Local file hash</strong>
            </div>
            <div className="flow-step" data-active={activeTab === "json"}>
              <span>03</span>
              <strong>Canonical JSON</strong>
            </div>
            <div className="flow-step" data-active={activeTab === "proof"}>
              <span>04</span>
              <strong>Proof bundle</strong>
            </div>
            <button
              type="button"
              className="cyber-button"
              onClick={clearWorkspace}
              style={{ width: "100%", marginTop: "1rem" }}
            >
              RESET_CONSOLE
            </button>
          </div>

          <RecentVerifications
            onSelect={(entry) => {
              switchTab("hash");
              setHashInput(entry.hash);
              submitHash(entry.hash);
            }}
          />
        </aside>
      </div>
    </div>
  );
}
