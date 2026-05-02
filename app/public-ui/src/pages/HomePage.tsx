import { useCallback, useState } from "react";
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

type Tab = "hash" | "file" | "json" | "proof";

const HASH_RE = /^[0-9a-f]{64}$/i;

const FALLBACK_STATS: PublicStatsResponse = {
  copies: 0,
  shards: 0,
  proofs: 0,
  uptime: "0s",
  uptime_seconds: 0,
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

  const statsQuery = useQuery({
    queryKey: ["public-stats"],
    queryFn: getPublicStats,
    staleTime: 15_000,
    refetchInterval: 30_000,
  });
  const stats = statsQuery.data ?? FALLBACK_STATS;

  const switchTab = (id: Tab) => {
    setActiveTab(id);
    setVerdictResult(null);
    setHashError(null);
    setProofError(null);
    setJsonError(null);
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
      hashMutation.mutate(normalized);
    },
    [hashMutation],
  );

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

  const isPending = hashMutation.isPending || proofMutation.isPending;
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
      <div style={{ marginBottom: "3rem" }}>
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
            maxWidth: "540px",
            fontSize: "0.82rem",
            margin: 0,
            lineHeight: 1.65,
          }}
        >
          Independently verify Olympus hashes, documents, and proof bundles
          against the append-only ledger.
        </p>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
          gap: "0.75rem",
          marginBottom: "2.5rem",
        }}
      >
        {statCards.map((s) => (
          <div
            key={s.label}
            className="cyber-panel-sm"
            style={{ padding: "0.85rem 1rem", textAlign: "center" }}
          >
            <div style={{ fontSize: "1.1rem", color: "#00FF41" }}>
              {s.raw ? String(s.value) : <AnimatedNumber value={Number(s.value)} />}
            </div>
            <div
              style={{
                fontSize: "0.5rem",
                opacity: 0.4,
                letterSpacing: "0.12em",
                marginTop: "0.2rem",
              }}
            >
              {s.label}
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: "2.5rem" }}>
        <div style={{ minWidth: 0 }}>
          <TiltContainer>
            <div className="cyber-panel" style={{ padding: 0 }}>
              <div
                role="tablist"
                style={{
                  display: "flex",
                  borderBottom: "1px solid rgba(0,255,65,0.18)",
                  overflowX: "auto",
                }}
              >
                {tabs.map((t) => (
                  <button
                    key={t.id}
                    role="tab"
                    aria-selected={activeTab === t.id}
                    className="tab-btn"
                    onClick={() => switchTab(t.id)}
                    type="button"
                  >
                    {t.label}
                  </button>
                ))}
              </div>

              <div style={{ padding: "1.75rem" }}>
                {activeTab === "hash" && (
                  <div>
                    <label htmlFor="hash-input" className="terminal-label">
                      BLAKE3 content hash
                    </label>
                    <div style={{ display: "flex", gap: "0.6rem" }}>
                      <input
                        id="hash-input"
                        type="text"
                        value={hashInput}
                        onChange={(e) => setHashInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") submitHash(hashInput);
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
                        disabled={isPending}
                      >
                        {isPending ? "EXECUTING..." : "EXECUTE"}
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
                      }}
                      onProgress={setFileProgress}
                    />
                    {fileProgress > 0 && fileProgress < 100 && (
                      <p style={{ fontSize: "0.65rem", color: "rgba(0,255,65,0.45)" }}>
                        HASHING... {fileProgress}%
                      </p>
                    )}
                    {fileHash && (
                      <div style={{ marginTop: "1rem" }}>
                        <HashDisplay hash={fileHash} />
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
                    <label htmlFor="json-input" className="terminal-label">
                      JSON document
                    </label>
                    <textarea
                      id="json-input"
                      value={jsonInput}
                      onChange={(e) => setJsonInput(e.target.value)}
                      rows={6}
                      placeholder='{"title":"Budget 2025","amount":1000000}'
                      spellCheck={false}
                      className="cyber-input"
                      style={{ resize: "vertical" }}
                    />
                    {jsonCanonical && (
                      <p
                        style={{
                          fontSize: "0.6rem",
                          color: "rgba(0,255,65,0.4)",
                          wordBreak: "break-all",
                        }}
                      >
                        CANONICAL:{" "}
                        {jsonCanonical.length > 120
                          ? `${jsonCanonical.slice(0, 120)}...`
                          : jsonCanonical}
                      </p>
                    )}
                    {jsonError && <p className="err-text">{jsonError}</p>}
                    <button
                      type="button"
                      className="cyber-button"
                      onClick={() => void submitJsonDoc()}
                      disabled={isPending}
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
                      onChange={(e) => setProofInput(e.target.value)}
                      rows={9}
                      placeholder='{"content_hash":"...","merkle_root":"...","merkle_proof":{}}'
                      spellCheck={false}
                      className="cyber-input"
                      style={{ resize: "vertical" }}
                    />
                    <button
                      type="button"
                      className="cyber-button"
                      onClick={submitProof}
                      disabled={isPending}
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

          {verdictResult && (
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
            </div>
          )}
        </div>

        <aside>
          <RecentVerifications />
        </aside>
      </div>
    </div>
  );
}
