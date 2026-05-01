import { useState, useCallback } from "react";
import { useMutation } from "@tanstack/react-query";
import { verifyHash, verifyProofBundle } from "../lib/api";
import { addRecentVerification } from "../lib/storage";
import { hashBytes } from "../lib/blake3";
import { canonicalJsonEncode, type CanonicalJsonValue } from "../lib/crypto";
import { playGlitchSound } from "../lib/audio";
import type {
  Verdict,
  VerdictDetail,
  HashVerificationResponse,
  ProofVerificationResponse,
  ProofVerificationRequest,
  RecentVerificationEntry,
} from "../lib/types";
import VerdictCard from "../components/VerdictCard";
import HashDisplay from "../components/HashDisplay";
import FileHasher from "../components/FileHasher";
import RecentVerifications from "../components/RecentVerifications";
import TiltContainer from "../components/TiltContainer";
import AnimatedNumber from "../components/AnimatedNumber";

type Tab = "hash" | "file" | "json" | "proof";

const HASH_RE = /^[0-9a-f]{64}$/i;

const STATS: { label: string; val: number | string; raw?: boolean }[] = [
  { label: "COPIES", val: 847293 },
  { label: "SHARDS", val: 14 },
  { label: "PROOFS", val: 23481 },
  { label: "UPTIME", val: "99.9%", raw: true },
];

function hashVerificationToVerdict(
  resp: HashVerificationResponse,
): { verdict: Verdict; details: VerdictDetail[] } {
  const verdict: Verdict = resp.merkle_proof_valid ? "verified" : "failed";
  return {
    verdict,
    details: [
      {
        key: "Content Hash",
        value: resp.content_hash,
        status: "ok",
        copyable: true,
      },
      { key: "Proof ID", value: resp.proof_id, status: "neutral", copyable: true },
      {
        key: "Record ID",
        value: resp.record_id,
        status: "neutral",
        copyable: true,
      },
      { key: "Shard ID", value: resp.shard_id, status: "neutral" },
      {
        key: "Merkle Root",
        value: resp.merkle_root,
        status: "neutral",
        copyable: true,
      },
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
      {
        key: "Content Hash",
        value: resp.content_hash,
        status: "neutral",
        copyable: true,
      },
      {
        key: "Merkle Root",
        value: resp.merkle_root,
        status: "neutral",
        copyable: true,
      },
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
          details: [
            {
              key: "Queried Hash",
              value: qHash,
              status: "warn",
              copyable: true,
            },
          ],
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

    let parsed: CanonicalJsonValue;
    try {
      parsed = JSON.parse(jsonInput) as CanonicalJsonValue;
    } catch (e) {
      setJsonError(
        "Invalid JSON: " + (e instanceof Error ? e.message : String(e)),
      );
      return;
    }

    try {
      const canon = canonicalJsonEncode(parsed);
      setJsonCanonical(canon);
      const bytes = new TextEncoder().encode(canon);
      const hex = await hashBytes(bytes);
      setHashInput(hex);
      setActiveTab("hash");
      submitHash(hex);
    } catch (e) {
      setJsonError(e instanceof Error ? e.message : String(e));
    }
  }, [jsonInput, submitHash]);

  const submitProof = useCallback(() => {
    setProofError(null);
    setVerdictResult(null);
    try {
      const parsed = JSON.parse(proofInput) as ProofVerificationRequest;
      if (!parsed.content_hash || !parsed.merkle_root || !parsed.merkle_proof) {
        setProofError(
          "Bundle must include content_hash, merkle_root, and merkle_proof",
        );
        return;
      }
      proofMutation.mutate(parsed);
    } catch {
      setProofError("Invalid JSON — paste the full proof bundle");
    }
  }, [proofInput, proofMutation]);

  const isPending = hashMutation.isPending || proofMutation.isPending;

  const TABS: { id: Tab; label: string }[] = [
    { id: "hash", label: "HASH" },
    { id: "file", label: "FILE" },
    { id: "json", label: "JSON_DOC" },
    { id: "proof", label: "PROOF_BUNDLE" },
  ];

  return (
    <div>
      {/* Hero */}
      <div style={{ marginBottom: "3rem" }}>
        <h1
          style={{
            fontSize: "clamp(1.8rem, 5vw, 3rem)",
            margin: "0 0 0.75rem",
            textShadow: "0 0 12px #00FF41",
            letterSpacing: "-0.02em",
            fontFamily: "'DM Mono', monospace",
          }}
        >
          VERIFY_TRUTH
        </h1>
        <p
          style={{
            color: "rgba(0,255,65,0.55)",
            maxWidth: "520px",
            fontSize: "0.82rem",
            margin: 0,
            lineHeight: 1.65,
          }}
        >
          The first rule of Project Olympus: You do not trust the hash.
          The second rule: You independently RE-VERIFY the hash.
          Merkle proofs are re-computed entirely in your browser.
        </p>
      </div>

      {/* Stats strip */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
          gap: "0.75rem",
          marginBottom: "2.5rem",
        }}
      >
        {STATS.map((s, i) => (
          <div
            key={i}
            className="cyber-panel-sm"
            style={{ padding: "0.85rem 1rem", textAlign: "center" }}
          >
            <div
              style={{
                fontSize: "1.1rem",
                color: "#00FF41",
                animation: "pulse-glow 3s ease-in-out infinite",
              }}
            >
              {s.raw ? (
                String(s.val)
              ) : (
                <AnimatedNumber value={s.val as number} />
              )}
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

      {/* Two-column layout on large screens */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr",
          gap: "2.5rem",
        }}
        className="lg:grid-cols-[1fr_220px]"
      >
        <div style={{ minWidth: 0 }}>
          {/* Verification Terminal */}
          <TiltContainer>
            <div className="cyber-panel" style={{ padding: 0 }}>
              {/* Tab bar */}
              <div
                role="tablist"
                style={{
                  display: "flex",
                  borderBottom: "1px solid rgba(0,255,65,0.18)",
                }}
              >
                {TABS.map((t) => (
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
                {/* Hash tab */}
                {activeTab === "hash" && (
                  <div>
                    <label
                      htmlFor="hash-input"
                      style={{
                        display: "block",
                        fontSize: "0.6rem",
                        color: "rgba(0,255,65,0.45)",
                        marginBottom: "0.5rem",
                        letterSpacing: "0.06em",
                      }}
                    >
                      INPUT_BUFFER_01 — BLAKE3 content hash (64 hex chars)
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
                        onMouseEnter={() => playGlitchSound("blip")}
                        disabled={isPending}
                        style={{ flexShrink: 0 }}
                      >
                        {isPending ? "EXECUTING…" : "EXECUTE"}
                      </button>
                    </div>
                    {hashError && (
                      <p className="err-text">{hashError}</p>
                    )}
                  </div>
                )}

                {/* File tab */}
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
                      <div style={{ marginTop: "0.75rem" }}>
                        <div
                          style={{
                            height: 2,
                            background: "rgba(0,255,65,0.15)",
                            borderRadius: 1,
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              height: "100%",
                              width: `${fileProgress}%`,
                              background: "#00FF41",
                              transition: "width 0.15s",
                              boxShadow: "0 0 6px #00FF41",
                            }}
                          />
                        </div>
                        <p
                          style={{
                            fontSize: "0.65rem",
                            color: "rgba(0,255,65,0.4)",
                            margin: "0.25rem 0 0",
                          }}
                        >
                          HASHING… {fileProgress}%
                        </p>
                      </div>
                    )}
                    {fileHash && (
                      <div style={{ marginTop: "1rem" }}>
                        <HashDisplay hash={fileHash} />
                        <button
                          type="button"
                          className="cyber-button"
                          onClick={() => submitHash(fileHash)}
                          onMouseEnter={() => playGlitchSound("blip")}
                          disabled={isPending}
                          style={{ marginTop: "1rem" }}
                        >
                          {isPending ? "EXECUTING…" : "VERIFY_ON_LEDGER"}
                        </button>
                      </div>
                    )}
                  </div>
                )}

                {/* JSON Document tab */}
                {activeTab === "json" && (
                  <div>
                    <label
                      htmlFor="json-input"
                      style={{
                        display: "block",
                        fontSize: "0.6rem",
                        color: "rgba(0,255,65,0.45)",
                        marginBottom: "0.5rem",
                        letterSpacing: "0.06em",
                      }}
                    >
                      PASTE_JSON_DOCUMENT — canonicalized (JCS/RFC 8785) then
                      hashed with BLAKE3
                    </label>
                    <textarea
                      id="json-input"
                      value={jsonInput}
                      onChange={(e) => setJsonInput(e.target.value)}
                      rows={5}
                      placeholder='{"title": "Budget 2025", "amount": 1000000}'
                      spellCheck={false}
                      className="cyber-input"
                      style={{ resize: "vertical" }}
                    />
                    {jsonCanonical && (
                      <p
                        style={{
                          fontSize: "0.6rem",
                          color: "rgba(0,255,65,0.4)",
                          margin: "0.3rem 0 0",
                          wordBreak: "break-all",
                        }}
                      >
                        CANONICAL:{" "}
                        {jsonCanonical.length > 120
                          ? jsonCanonical.slice(0, 120) + "…"
                          : jsonCanonical}
                      </p>
                    )}
                    {jsonError && <p className="err-text">{jsonError}</p>}
                    <button
                      type="button"
                      className="cyber-button"
                      onClick={() => void submitJsonDoc()}
                      onMouseEnter={() => playGlitchSound("blip")}
                      disabled={isPending}
                      style={{ marginTop: "0.75rem" }}
                    >
                      {isPending ? "EXECUTING…" : "CANONICALIZE_+_HASH"}
                    </button>
                  </div>
                )}

                {/* Proof Bundle tab */}
                {activeTab === "proof" && (
                  <div>
                    <label
                      htmlFor="proof-input"
                      style={{
                        display: "block",
                        fontSize: "0.6rem",
                        color: "rgba(0,255,65,0.45)",
                        marginBottom: "0.5rem",
                        letterSpacing: "0.06em",
                      }}
                    >
                      PASTE_PROOF_BUNDLE — JSON with content_hash, merkle_root,
                      merkle_proof
                    </label>
                    <textarea
                      id="proof-input"
                      value={proofInput}
                      onChange={(e) => setProofInput(e.target.value)}
                      rows={9}
                      placeholder='{"content_hash":"...","merkle_root":"...","merkle_proof":{...}}'
                      spellCheck={false}
                      className="cyber-input"
                      style={{ resize: "vertical" }}
                    />
                    <p
                      style={{
                        fontSize: "0.62rem",
                        color: "rgba(0,255,65,0.35)",
                        margin: "0.4rem 0 0.75rem",
                      }}
                    >
                      Both HASH_MATCHES_PROOF and SERVER_MERKLE_VALID must pass.
                    </p>
                    <button
                      type="button"
                      className="cyber-button"
                      onClick={submitProof}
                      onMouseEnter={() => playGlitchSound("blip")}
                      disabled={isPending}
                    >
                      {isPending ? "EXECUTING…" : "EXECUTE_VERIFICATION"}
                    </button>
                    {proofError && <p className="err-text">{proofError}</p>}
                  </div>
                )}
              </div>
            </div>
          </TiltContainer>

          {/* Result */}
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

          {/* How It Works */}
          <section
            style={{
              marginTop: "4rem",
              paddingTop: "2.5rem",
              borderTop: "1px solid rgba(0,255,65,0.1)",
            }}
          >
            <h2
              style={{
                fontSize: "0.62rem",
                letterSpacing: "0.15em",
                textTransform: "uppercase",
                color: "rgba(0,255,65,0.4)",
                margin: "0 0 1.5rem",
              }}
            >
              HOW_IT_WORKS
            </h2>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
                gap: "0.85rem",
              }}
            >
              {(
                [
                  {
                    n: "01",
                    title: "BLAKE3_WASM",
                    body: "Files are hashed locally using a WebAssembly BLAKE3 implementation. Bytes never leave your machine.",
                  },
                  {
                    n: "02",
                    title: "CANONICAL_JSON",
                    body: "Documents are serialized with JCS (RFC 8785) — sorted keys, NFC Unicode, no whitespace — ensuring byte-for-byte reproducibility.",
                  },
                  {
                    n: "03",
                    title: "LEDGER_LOOKUP",
                    body: "The 64-char BLAKE3 digest is sent to the Olympus append-only ledger API which returns the stored Merkle proof bundle.",
                  },
                  {
                    n: "04",
                    title: "CLIENT_VERIFY",
                    body: "Your browser independently recomputes the Merkle root from the proof path using OLY:LEAF:V1 / OLY:NODE:V1 domain-separated BLAKE3 — server trust not required.",
                  },
                ] as const
              ).map((step) => (
                <div
                  key={step.n}
                  className="cyber-panel-sm"
                  style={{ padding: "1rem 1.1rem" }}
                >
                  <div
                    style={{
                      color: "#ff0055",
                      fontSize: "0.6rem",
                      marginBottom: "0.4rem",
                      letterSpacing: "0.05em",
                    }}
                  >
                    {step.n}
                  </div>
                  <h3
                    style={{
                      margin: "0 0 0.4rem",
                      fontSize: "0.78rem",
                      color: "#00FF41",
                    }}
                  >
                    {step.title}
                  </h3>
                  <p
                    style={{
                      margin: 0,
                      fontSize: "0.68rem",
                      color: "rgba(0,255,65,0.45)",
                      lineHeight: 1.55,
                    }}
                  >
                    {step.body}
                  </p>
                </div>
              ))}
            </div>
          </section>
        </div>

        {/* Sidebar */}
        <aside>
          <RecentVerifications />
        </aside>
      </div>
    </div>
  );
}
