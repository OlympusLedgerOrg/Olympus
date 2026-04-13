import { useState, useCallback } from "react";
import { useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { verifyHash, verifyProofBundle } from "../lib/api";
import { addRecentVerification } from "../lib/storage";
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

type Tab = "hash" | "file" | "proof";

const HASH_RE = /^[0-9a-f]{64}$/i;

function hashVerificationToVerdict(
  resp: HashVerificationResponse
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
      { key: "Ledger Entry Hash", value: resp.ledger_entry_hash, status: "neutral", copyable: true },
      { key: "Committed", value: new Date(resp.timestamp).toLocaleString(), status: "neutral" },
    ],
  };
}

function proofVerificationToVerdict(
  resp: ProofVerificationResponse
): { verdict: Verdict; details: VerdictDetail[] } {
  const allValid =
    resp.content_hash_matches_proof && resp.merkle_proof_valid && resp.known_to_server;
  const verdict: Verdict = allValid ? "verified" : resp.known_to_server ? "failed" : "unknown";
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
  const [proofInput, setProofInput] = useState("");
  const [proofError, setProofError] = useState<string | null>(null);

  const [verdictResult, setVerdictResult] = useState<{
    verdict: Verdict;
    details: VerdictDetail[];
    displayHash?: string;
  } | null>(null);

  const hashMutation = useMutation({
    mutationFn: verifyHash,
    onSuccess: (data) => {
      const result = hashVerificationToVerdict(data);
      setVerdictResult({ ...result, displayHash: data.content_hash });
      addRecentVerification({
        hash: data.content_hash,
        type: activeTab === "file" ? "file" : "hash",
        verdict: result.verdict,
        timestamp: Date.now(),
      } satisfies RecentVerificationEntry);
    },
    onError: (err) => {
      if (err instanceof Error && err.message.includes("404")) {
        setVerdictResult({
          verdict: "unknown",
          details: [
            { key: "Queried Hash", value: hashInput || fileHash || "", status: "warn", copyable: true },
          ],
          displayHash: hashInput || fileHash || undefined,
        });
        addRecentVerification({
          hash: hashInput || fileHash || "",
          type: activeTab === "file" ? "file" : "hash",
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
    [hashMutation]
  );

  const submitProof = useCallback(() => {
    setProofError(null);
    setVerdictResult(null);
    try {
      const parsed = JSON.parse(proofInput) as ProofVerificationRequest;
      if (!parsed.content_hash || !parsed.merkle_root || !parsed.merkle_proof) {
        setProofError(
          "Bundle must include content_hash, merkle_root, and merkle_proof"
        );
        return;
      }
      proofMutation.mutate(parsed);
    } catch {
      setProofError("Invalid JSON");
    }
  }, [proofInput, proofMutation]);

  const tabs: { id: Tab; label: string }[] = [
    { id: "hash", label: "Hash" },
    { id: "file", label: "File" },
    { id: "proof", label: "Proof Bundle" },
  ];

  const isPending = hashMutation.isPending || proofMutation.isPending;

  return (
    <div className="lg:grid lg:grid-cols-[1fr_240px] gap-12">
      <div>
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: "easeOut" }}
        >
          <h1 className="font-serif text-4xl md:text-5xl text-ink mb-2">
            Verify a Record
          </h1>
          <p className="text-sm font-ui text-ink/50 mb-8 max-w-lg">
            Confirm that a document, hash, or proof bundle exists on the Olympus
            ledger and has not been altered since commitment.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1, ease: "easeOut" }}
          className="bg-white/50 rounded-sm border border-ink/10 overflow-hidden"
        >
          {/* Tabs */}
          <div className="flex border-b border-ink/10">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => {
                  setActiveTab(tab.id);
                  setVerdictResult(null);
                  setHashError(null);
                  setProofError(null);
                }}
                className={`flex-1 py-3 text-xs font-ui tracking-wider uppercase transition-colors cursor-pointer ${
                  activeTab === tab.id
                    ? "text-ink border-b-2 border-gold bg-white/60"
                    : "text-ink/40 hover:text-ink/60"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab Content */}
          <div className="p-6">
            {activeTab === "hash" && (
              <div>
                <label
                  htmlFor="hash-input"
                  className="block text-xs font-ui text-ink/50 mb-2"
                >
                  BLAKE3 Content Hash (64 hex characters)
                </label>
                <div className="flex gap-2">
                  <input
                    id="hash-input"
                    type="text"
                    value={hashInput}
                    onChange={(e) => setHashInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") submitHash(hashInput);
                    }}
                    placeholder="e.g. a1b2c3d4…"
                    className="flex-1 font-mono text-sm border border-ink/15 rounded-sm px-3 py-2.5 bg-paper text-ink placeholder:text-ink/25 outline-none focus:border-gold transition-colors"
                    maxLength={64}
                    spellCheck={false}
                    autoComplete="off"
                  />
                  <button
                    type="button"
                    onClick={() => submitHash(hashInput)}
                    disabled={isPending}
                    className="px-5 py-2.5 bg-ink text-paper text-xs font-ui rounded-sm hover:bg-ink/85 transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    {isPending ? "Verifying…" : "Verify"}
                  </button>
                </div>
                {hashError && (
                  <p className="text-xs text-failed mt-2 font-ui">{hashError}</p>
                )}
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
                  <div className="mt-3">
                    <div className="h-1 bg-ink/10 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gold transition-all duration-200"
                        style={{ width: `${fileProgress}%` }}
                      />
                    </div>
                    <p className="text-xs text-ink/40 font-ui mt-1">
                      Hashing… {fileProgress}%
                    </p>
                  </div>
                )}
                {fileHash && (
                  <div className="mt-4">
                    <p className="text-xs font-ui text-ink/50 mb-2">
                      Computed BLAKE3 Hash
                    </p>
                    <HashDisplay hash={fileHash} />
                    <button
                      type="button"
                      onClick={() => submitHash(fileHash)}
                      disabled={isPending}
                      className="mt-4 px-5 py-2.5 bg-ink text-paper text-xs font-ui rounded-sm hover:bg-ink/85 transition-colors disabled:opacity-50 cursor-pointer"
                    >
                      {isPending ? "Verifying…" : "Verify on Ledger"}
                    </button>
                  </div>
                )}
              </div>
            )}

            {activeTab === "proof" && (
              <div>
                <label
                  htmlFor="proof-input"
                  className="block text-xs font-ui text-ink/50 mb-2"
                >
                  Paste a JSON proof bundle
                </label>
                <textarea
                  id="proof-input"
                  value={proofInput}
                  onChange={(e) => setProofInput(e.target.value)}
                  rows={8}
                  placeholder='{"content_hash": "...", "merkle_root": "...", "merkle_proof": {...}}'
                  className="w-full font-mono text-xs border border-ink/15 rounded-sm px-3 py-2.5 bg-paper text-ink placeholder:text-ink/25 outline-none focus:border-gold transition-colors resize-y"
                  spellCheck={false}
                />
                <button
                  type="button"
                  onClick={submitProof}
                  disabled={isPending}
                  className="mt-3 px-5 py-2.5 bg-ink text-paper text-xs font-ui rounded-sm hover:bg-ink/85 transition-colors disabled:opacity-50 cursor-pointer"
                >
                  {isPending ? "Verifying…" : "Verify Bundle"}
                </button>
                {proofError && (
                  <p className="text-xs text-failed mt-2 font-ui">{proofError}</p>
                )}
              </div>
            )}
          </div>
        </motion.div>

        {/* Verdict */}
        {verdictResult && (
          <div>
            {verdictResult.displayHash && (
              <div className="mt-6">
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

      {/* Sidebar */}
      <aside>
        <RecentVerifications />
      </aside>
    </div>
  );
}
