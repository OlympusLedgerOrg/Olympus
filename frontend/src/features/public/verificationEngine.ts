/**
 * useVerificationEngine — React hook encapsulating all verification logic.
 *
 * Extracted from olympus-full.tsx to support multiple UX skins (Mayhem, Basic,
 * Forensic) that share the same cryptographic verification engine.
 *
 * Responsibilities
 * ────────────────
 * • State management for all four verification modes (hash, file, json, proof)
 * • WASM BLAKE3 file/JSON hashing via hashFileBLAKE3 / blake3Hex
 * • Canonical JSON encoding via canonicalJsonEncode (JCS / RFC 8785)
 * • API calls to the Olympus FastAPI backend
 * • Client-side Merkle proof re-verification via verifyMerkleProof
 * • Bounded in-memory history of recent lookups
 *
 * Usage
 * ─────
 *   const engine = useVerificationEngine({ apiBase: "http://localhost:8000" });
 *   // Render <MayhemSkin {...engine} /> or <BasicSkin {...engine} />
 */

import { useState, useCallback } from "react";
import {
  hashFileBLAKE3,
  blake3Hex,
  canonicalJsonEncode,
  verifyMerkleProof,
  type CanonicalJsonValue,
  type OlympusMerkleProof,
  type HashVerificationResponse,
  type ProofVerificationRequest,
} from "../../lib/olympus-crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export type Verdict = "verified" | "failed" | "unknown";
export type VerificationTab = "hash" | "file" | "json" | "proof";

export interface DetailRow {
  key: string;
  value: string;
}

export interface VerificationResult {
  verdict: Verdict;
  details: DetailRow[];
  hash: string;
  /** Result of the independent client-side Merkle re-verification. */
  localVerdict?: boolean;
}

export interface RecentEntry {
  hash: string;
  verdict: Verdict;
  ts: number;
}

// ─── Engine options ────────────────────────────────────────────────────────────

export interface VerificationEngineOptions {
  /** FastAPI root URL. Defaults to "" (same origin / Vite proxy). */
  apiBase?: string;
}

// ─── Return type ──────────────────────────────────────────────────────────────

export interface VerificationEngineState {
  // ── Tab ──
  tab: VerificationTab;
  switchTab: (id: VerificationTab) => void;

  // ── Hash mode ──
  hashInput: string;
  setHashInput: (v: string) => void;
  hashError: string;
  submitHash: () => void;

  // ── File mode ──
  fileHash: string;
  fileProgress: number;
  handleFileHashed: (hex: string) => void;
  handleFileProgress: (pct: number) => void;

  // ── JSON mode ──
  jsonInput: string;
  setJsonInput: (v: string) => void;
  jsonError: string;
  jsonCanonical: string;
  submitJsonDoc: () => Promise<void>;

  // ── Proof bundle mode ──
  proofInput: string;
  setProofInput: (v: string) => void;
  proofError: string;
  submitProof: () => Promise<void>;

  // ── Shared ──
  loading: boolean;
  result: VerificationResult | null;
  recents: RecentEntry[];
}

// ─── API helpers ──────────────────────────────────────────────────────────────

const HASH_RE = /^[0-9a-f]{64}$/i;

async function apiVerifyHash(
  base: string,
  hash: string,
): Promise<HashVerificationResponse | null> {
  const res = await fetch(`${base}/ingest/records/hash/${hash}/verify`, {
    headers: { "Content-Type": "application/json" },
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `API error ${res.status.toString()}${text ? ": " + text.slice(0, 120) : ""}`,
    );
  }
  return res.json() as Promise<HashVerificationResponse>;
}

async function apiVerifyProofBundle(
  base: string,
  bundle: ProofVerificationRequest,
): Promise<{
  content_hash: string;
  merkle_root: string;
  content_hash_matches_proof: boolean;
  merkle_proof_valid: boolean;
  known_to_server: boolean;
  poseidon_root?: string;
}> {
  const res = await fetch(`${base}/ingest/proofs/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      proof_id: bundle.proof_id ?? null,
      content_hash: bundle.content_hash,
      merkle_root: bundle.merkle_root,
      merkle_proof: bundle.merkle_proof,
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `API error ${res.status.toString()}${text ? ": " + text.slice(0, 120) : ""}`,
    );
  }
  return res.json() as ReturnType<typeof apiVerifyProofBundle>;
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useVerificationEngine(
  options: VerificationEngineOptions = {},
): VerificationEngineState {
  const apiBase = options.apiBase ?? "";

  // ── UI state ──
  const [tab, setTab] = useState<VerificationTab>("hash");
  const [hashInput, setHashInput] = useState<string>("");
  const [hashError, setHashError] = useState<string>("");
  const [fileHash, setFileHash] = useState<string>("");
  const [fileProgress, setFileProgress] = useState<number>(0);
  const [jsonInput, setJsonInput] = useState<string>("");
  const [jsonError, setJsonError] = useState<string>("");
  const [jsonCanonical, setJsonCanonical] = useState<string>("");
  const [proofInput, setProofInput] = useState<string>("");
  const [proofError, setProofError] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [recents, setRecents] = useState<RecentEntry[]>([]);

  const clearResult = useCallback((): void => {
    setResult(null);
    setHashError("");
    setProofError("");
    setJsonError("");
  }, []);

  const switchTab = useCallback(
    (id: VerificationTab): void => {
      setTab(id);
      clearResult();
    },
    [clearResult],
  );

  const pushRecent = useCallback((hash: string, verdict: Verdict): void => {
    setRecents((prev) =>
      [{ hash, verdict, ts: Date.now() }, ...prev].slice(0, 7),
    );
  }, []);

  // ── Core: look up a 64-char hash in the ledger then re-verify client-side ──
  const verifyHash = useCallback(
    async (hash: string): Promise<void> => {
      setLoading(true);
      setResult(null);

      try {
        const data = await apiVerifyHash(apiBase, hash);

        if (!data) {
          setResult({
            verdict: "unknown",
            details: [{ key: "QUERIED_HASH", value: hash }],
            hash,
          });
          pushRecent(hash, "unknown");
          return;
        }

        // Re-verify the Merkle proof locally — no server trust required
        const localVerdict = data.merkle_proof
          ? await verifyMerkleProof(data.merkle_proof)
          : undefined;

        const verdict: Verdict = data.merkle_proof_valid ? "verified" : "failed";
        const details: DetailRow[] = [
          { key: "CONTENT_HASH", value: data.content_hash },
          { key: "PROOF_ID", value: data.proof_id ?? "—" },
          { key: "RECORD_ID", value: data.record_id ?? "—" },
          { key: "SHARD_ID", value: data.shard_id ?? "—" },
          { key: "MERKLE_ROOT", value: data.merkle_root },
          { key: "SERVER_VERIFIED", value: data.merkle_proof_valid ? "YES" : "NO" },
          {
            key: "COMMITTED",
            value: data.timestamp
              ? new Date(data.timestamp).toLocaleString()
              : "—",
          },
          ...(data.poseidon_root
            ? [{ key: "POSEIDON_ROOT", value: data.poseidon_root }]
            : []),
        ];

        setResult({ verdict, details, hash: data.content_hash, localVerdict });
        pushRecent(hash, verdict);
      } catch (err) {
        setHashError(err instanceof Error ? err.message : "Network error");
      } finally {
        setLoading(false);
      }
    },
    [apiBase, pushRecent],
  );

  const submitHash = useCallback((): void => {
    const normalized = hashInput.trim().toLowerCase();
    if (!HASH_RE.test(normalized)) {
      setHashError("Enter a valid 64-character BLAKE3 hex hash");
      return;
    }
    setHashError("");
    void verifyHash(normalized);
  }, [hashInput, verifyHash]);

  // ── File mode: called by the FileDrop component when hashing completes ──
  const handleFileHashed = useCallback(
    (hex: string): void => {
      setFileHash(hex);
      void verifyHash(hex);
    },
    [verifyHash],
  );

  const handleFileProgress = useCallback((pct: number): void => {
    setFileProgress(pct);
  }, []);

  // ── JSON mode: canonicalise → BLAKE3 → verify ──
  const submitJsonDoc = useCallback(async (): Promise<void> => {
    setJsonError("");
    setJsonCanonical("");
    clearResult();

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
      const hex = await blake3Hex(bytes);
      setHashInput(hex);
      setTab("hash");
      void verifyHash(hex);
    } catch (e) {
      setJsonError(e instanceof Error ? e.message : String(e));
    }
  }, [jsonInput, clearResult, verifyHash]);

  // ── Proof bundle mode ──
  const submitProof = useCallback(async (): Promise<void> => {
    setProofError("");
    clearResult();

    let parsed: unknown;
    try {
      parsed = JSON.parse(proofInput);
    } catch {
      setProofError("Invalid JSON — paste the full proof bundle");
      return;
    }

    const p = parsed as Partial<ProofVerificationRequest>;
    if (!p.content_hash || !p.merkle_root || !p.merkle_proof) {
      setProofError(
        "Bundle must include content_hash, merkle_root, and merkle_proof",
      );
      return;
    }

    const bundle = p as ProofVerificationRequest;

    // Client-side Merkle re-verification runs before the network call
    const localVerdict = await verifyMerkleProof(
      bundle.merkle_proof as OlympusMerkleProof,
    ).catch(() => false);

    setLoading(true);

    try {
      const data = await apiVerifyProofBundle(apiBase, bundle);
      const allValid =
        data.content_hash_matches_proof &&
        data.merkle_proof_valid &&
        data.known_to_server;
      const verdict: Verdict = allValid
        ? "verified"
        : data.known_to_server
          ? "failed"
          : "unknown";

      const details: DetailRow[] = [
        { key: "CONTENT_HASH", value: data.content_hash },
        { key: "MERKLE_ROOT", value: data.merkle_root },
        {
          key: "HASH_MATCHES_PROOF",
          value: data.content_hash_matches_proof ? "YES" : "NO",
        },
        {
          key: "SERVER_MERKLE_VALID",
          value: data.merkle_proof_valid ? "YES" : "NO",
        },
        {
          key: "KNOWN_TO_SERVER",
          value: data.known_to_server ? "YES" : "NO",
        },
        ...(data.poseidon_root
          ? [{ key: "POSEIDON_ROOT", value: data.poseidon_root }]
          : []),
      ];

      setResult({ verdict, details, hash: data.content_hash, localVerdict });
      pushRecent(data.content_hash, verdict);
    } catch (err) {
      setProofError(err instanceof Error ? err.message : "Network error");
    } finally {
      setLoading(false);
    }
  }, [apiBase, proofInput, clearResult, pushRecent]);

  return {
    tab,
    switchTab,
    hashInput,
    setHashInput,
    hashError,
    submitHash,
    fileHash,
    fileProgress,
    handleFileHashed,
    handleFileProgress,
    jsonInput,
    setJsonInput,
    jsonError,
    jsonCanonical,
    submitJsonDoc,
    proofInput,
    setProofInput,
    proofError,
    submitProof,
    loading,
    result,
    recents,
  };
}
