/**
 * Shared TypeScript types for Olympus Public UI.
 *
 * These mirror the Pydantic schemas in api/schemas/ingest.py and
 * api/schemas/dataset.py so that the frontend remains type-safe against the
 * FastAPI contract without a code-generation step.
 */

// ─── Core domain types ────────────────────────────────────────────────────────

export type Verdict = "verified" | "failed" | "unknown";

export type GlitchSoundType = "blip" | "noise" | "success" | "fail";

/** A single key/value row shown inside a VerdictCard. */
export interface VerdictDetail {
  key: string;
  value: string;
  /** Optional colour hint: ok=green, err=red, warn=amber, neutral=dim-green. */
  status?: "ok" | "err" | "warn" | "neutral";
  /** When true a copy-to-clipboard button is rendered next to the value. */
  copyable?: boolean;
}

// ─── Merkle proof ─────────────────────────────────────────────────────────────

/**
 * Serialised Merkle inclusion proof as returned by the Olympus API.
 * Matches the structure consumed by verifyMerkleProof() in the JS verifier
 * (verifiers/javascript/verifier.js).
 */
export interface OlympusMerkleProof {
  /** Hex-encoded BLAKE3 hash of the leaf value (content_hash). */
  leafHash: string;
  /** Ordered list of sibling hashes needed to recompute the root. */
  siblings: Array<{ hash: string; position: "left" | "right" }>;
  /** Expected Merkle root (hex). */
  rootHash: string;
}

// ─── API response types ───────────────────────────────────────────────────────

/**
 * Response from GET /ingest/records/hash/{hash}/verify
 * Extends the base IngestionProofResponse with merkle_proof_valid.
 */
export interface HashVerificationResponse {
  proof_id: string;
  record_id: string;
  shard_id: string;
  content_hash: string;
  merkle_root: string;
  merkle_proof: OlympusMerkleProof | null;
  merkle_proof_valid: boolean;
  ledger_entry_hash: string;
  timestamp: string;
  batch_id?: string;
  poseidon_root?: string;
}

/**
 * Request body for POST /ingest/proofs/verify
 */
export interface ProofVerificationRequest {
  proof_id?: string;
  content_hash: string;
  merkle_root: string;
  merkle_proof: OlympusMerkleProof;
}

/**
 * Response from POST /ingest/proofs/verify
 */
export interface ProofVerificationResponse {
  proof_id?: string;
  content_hash: string;
  merkle_root: string;
  content_hash_matches_proof: boolean;
  merkle_proof_valid: boolean;
  known_to_server: boolean;
  poseidon_root?: string;
}

/**
 * Response from GET /ingest/records/{proof_id}
 */
export interface RecordProofResponse {
  proof_id: string;
  record_id: string;
  shard_id: string;
  content_hash: string;
  merkle_root: string;
  ledger_entry_hash: string;
  timestamp: string;
  batch_id?: string;
  poseidon_root?: string;
  merkle_proof: OlympusMerkleProof;
}

// ─── Dataset types ────────────────────────────────────────────────────────────

export interface DatasetFile {
  path: string;
  byte_size: number;
  content_hash: string;
  record_count?: number;
}

export interface DatasetResponse {
  dataset_id: string;
  dataset_name: string;
  dataset_version: string;
  license_spdx: string;
  source_uri: string;
  epoch: string;
  commit_id: string;
  committer_pubkey: string;
  parent_commit_id: string;
  files: DatasetFile[];
}

export interface DatasetVerificationResponse {
  verified: boolean;
  checks: Record<string, boolean>;
  commit_id_valid: boolean | null;
  signature_valid: boolean | null;
  chain_valid: boolean | null;
  rfc3161_valid: boolean | null;
  timestamp_state?: string;
  key_revoked: boolean | null;
  merkle_proof?: OlympusMerkleProof[];
  zk_proof?: Record<string, unknown>;
}

// ─── Local state types ────────────────────────────────────────────────────────

export interface RecentVerificationEntry {
  hash: string;
  type: "hash" | "file" | "json" | "proof";
  verdict: Verdict;
  timestamp: number;
}
