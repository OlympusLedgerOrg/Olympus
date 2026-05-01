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
 *
 * Matches the wire format produced by `protocol/merkle.py::deserialize_merkle_proof`.
 * `siblings` is an ordered list of `[hashHex, is_right]` tuples where `is_right`
 * is `true` when the sibling is to the right of the current node.
 */
export type OlympusMerkleProofSibling = [hashHex: string, is_right: boolean];

export interface OlympusMerkleProof {
  /** Hex-encoded BLAKE3 hash of the leaf value (content_hash). */
  leaf_hash: string;
  /** Leaf position within the tree. */
  leaf_index?: number;
  /** Ordered list of sibling hashes needed to recompute the root. */
  siblings: OlympusMerkleProofSibling[];
  /** Expected Merkle root (hex). */
  root_hash: string;
  proof_version?: string;
  tree_version?: string;
  epoch?: number;
  tree_size?: number;
}

// ─── API response types ───────────────────────────────────────────────────────

/**
 * Response from GET /ingest/records/hash/{hash}/verify
 * Extends the base IngestionProofResponse with merkle_proof_valid.
 *
 * `merkle_proof` is typed as `Record<string, unknown>` because the server
 * serializes it as an opaque `dict[str, Any]`; use `OlympusMerkleProof` only
 * after explicit validation/casting.
 */
export interface HashVerificationResponse {
  proof_id: string;
  record_id: string;
  shard_id: string;
  content_hash: string;
  merkle_root: string;
  merkle_proof: Record<string, unknown> | null;
  merkle_proof_valid: boolean;
  ledger_entry_hash: string;
  timestamp: string;
  canonicalization?: Record<string, unknown> | null;
  batch_id?: string;
  poseidon_root?: string;
}

/**
 * Request body for POST /ingest/proofs/verify
 *
 * `merkle_proof` is passed through as-is to the server, so we type it as a
 * generic dict to avoid silently dropping fields the server needs.
 */
export interface ProofVerificationRequest {
  proof_id?: string;
  content_hash: string;
  merkle_root: string;
  merkle_proof: Record<string, unknown>;
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
  canonicalization?: Record<string, unknown> | null;
  batch_id?: string;
  poseidon_root?: string;
  merkle_proof: Record<string, unknown>;
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
