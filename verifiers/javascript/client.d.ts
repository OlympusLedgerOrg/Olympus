export interface OlympusCommitResponse {
  proof_id: string;
  artifact_hash: string;
  namespace: string;
  id: string;
  committed_at: string;
  ledger_entry_hash: string;
  poseidon_root: string | null;
}

export interface OlympusProofBundle {
  proof_id?: string | null;
  record_id: string;
  shard_id: string;
  content_hash: string;
  merkle_root: string;
  merkle_proof: Record<string, unknown>;
  ledger_entry_hash: string;
  timestamp: string;
  canonicalization: Record<string, unknown>;
  batch_id?: string | null;
  poseidon_root?: string | null;
}

export interface OlympusVerificationResponse {
  proof_id: string | null;
  content_hash: string;
  merkle_root: string;
  content_hash_matches_proof: boolean;
  merkle_proof_valid: boolean;
  known_to_server: boolean;
  poseidon_root: string | null;
}

export declare class OlympusClient {
  constructor(options?: {
    baseUrl?: string;
    apiKey?: string;
    fetchImpl?: typeof fetch;
  });

  commitArtifact(input: {
    artifactHash: string;
    namespace: string;
    id: string;
  }): Promise<OlympusCommitResponse>;

  getProof(proofId: string): Promise<OlympusProofBundle>;
  verifyContentHash(contentHash: string): Promise<Record<string, unknown>>;
  verifyProofBundle(bundle: OlympusProofBundle): Promise<OlympusVerificationResponse>;
  submitProofBundle(bundle: OlympusProofBundle): Promise<OlympusProofBundle>;
  ingestFile(input: {
    fileBytes: ArrayBuffer | Uint8Array;
    namespace?: string;
    id?: string;
    generateProof?: boolean;
    verify?: boolean;
  }): Promise<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// SMT (SSMF) cross-language verifier — ADR-0003
// Mirrors verifiers/javascript/verifier.js exports. Siblings are wire-format
// leaf-to-root: siblings[0] is leaf-adjacent, siblings[255] is root-adjacent.
// ---------------------------------------------------------------------------

/**
 * SMT inclusion proof. All 32-byte fields are Uint8Array; callers convert
 * hex with the existing fromHex() helper.
 */
export interface SmtInclusionProof {
  key: Uint8Array;
  valueHash: Uint8Array;
  parserId: string;
  canonicalParserVersion: string;
  /** Exactly 256 entries, each 32 bytes, leaf-to-root. */
  siblings: Uint8Array[];
  rootHash: Uint8Array;
}

/** SMT non-inclusion proof. */
export interface SmtNonInclusionProof {
  key: Uint8Array;
  /** Exactly 256 entries, each 32 bytes, leaf-to-root. */
  siblings: Uint8Array[];
  rootHash: Uint8Array;
}

/** BLAKE3(b"OLY:EMPTY-LEAF:V1") — 32-byte SMT empty-leaf sentinel.
 * Returns a new Uint8Array copy each call to prevent external mutation. */
export function getSmtEmptyLeaf(): Uint8Array;

/** Compute the SMT leaf hash with parser-identity binding (ADR-0003). */
export function smtLeafHash(
  key: Uint8Array,
  valueHash: Uint8Array,
  parserId: string,
  canonicalParserVersion: string,
): Uint8Array;

/**
 * Verify an SMT inclusion proof. Returns false (never throws) for any
 * input-validation failure, matching the Python reference's behavior.
 */
export function verifySmtInclusion(proof: SmtInclusionProof): boolean;

/**
 * Verify an SMT non-inclusion proof. Returns false (never throws) for any
 * input-validation failure.
 */
export function verifySmtNonInclusion(proof: SmtNonInclusionProof): boolean;
