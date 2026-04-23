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

/** BLAKE3(b"OLY:EMPTY-LEAF:V1") — SMT empty-leaf sentinel as an immutable hex string.
 * Primitives are immutable; use this for equality comparisons. */
export const SMT_EMPTY_LEAF_HEX: string;

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

// ---------------------------------------------------------------------------
// Primitive crypto / Merkle helpers — mirrors verifier.js exports
// ---------------------------------------------------------------------------

/** Compute a BLAKE3 hash of the given bytes. */
export function computeBlake3(data: Uint8Array): Uint8Array;

/** Encode a byte array as a lowercase hex string. */
export function toHex(bytes: Uint8Array): string;

/** Decode a hex string into a Uint8Array. */
export function fromHex(hex: string): Uint8Array;

/** Return true iff BLAKE3(data) equals the given hex string (case-insensitive). */
export function verifyBlake3Hash(data: Uint8Array, expectedHex: string): boolean;

/** Compute the BLAKE3 Merkle parent hash of two child hashes. */
export function merkleParentHash(left: Uint8Array, right: Uint8Array): Uint8Array;

/** Compute the BLAKE3 Merkle leaf hash (OLY:LEAF:V1 domain separation). */
export function merkleLeafHash(data: Uint8Array): Uint8Array;

/** Build a Merkle tree from leaves and return the root as a hex string. */
export function computeMerkleRoot(leaves: Uint8Array[]): string;

/** One sibling entry in a Merkle inclusion proof. */
export interface MerkleSibling {
  /** Hex-encoded sibling hash. */
  hash: string;
  /** Whether this sibling is to the left or right of the current node. */
  position: 'left' | 'right';
}

/** Merkle inclusion proof as produced by computeMerkleRoot. */
export interface MerkleProof {
  /** Hash of the leaf being proved. */
  leafHash: Uint8Array;
  /** Ordered list of sibling hashes from leaf to root. */
  siblings: MerkleSibling[];
  /** Expected root hash as a hex string. */
  rootHash: string;
}

/** Verify a Merkle inclusion proof. Returns true iff the proof is valid. */
export function verifyMerkleProof(proof: MerkleProof): boolean;

/**
 * Compute the ledger entry hash from pre-canonicalized payload bytes.
 * Formula: BLAKE3(OLY:LEDGER:V1 || canonical_json_bytes)
 */
export function computeLedgerEntryHash(canonicalPayloadBytes: Uint8Array): Uint8Array;

/**
 * Compute the dual-root commitment hash binding a BLAKE3 Merkle root and a
 * Poseidon root (BN128 field element expressed as a decimal string).
 * Returns a 64-character hex string.
 */
export function computeDualCommitment(blake3RootHex: string, poseidonRootDecimal: string): string;
