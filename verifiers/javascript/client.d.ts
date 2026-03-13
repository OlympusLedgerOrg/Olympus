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
    poseidonRoot?: string | null;
  }): Promise<OlympusCommitResponse>;

  getProof(proofId: string): Promise<OlympusProofBundle>;
  verifyContentHash(contentHash: string): Promise<Record<string, unknown>>;
  verifyProofBundle(bundle: OlympusProofBundle): Promise<OlympusVerificationResponse>;
  submitProofBundle(bundle: OlympusProofBundle): Promise<OlympusProofBundle>;
  ingestFile(input: {
    fileBytes: ArrayBuffer | Uint8Array;
    namespace?: string;
    id?: string;
    poseidonRoot?: string | null;
    generateProof?: boolean;
    verify?: boolean;
  }): Promise<Record<string, unknown>>;
}
