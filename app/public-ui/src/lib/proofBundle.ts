import type {
  HashVerificationResponse,
  ProofVerificationRequest,
} from "./types";

export const MAX_PROOF_BUNDLE_BYTES = 50 * 1024;

export function formatProofBundleSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function isProofVerificationRequest(
  value: unknown,
): value is ProofVerificationRequest {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<ProofVerificationRequest>;
  return (
    typeof candidate.content_hash === "string" &&
    typeof candidate.merkle_root === "string" &&
    Boolean(candidate.merkle_proof) &&
    typeof candidate.merkle_proof === "object"
  );
}

export function parseProofBundleInput(input: string): ProofVerificationRequest {
  const trimmed = input.trim();
  const candidates = [trimmed];

  if (!trimmed.startsWith("{")) {
    candidates.push(`{${trimmed}`);
  }

  if (!trimmed.endsWith("}")) {
    candidates.push(`${trimmed}}`);
  }

  if (!trimmed.startsWith("{") && !trimmed.endsWith("}")) {
    candidates.push(`{${trimmed}}`);
  }

  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate) as unknown;
      if (isProofVerificationRequest(parsed)) return parsed;
    } catch {
      // Try the next common paste repair.
    }
  }

  throw new Error("invalid-proof-bundle-json");
}

export function proofRequestFromHashResponse(
  data: HashVerificationResponse,
): ProofVerificationRequest | null {
  if (!data.merkle_proof) return null;

  return {
    proof_id: data.proof_id,
    content_hash: data.content_hash,
    merkle_root: data.merkle_root,
    merkle_proof: data.merkle_proof,
  };
}

export function serializeProofBundle(bundle: ProofVerificationRequest): string {
  return JSON.stringify(bundle, null, 2);
}
