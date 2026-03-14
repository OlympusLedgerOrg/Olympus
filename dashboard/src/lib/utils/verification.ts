import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

export type VerificationMethod = "world-id" | "gitcoin-passport" | "social-graph";

export type LocationPrecision = "zip3";

export type LocationClaim = {
  precision: LocationPrecision;
  locationHash: string;
  display: string;
};

export type VerificationProof = {
  worldIdProof?: string;
  worldIdNullifier?: string;
  passportId?: string;
  passportScore?: number;
  socialHandle?: string;
  socialPlatform?: string;
  socialProof?: string;
  socialGraphConnections?: number;
};

export type VerificationRequestPayload = {
  walletAddress: string;
  method: VerificationMethod;
  proof: VerificationProof;
  location: LocationClaim;
  consent: boolean;
  assertion: boolean;
};

export type SbtMintRecord = {
  chainId: number;
  contractAddress: string;
  tokenId: string;
  txHash: string;
};

export type VerificationRecord = {
  verificationId: string;
  walletAddress: string;
  method: VerificationMethod;
  personhoodId: string;
  location: LocationClaim;
  sbt: SbtMintRecord;
  issuedAt: string;
};

export type VerificationResponse = {
  status: "verified" | "already_verified";
  record: VerificationRecord;
};

export const VERIFICATION_METHODS: Array<{
  id: VerificationMethod;
  label: string;
  description: string;
  disclaimer: string;
}> = [
  {
    id: "world-id",
    label: "World ID",
    description: "Iris-based proof of personhood with anonymized nullifiers.",
    disclaimer: "Optional fallback for users with Worldcoin credentials.",
  },
  {
    id: "gitcoin-passport",
    label: "Gitcoin Passport",
    description: "Aggregated attestations with a civic trust score.",
    disclaimer: "Optional fallback for established Web3 contributors.",
  },
  {
    id: "social-graph",
    label: "Social Graph",
    description: "Attestation from a social network with verified connections.",
    disclaimer: "Primary civic path for community-based verification.",
  },
];

export const VERIFICATION_METHOD_LABELS: Record<VerificationMethod, string> = {
  "world-id": "World ID",
  "gitcoin-passport": "Gitcoin Passport",
  "social-graph": "Social Graph",
};

export const MOCK_SBT_ADDRESS =
  "0x00000000000000000000000000000000C1C1C0";
export const MOCK_SBT_CHAIN_ID = 11155111;
// Matches protocol.hashes.HASH_SEPARATOR for cross-layer commitments.
export const HASH_SEPARATOR = "|";

export const MOCK_SBT_ABI = [
  {
    type: "function",
    name: "mint",
    stateMutability: "nonpayable",
    inputs: [
      { name: "to", type: "address" },
      { name: "metadata", type: "string" },
    ],
    outputs: [{ name: "tokenId", type: "uint256" }],
  },
  {
    type: "event",
    name: "Minted",
    inputs: [
      { name: "to", type: "address", indexed: true },
      { name: "tokenId", type: "uint256", indexed: false },
    ],
    anonymous: false,
  },
] as const;

const DEFAULT_LOCATION_SALT = "olympus-civic-location-v1";

export function normalizeZipCode(zip: string): string {
  return zip.replace(/\D/g, "").slice(0, 5);
}

export function isValidZipCode(zip: string): boolean {
  return normalizeZipCode(zip).length === 5;
}

export function maskZip(zip: string): string {
  const normalized = normalizeZipCode(zip);
  if (normalized.length < 3) {
    return normalized;
  }
  return `${normalized.slice(0, 3)}**`;
}

export function formatWalletAddress(address?: string | null): string {
  if (!address) {
    return "";
  }
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

export function normalizeWalletAddress(address: string): string {
  return address.trim().toLowerCase();
}

export function isSameWalletAddress(left: string, right: string): boolean {
  return normalizeWalletAddress(left) === normalizeWalletAddress(right);
}

export function validateWalletAddress(address: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

export function validateVerificationProof(
  method: VerificationMethod,
  proof: VerificationProof,
): { valid: boolean; issues: string[] } {
  const issues: string[] = [];
  if (method === "world-id") {
    if (!proof.worldIdProof) {
      issues.push("World ID proof is required.");
    }
    if (!proof.worldIdNullifier) {
      issues.push("World ID nullifier hash is required.");
    }
  }
  if (method === "gitcoin-passport") {
    if (!proof.passportId) {
      issues.push("Passport ID is required.");
    }
    if (
      proof.passportScore === undefined ||
      !Number.isFinite(proof.passportScore) ||
      proof.passportScore < 15
    ) {
      issues.push("Passport score must be 15 or higher.");
    }
  }
  if (method === "social-graph") {
    if (!proof.socialHandle) {
      issues.push("Social handle is required.");
    }
    if (!proof.socialPlatform) {
      issues.push("Social platform is required.");
    }
    if (!proof.socialProof) {
      issues.push("Social attestation hash is required.");
    }
    if (
      proof.socialGraphConnections === undefined ||
      !Number.isFinite(proof.socialGraphConnections) ||
      proof.socialGraphConnections < 10
    ) {
      issues.push("Social graph must confirm at least 10 connections.");
    }
  }
  return { valid: issues.length === 0, issues };
}

export function sanitizeProof(
  method: VerificationMethod,
  proof: VerificationProof,
): VerificationProof {
  if (method === "world-id") {
    return {
      worldIdProof: proof.worldIdProof,
      worldIdNullifier: proof.worldIdNullifier,
    };
  }
  if (method === "gitcoin-passport") {
    return {
      passportId: proof.passportId,
      passportScore: proof.passportScore,
    };
  }
  return {
    socialHandle: proof.socialHandle,
    socialPlatform: proof.socialPlatform,
    socialProof: proof.socialProof,
    socialGraphConnections: proof.socialGraphConnections,
  };
}

export function canonicalizeProof(proof: VerificationProof): string {
  const ordered = Object.keys(proof)
    .sort()
    .reduce<Record<string, unknown>>((accumulator, key) => {
      const value = proof[key as keyof VerificationProof];
      if (value !== undefined) {
        accumulator[key] = value;
      }
      return accumulator;
    }, {});
  return JSON.stringify(ordered);
}

/**
 * Deterministic BLAKE3 hashing (hex) aligned with protocol.hashes.hash_string().
 */
export function hashString(payload: string): string {
  return bytesToHex(blake3(utf8ToBytes(payload)));
}

/**
 * Deterministic hashing of structured fields joined with HASH_SEPARATOR.
 */
export function hashStructuredFields(...fields: string[]): string {
  return hashString(fields.join(HASH_SEPARATOR));
}

export function createLocationClaim(
  zip: string,
  salt = DEFAULT_LOCATION_SALT,
): LocationClaim {
  const normalized = normalizeZipCode(zip);
  if (normalized.length < 5) {
    throw new Error("ZIP code must include five digits.");
  }
  const zip3 = normalized.slice(0, 3);
  const locationHash = hashStructuredFields(salt, zip3);
  return {
    precision: "zip3",
    locationHash,
    display: `${zip3}**`,
  };
}

export function createPersonhoodCommitment(
  method: VerificationMethod,
  proof: VerificationProof,
): string {
  const proofHash = hashString(canonicalizeProof(proof));
  return hashStructuredFields("personhood", method, proofHash);
}

export function createVerificationId(
  walletAddress: string,
  personhoodId: string,
): string {
  return hashStructuredFields("verification", walletAddress, personhoodId);
}
