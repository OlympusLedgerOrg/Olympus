export const API_BASE =
  (typeof import.meta !== "undefined" &&
    (import.meta as { env?: { VITE_API_BASE?: string } }).env?.VITE_API_BASE) ||
  (typeof window !== "undefined" ? window.location.origin : "");

export const HASH_RE = /^[0-9a-f]{64}$/i;

export const SAMPLE_HASH =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

export function sanitizeId(s: string): string {
  return (
    s
      .replace(/[^a-zA-Z0-9_.:-]/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 200) || "record"
  );
}

export const EXAMPLE_PROOF = {
  content_hash: SAMPLE_HASH,
  merkle_root: SAMPLE_HASH,
  merkle_proof: {
    leaf_hash: SAMPLE_HASH,
    siblings: [],
    root_hash: SAMPLE_HASH,
  },
};
