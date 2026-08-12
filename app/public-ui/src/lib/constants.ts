export const HASH_RE = /^[0-9a-f]{64}$/i;

export const SAMPLE_HASH = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

export function sanitizeId(s: string): string {
  return (
    s
      .replace(/[^a-zA-Z0-9_.:-]/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 200) || "record"
  );
}
