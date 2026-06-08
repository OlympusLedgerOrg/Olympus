/**
 * Byte ↔ base64 helpers for the redaction producer flow.
 *
 * `btoa`/`atob` only speak "binary strings" (one char per byte), so the bytes
 * are walked in fixed-size chunks: `String.fromCharCode(...wholeArray)` blows
 * the call stack on multi-MB files, and a per-byte string concat is O(n²).
 * Chunking keeps both bounded while staying pure-browser (no Buffer, no deps).
 */

// 32 KiB per chunk — comfortably under the argument-count limit of
// `String.fromCharCode.apply` while keeping the loop count low.
const CHUNK = 0x8000;

/** Encode raw bytes to a standard (RFC 4648) base64 string. */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    const slice = bytes.subarray(i, i + CHUNK);
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary);
}

/** Decode a standard base64 string back to raw bytes. */
export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64.trim());
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}
