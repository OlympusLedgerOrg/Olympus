/**
 * Canonical JSON encoder (JCS / RFC 8785).
 *
 * Produces a deterministic UTF-8 string representation of a JSON value by
 * sorting object keys lexicographically at every nesting level, normalising
 * Unicode to NFC, and stripping all insignificant whitespace.  The output is
 * byte-for-byte identical to the Python reference:
 *
 *   from protocol.canonical_json import canonical_json_encode
 *
 * This matches the server-side `canonical_json_encode()` used by the Olympus
 * ingestion pipeline so that BLAKE3 digests computed in the browser are
 * consistent with ledger entries.
 */

/** Any value that can appear in a canonical JSON document. */
export type CanonicalJsonValue =
  | null
  | boolean
  | number
  | string
  | CanonicalJsonValue[]
  | { [key: string]: CanonicalJsonValue };

/**
 * Encode a value as canonical JSON (JCS / RFC 8785).
 *
 * Rules:
 *  - Object keys sorted lexicographically (Unicode code-point order).
 *  - No whitespace between tokens.
 *  - Strings normalised to NFC.
 *  - Numbers: integers serialised without decimal point; floats use the
 *    shortest representation that round-trips (matching JSON.stringify).
 */
export function canonicalJsonEncode(value: CanonicalJsonValue): string {
  return _encode(value);
}

function _encode(value: CanonicalJsonValue): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!isFinite(value)) throw new Error("Non-finite number in canonical JSON");
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    // NFC normalisation ensures byte-for-byte agreement with the Python
    // unicodedata.normalize("NFC", …) call in canonical_json.py.
    return JSON.stringify(value.normalize("NFC"));
  }
  if (Array.isArray(value)) {
    return "[" + value.map(_encode).join(",") + "]";
  }
  // Object: sort keys lexicographically
  const sortedKeys = Object.keys(value).sort();
  const pairs = sortedKeys.map(
    (k) => `${JSON.stringify(k.normalize("NFC"))}:${_encode((value as Record<string, CanonicalJsonValue>)[k])}`,
  );
  return "{" + pairs.join(",") + "}";
}
