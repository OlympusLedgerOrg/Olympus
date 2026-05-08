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
 * Maximum nesting depth. Matches src/canonical.rs MAX_DEPTH (64).
 * Prevents stack overflow on adversarial input; real ledger documents nest
 * only a handful of levels.
 */
const MAX_DEPTH = 64;

/**
 * Encode a value as canonical JSON (JCS / RFC 8785).
 *
 * Rules:
 *  - Object keys NFC-normalised first, then sorted by UTF-16 code-unit order
 *    (RFC 8785 §3.2.3). Sort is on the normalised form — matches src/canonical.rs.
 *  - No whitespace between tokens.
 *  - Strings normalised to NFC.
 *  - Numbers: integers serialised without decimal point; floats use the
 *    shortest representation that round-trips (matching JSON.stringify).
 */
export function canonicalJsonEncode(value: CanonicalJsonValue): string {
  return _encode(value, 0);
}

function _encode(value: CanonicalJsonValue, depth: number): string {
  if (depth > MAX_DEPTH) {
    throw new Error(
      `Canonical JSON nesting depth ${depth} exceeds maximum of ${MAX_DEPTH}`,
    );
  }
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Non-finite number in canonical JSON");
    }
    if (!Number.isInteger(value)) {
      throw new Error(
        "Non-integer number in canonical JSON: browser canonicalization only accepts integers",
      );
    }
    if (!Number.isSafeInteger(value)) {
      throw new Error(
        "Unsafe integer in canonical JSON: value cannot be represented losslessly in JavaScript",
      );
    }
    return value.toString();
  }
  if (typeof value === "string") {
    // NFC normalisation ensures byte-for-byte agreement with the Python
    // unicodedata.normalize("NFC", …) call in canonical_json.py.
    return JSON.stringify(value.normalize("NFC"));
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => _encode(v, depth + 1)).join(",") + "]";
  }
  // Object: NFC-normalise keys first, then sort by normalised form (UTF-16
  // code-unit order is JS default string sort). Sorting on the raw key before
  // normalising would diverge from src/canonical.rs for supplementary-plane
  // characters whose NFC form changes their sort position.
  const sortedPairs = Object.keys(value)
    .map((k) => [k, k.normalize("NFC")] as [string, string])
    .sort((a, b) => (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));

  // Reject objects where two distinct raw keys collapse to the same NFC form.
  // Such objects cannot have a unique canonical encoding and indicate a
  // malformed input that would silently corrupt ledger hashes.
  for (let i = 1; i < sortedPairs.length; i++) {
    if (sortedPairs[i][1] === sortedPairs[i - 1][1]) {
      throw new Error(
        `Canonical JSON: keys "${sortedPairs[i - 1][0]}" and "${sortedPairs[i][0]}" ` +
          `both normalize to "${sortedPairs[i][1]}" — duplicate NFC keys break canonical uniqueness`,
      );
    }
  }

  const pairs = sortedPairs.map(
    ([orig, nfc]) =>
      `${JSON.stringify(nfc)}:${_encode((value as Record<string, CanonicalJsonValue>)[orig], depth + 1)}`,
  );
  return "{" + pairs.join(",") + "}";
}
