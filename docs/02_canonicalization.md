# Canonicalization

This document describes the canonicalization process in Olympus.

## Purpose

Canonicalization ensures that semantically equivalent documents produce identical hashes, regardless of superficial formatting differences.

## Pipeline Stages

1. Parse input document
2. Extract semantic content
3. Normalize structure (Unicode NFC, whitespace, attribute ordering)
4. Apply deterministic serialization
5. Output canonical representation

## Canonicalization Layers

Olympus provides two canonicalization layers:

### Basic Canonicalization (`protocol/canonical.py`)

Used for internal protocol operations:

- **JSON**: `json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)`
- **Text**: Whitespace normalization, line ending normalization (CRLF/CR → LF)
- **Documents**: Recursive key sorting and whitespace normalization

### Hardened Artifact Canonicalization (`protocol/canonicalizer.py`)

Phase 0.1 Institutional Pinning — multi-format artifact ingestion with byte-stable idempotency guarantees. Each canonicalizer is version-pinned for hash stability.

#### JSON — JCS (RFC 8785)

- **Module**: `Canonicalizer.json_jcs()`
- **Version**: `1.2.0-strict-numeric`
- Unicode NFC normalization before parsing
- Duplicate key rejection (Semantic Ambiguity Protection)
- `Decimal`-based number parsing to avoid IEEE-754 float drift
- Deterministic number serialization (ECMA-262 compliant)
- Lexicographic key sorting
- Idempotency guard: `C(x) == C(C(x))`

#### HTML

- **Module**: `Canonicalizer.html_v1()`
- **Version**: `1.0.1-lxml-pinned-nfc`
- Requires `lxml` (version-pinned in production)
- Unicode NFC normalization
- Attribute sorting by name
- Active content stripping (`<script>`, `<style>`, `<iframe>`, etc.)
- Whitespace normalization within text nodes

#### DOCX

- **Module**: `Canonicalizer.docx_v1()`
- **Version**: `1.1.0-c14n-strict`
- Requires `lxml` for XML C14N
- Lexicographic ZIP entry ordering
- Volatile metadata stripping (timestamps, thumbnails, `docProps/core.xml`)
- Exclusive XML Canonicalization (C14N) for XML parts
- Returns BLAKE3 digest of canonical content stream

#### PDF

- **Module**: `Canonicalizer.pdf_normalize()`
- **Version**: `1.4.0-pikepdf-10.3.0-linearized`
- Implementation: `pikepdf` (version-pinned)
- Strips volatile metadata keys (CreationDate, ModDate, Producer, Creator, Title, Subject, Author, Keywords) and clears XMP packets
- Forces deterministic document IDs (`static_id=True`) and linearized output for stable byte order
- Line ending normalization to LF

## Artifact Ingestion

The `process_artifact()` function is the primary entry point:

```python
from protocol.canonicalizer import process_artifact

result = process_artifact(raw_bytes, "application/json", witness_anchor="anchor-123")
# Returns: {
#   "raw_hash": "...",
#   "canonical_hash": "...",
#   "mode": "jcs_v1",
#   "version": "1.2.0-strict-numeric",
#   "witness_anchor": "anchor-123",
#   ...
# }
```

Unknown MIME types are rejected with `UnsupportedMimeTypeError`, and canonicalization failures raise explicit `ArtifactCanonicalizationError`/`ArtifactIdempotencyError` exceptions instead of silently falling back to raw bytes. Successful runs still include a `fallback_reason` field (always `null`) for bundle schema compatibility.

## Canonical JSON Encoding (`protocol/canonical_json.py`)

A separate deterministic JSON encoder used internally for protocol operations (ledger hashing, shard headers, policy hashing):

- All object keys and string values are normalized to Unicode **NFC** before serialization
- Finite **Decimal** and integer numeric types only (`float` inputs are rejected)
- Rejects NaN and ±Infinity
- Integers emitted without leading zeros
- Non-integers trimmed of trailing zeros
- Fixed notation for `-6 <= exp10 <= 20`; scientific notation otherwise
- `-0` normalized to `0`
- Duplicate keys created by NFC normalization are rejected

## Formal Canonicalization Specification (Normative)

All implementations MUST follow these rules before hashing canonical payload bytes:

1. **Unicode normalization**
   - Every JSON key and every string value MUST be normalized to NFC.
   - Canonical-equivalent strings (e.g., `"\u00E9"` and `"e\u0301"`) MUST serialize identically.
2. **Numeric normalization**
   - Numeric values MUST be represented using arbitrary-precision decimal semantics.
   - Implementations MUST reject language-native binary floating-point values for canonical protocol encoding.
   - Non-finite numeric values (NaN, +Infinity, -Infinity) MUST be rejected.
3. **Structural determinism**
   - Object keys MUST be sorted lexicographically.
   - If NFC normalization causes key collisions, canonicalization MUST fail.
   - Arrays MUST preserve input order.
4. **Serialization determinism**
   - JSON serialization MUST be compact (no insignificant whitespace).
   - Output bytes MUST be UTF-8 encoded.
   - Number formatting MUST follow the fixed/scientific threshold used by `protocol/canonical_json.py`.
5. **Hash input**
   - Hashing MUST consume canonical bytes only (`canonical_json_bytes(...)` output).
   - Hash domain separation prefixes (`OLY:*`) remain mandatory.

## Version Pinning

All canonicalizer versions are declared in `CANONICALIZER_VERSIONS` and embedded in every artifact result. Changing a version requires a protocol version bump and invalidates all historical proofs for that format.

## Newline Handling

Line endings are normalized to Unix-style LF (`\n`):

- `\r\n` (Windows) → `\n`
- `\r` (old Mac) → `\n`

After normalization, leading and trailing empty lines are stripped while internal empty lines are preserved. Each line's whitespace is individually normalized (multiple spaces/tabs collapsed to a single space, leading/trailing trimmed).

This is implemented in `canonicalize_text()` in `protocol/canonical.py`.

## Timestamp Normalization

All timestamps use RFC 3339 / ISO 8601 format with a `Z` suffix for UTC:

```
2024-01-15T12:30:00.000000Z
```

Generated by `protocol.timestamps.current_timestamp()`, which calls `datetime.now(UTC).isoformat()` and replaces `+00:00` with `Z`.

For cryptographic timestamp anchoring via an external Timestamp Authority (RFC 3161), see `protocol/rfc3161.py`.

## Security Rationale

Canonicalization is a security-critical component. Without deterministic canonicalization, semantically identical documents could produce different hashes, undermining the integrity guarantees of the entire protocol. The following design choices mitigate specific threats:

### Why Deterministic Formatting?

**Threat:** An attacker submits two semantically identical documents that produce different hashes, allowing them to claim the ledger was tampered with (or to submit a "different" document that was already committed).

**Mitigation:** Every document is canonicalized before hashing — sorted keys, compact separators, collapsed whitespace, NFC Unicode normalization — so semantically equivalent inputs always produce identical byte sequences.

### Why Domain-Separated Hashing?

**Threat:** A Merkle leaf hash is reinterpreted as an internal node hash (or vice versa), enabling second-preimage attacks on the tree structure.

**Mitigation:** BLAKE3 hashes use domain-separation prefixes (`OLY:LEAF:V1`, `OLY:NODE:V1`, `OLY:LEDGER:V1`, etc.) so hashes from one domain can never collide with hashes from another.

### Why Reject NaN and Infinity?

**Threat:** IEEE 754 special values (NaN, ±Infinity) have platform-dependent string representations, causing cross-implementation hash divergence.

**Mitigation:** `canonical_json_encode()` and `Canonicalizer.json_jcs()` reject NaN and Infinity with a `ValueError` / `CanonicalizationError`.

### Why Idempotency Guards?

**Threat:** A canonicalization function that is not idempotent (`C(x) ≠ C(C(x))`) could silently change document content on re-processing, breaking proof verification.

**Mitigation:** The `process_artifact()` function includes byte-stable idempotency checks — the output of canonicalization is re-canonicalized and compared to ensure `C(x) == C(C(x))`.

### Why Version Pinning?

**Threat:** A library upgrade changes canonicalization behavior (e.g., a new version of `lxml` normalizes attributes differently), silently invalidating all historical proofs.

**Mitigation:** All canonicalizer versions are declared in `CANONICALIZER_VERSIONS` and embedded in every artifact result. Changing a version requires a protocol version bump.

### Independent Verifiability

A third party can independently verify any document's hash by:

1. Obtaining the original document bytes
2. Applying the documented canonicalization rules (this document)
3. Computing BLAKE3 with the appropriate domain-separation prefix
4. Comparing the result against the committed hash in the ledger

No secret keys or proprietary algorithms are required for verification.

## Canonicalization Rules Summary

- Whitespace normalization (Unicode NFC, then residual NBSP mapping, then collapse)
- Consistent encoding (UTF-8)
- Unicode NFC normalization (for JSON/HTML content)
- Deterministic ordering of keys and attributes
- Line ending normalization (CRLF/CR → LF)
- Removal of non-semantic metadata
- Byte-stable idempotency: `C(x) == C(C(x))`
- Domain-separated hashing to prevent cross-domain collisions
