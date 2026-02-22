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

Unknown MIME types fall back to `byte_preserved` mode (raw bytes are hashed without transformation). Canonicalization errors also trigger fallback with a `fallback_reason` field.

## Canonical JSON Encoding (`protocol/canonical_json.py`)

A separate deterministic JSON encoder used internally for protocol operations (ledger hashing, shard headers, policy hashing):

- Rejects NaN and ±Infinity
- Integers emitted without leading zeros
- Non-integers trimmed of trailing zeros
- Fixed notation for `-6 <= exp10 <= 20`; scientific notation otherwise
- `-0` normalized to `0`

## Version Pinning

All canonicalizer versions are declared in `CANONICALIZER_VERSIONS` and embedded in every artifact result. Changing a version requires a protocol version bump and invalidates all historical proofs for that format.

## Commitment Provenance Metadata

Every commitment and verification bundle must carry canonicalization provenance:

- **`format`** — MIME type or format identifier (e.g., `application/pdf`)
- **`normalization_mode`** — Canonicalization pipeline identifier (e.g., `pdf_norm_pikepdf_v1`)
- **`canonicalizer_versions`** — Full `CANONICALIZER_VERSIONS` map pinned at commit time
- **`fallback_reason`** — Explicit fallback reason code when byte preservation is used

This metadata prevents “same document hashed differently later” disputes by making
the canonicalization decision explicit and auditable.

## Canonicalization Rules Summary

- Whitespace normalization
- Consistent encoding (UTF-8)
- Unicode NFC normalization
- Deterministic ordering of keys and attributes
- Removal of non-semantic metadata
- Byte-stable idempotency: `C(x) == C(C(x))`
