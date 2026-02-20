# Olympus Phase 0.1 — Best-Case Readiness

This note captures what “good” looks like for the earliest Phase 0.1 delivery. It is intentionally concrete so auditors know exactly which properties to expect and where to verify them.

## 1) Deterministic identity that survives audit
- **Canonicalizer pinning**: Every canonicalizer run is tied to the exact parser library and version, the canonicalizer version, and explicit behaviors for Unicode normalization, duplicate JSON keys, HTML entity handling, DOCX non-XML parts, and PDF fallback reasons. Version constants are declared in `protocol/canonicalizer.py:CANONICALIZER_VERSIONS`.
- **Idempotent + byte-stable**: Canonicalization is reproducible: `Hash(C(x)) == Hash(C(C(x)))` *and* the bytes of `C(x)` are identical across runs for the same version. Enforced by idempotency guards in `json_jcs()` and `html_v1()`.
- **Multi-format support**: JSON (JCS/RFC 8785), HTML (NFC + attribute sorting), DOCX (ZIP + XML C14N), and PDF (structural scrub) are all supported through the `process_artifact()` entry point.

## 2) Append-only you can independently verify
- **Signed shard headers (Ed25519)** include: root, shard range, created_at, canonicalizer versions, and optional witness anchors.
- **Ledger hash chain**: Shard headers and ledger entries hash-chain together so deletions or reordering are obvious.
- **Sparse Merkle proofs**: Membership proofs exist for every committed artifact hash.
- **Outcome**: A third party can verify exported headers and proofs without trusting the operator; any tampering by a database admin is detectable.

## 3) Existence at time T is witnessed, not just asserted
- Each shard (or batch of shards) includes an external witness anchor over the shard header hash or root—e.g., transparency log entry, timestamp authority token, independent notary signatures, or mirrored publication to watchdogs.
- This upgrades the claim from “we said it existed then” to “others saw it existed then.”

## 4) Storage that scales without weakening integrity
- **PostgreSQL** stores hashes, canonicalization metadata, ledger entries, SMT nodes/leaves, and shard headers.
- **Object storage (S3/MinIO)** holds large raw bytes at a path derived from the raw hash (immutable by construction).
- PostgreSQL keeps only pointers, size, MIME type, and ingest provenance—avoiding bloat while preserving verifiability.

## 5) DB hardening: triggers are guardrails, crypto is the lock
- Acknowledge that triggers/RLS protect against app bugs and low-priv roles; superusers can still cheat locally.
- Real security comes from signed headers, the hash-chained ledger, and independent verification/mirrors.
- Separation of duties (migration role ≠ writer role ≠ auditor role) plus immutable backups (WORM) and frequent export of shard headers to public mirrors.

## 6) Redaction workflows are provable
- Both original and redacted artifacts are committed; redaction records link them (`redacts_artifact_id`, reason code, authority).
- For PDFs (minimum bar): prove the redacted version was committed after the original and ship both hashes and proofs.
- For stronger guarantees later, move toward structured redaction proofs (field/region-level) while keeping the linkage intact.
