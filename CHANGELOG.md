# Changelog

All notable changes to the Olympus protocol are documented in this file.

## canonical_v2 (Round 2) — 2026-03-26

### Breaking Changes

- **Merkle tree: 0x00/0x01 domain separation** (`api/services/merkle.py`)
  Internal node hashes are now computed as `H(0x01 || left || right)` and
  leaf hashes as `H(0x00 || data)`, following RFC 6962 conventions.  This
  prevents a crafted leaf value from colliding with an internal node hash
  and eliminates structural ambiguity in the tree.  All Merkle roots change.
  Pre-launch determination: no stored proofs reference unprefixed roots in
  a way that cannot be regenerated, so no `CANONICAL_VERSION` bump is needed.

### Fixes

- **Unicode homoglyph scrub** (`protocol/canonical.py`)
  `_scrub_homoglyphs()` replaces Unicode characters whose NFKD form is a
  single ASCII printable character with that ASCII character.  This catches
  fullwidth Latin (`Ａ` → `A`), mathematical bold/italic (`𝐔` → `U`), and
  enclosed alphanumerics without touching legitimate non-ASCII (Arabic, CJK,
  accented Latin).  Controlled via `scrub_homoglyphs=True/False` parameter
  on `canonicalize_document()` and `document_to_bytes()`.

- **Schema-annotated list sorting** (`protocol/canonical.py`)
  Added `sorted_list_keys: set[str] | None` parameter to
  `canonicalize_document()` and `document_to_bytes()`.  Fields named in the
  set have their array values sorted deterministically using canonical JSON
  as the sort key.  Default is `None` (preserve order) for backward
  compatibility.

- **Idempotency gate** (`api/ingest.py`)
  `IngestionResult` now includes an `idempotent: bool` field, set `True`
  when a duplicate submission returns the existing record instead of creating
  a new ledger entry.  The existing content-hash dedup check was already
  enforced before any ledger write; this field lets callers distinguish fresh
  inserts from deduplicated returns.

- **Mixed crypto isolation** (`api/ingest.py`, `api/auth.py`)
  `hmac.compare_digest` calls replaced with `_constant_time_equals()` wrapper
  that documents its sole use is timing-safe comparison (not MAC computation).
  Clarifies the crypto boundary: BLAKE3 for hashing, Ed25519 (nacl) for
  signing, `hmac.compare_digest` only for constant-time equality.

- **Proof depth validation** (`api/services/merkle.py`)
  `MerkleProof` now carries `tree_size`; `verify_proof()` validates that
  proof depth matches `ceil(log2(tree_size))` and rejects invalid sibling
  direction values.  `tree_size=0` disables the check for legacy proofs.

- **BLAKE3/Poseidon canonical-hash binding** (`proofs/proof_generator.py`)
  Added `recompute_canonical_hash()` and `_validate_canonical_hash_binding()`
  to the unified circuit validator.  Before witness generation, the Python
  layer independently recomputes the Poseidon chain from `sectionCount`,
  `sectionLengths`, and `sectionHashes`, and rejects inputs where
  `canonicalHash` does not match.  This closes the binding gap between the
  BLAKE3 canonicalization layer and the Poseidon ZK circuit.

## canonical_v2 (Round 1) — 2026-03-26

### Breaking Changes

- **Merkle tree: lone-node self-pair instead of promotion** (`api/services/merkle.py`)
  Lone nodes at any level of the Merkle tree are now duplicated and hashed
  (`H(node || node)`) instead of being promoted without rehashing.  This
  prevents an attacker who controls batching boundaries from producing
  alternate valid roots from the same dataset.  Any tree with an odd leaf
  count will produce a different root than under `canonical_v1`.

### Fixes

- **Numeric canonicalization** (`protocol/canonical.py`)
  `_canonicalize_value()` now normalises numeric types: whole floats are
  converted to `int`, non-whole floats to `Decimal`, and `NaN`/`Inf` are
  rejected with `CanonicalizationError`.  This ensures semantically
  equivalent JSON representations (`100`, `100.0`, `1e2`) produce the same
  canonical bytes.

- **Merkle leaf ordering** (`api/services/merkle.py`)
  `build_tree()` now sorts leaf hashes lexicographically by default so that
  federation nodes ingesting the same dataset in different arrival orders
  produce identical Merkle roots.  A `preserve_order=True` parameter is
  available for append-only log proofs where positional ordering is required.

### Migration

`CANONICAL_VERSION` has been bumped from `canonical_v1` to `canonical_v2`.
`SUPPORTED_VERSIONS` includes both `canonical_v1` and `canonical_v2` so that
the verifier can still accept proofs generated under the old version (with a
deprecation warning).  A full migration layer is planned for a follow-up PR.
