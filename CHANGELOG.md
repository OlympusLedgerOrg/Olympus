# Changelog

All notable changes to the Olympus protocol are documented in this file.

## canonical_v2 — 2026-03-26

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
