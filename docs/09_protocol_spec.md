# Olympus Protocol Specification (v1.0)

This document defines the normative Olympus protocol for **single-node v1.0** and highlights the forward-compatible hooks for **federated Phase 1+**. All sections marked ⚠️ describe Phase 1+ behavior that is not implemented in v1.0 but must be preserved as compatibility points.

## Scope

- Canonicalization, hashing, Merkle commitment, ledger linkage, and proof verification
- External anchoring and timestamping hooks
- Shard headers and ledger entry structure
- Deterministic behavior required for independent verification

Out of scope: deployment topologies, user interfaces, and non-protocol application flows (see `docs/12_protocol_vs_applications.md`).

## Pipeline (Normative)

1. **Ingest** — Accept raw artifact bytes and MIME metadata.
2. **Canonicalize** — Apply version-pinned canonicalizers (`protocol.canonicalizer`) to produce a deterministic byte stream. Canonicalizers are immutable; version bumps are append-only.
3. **Hash** — Compute BLAKE3 hashes with protocol domain separation (`protocol.hashes.HASH_SEPARATOR`, `LEAF_PREFIX`, `NODE_PREFIX`, `LEDGER_PREFIX`). Hash outputs are hex strings at rest.
4. **Commit** — Insert canonical hashes into a Merkle tree / Sparse Merkle Forest (`protocol.merkle`, `protocol.ssmf`) and compute the root.
5. **Anchor** — Optionally request an external timestamp token (RFC 3161) over the root hash (see `docs/11_external_anchoring.md`).
6. **Ledger** — Emit an append-only ledger entry that links to the previous entry hash. The genesis entry uses an empty `previous_hash`.
7. **Prove** — Generate Merkle and ZK redaction proofs (`protocol.redaction`, `protocol.poseidon_tree`).
8. **Replicate** ⚠️ — Phase 1+ guardian replication of shard headers and ledger entries with quorum acknowledgments.
9. **Verify** — Independently recompute canonical bytes, hashes, and proof checks. No secret material is required for verification.

## Cryptographic Primitives

- **Hashing**: BLAKE3 with domain separation. No SHA-256 fallback is permitted in the protocol.
- **Signatures**: Ed25519 for ledger/shard headers. Threshold signatures (e.g., FROST) are a Phase 1+ extension point.
- **Timestamping**: RFC 3161 timestamp tokens over Merkle or ledger roots; TSA certificate fingerprints are part of the evidence.
- **Merkle Trees**: Binary trees with CT-style promotion (lone nodes promoted without hashing on odd counts); Sparse Merkle Forest uses fixed-depth Poseidon/BLAKE3 hybrids.

## Data Structures (Canonical)

- **Canonical Artifact**: Tuple of `(mode, version, canonical_bytes, canonical_hash, raw_hash, witness_anchor?)`. Emitted by `process_artifact()`.
- **Merkle Leaf**: `leaf_hash = leaf_hash(prefix || key || value_hash)` with `LEAF_PREFIX`.
- **Merkle Node**: `node_hash = node_hash(NODE_PREFIX || left || right)`. If odd leaf count, the lone node is promoted without hashing (CT-style).
- **Shard Header**:
  - Fields: `shard_id`, `seq`, `root_hash`, `previous_header_hash`, `timestamp`, `pubkey`, `signature`
  - Canonical serialization: canonical JSON with sorted keys and compact separators
  - Signature: Ed25519 over `shard_header_hash` (BLAKE3 of canonical header JSON)
- **Ledger Entry**:
  - Fields: `timestamp`, `document_hash`, `merkle_root`, `shard_id`, `source_signature`, `previous_hash`, optional `anchor` token reference
  - `entry_hash = hash_bytes(HASH_SEPARATOR.join([...]))`
  - Append-only; `previous_hash` is empty for genesis.
- **Redaction Proof**: Poseidon-backed commitment with sibling positions and revealed indices; max leaves and depth documented in `proofs/circuits/redaction_validity.circom`.

## Determinism Requirements

- Canonicalization functions are idempotent: `C(x) == C(C(x))`.
- JSON serialization uses `json.dumps(..., sort_keys=True, separators=(',', ':'), ensure_ascii=True)`.
- Whitespace normalization is defined in `protocol.canonical.normalize_whitespace`.
- All timestamps are RFC 3339 with trailing `Z` (`protocol.timestamps.current_timestamp`).
- Schema evolution is append-only; prior canonical forms remain valid indefinitely.

## Verification Requirements

Any verifier must be able to, offline and without secrets:

1. Recompute canonical bytes from the original artifact using the published version of the canonicalizer.
2. Recompute leaf and node hashes with the documented domain-separated BLAKE3 functions.
3. Rebuild the Merkle path and confirm the root matches the shard header.
4. Verify the Ed25519 signature on the shard header using the embedded public key.
5. Walk the ledger chain by `previous_hash` back to genesis.
6. Validate optional RFC 3161 timestamp tokens against pinned TSA fingerprints.
7. For redaction proofs, verify Poseidon accumulator consistency and revealed content commitments.

## Forward Compatibility (Phase 1+ Hooks)

- **Replication**: Guardian quorum acknowledgments are stored as append-only attestations linked to shard headers and ledger entries.
- **Consensus**: Conflict resolution rules favor the highest-finality chain (quorum + timestamp monotonicity).
- **Key Rotation**: Superseding signatures are attached without mutating historical headers (see `docs/04_ledger_protocol.md`).
- **External Anchors**: Multiple anchors per batch are allowed; verifiers must accept any valid anchor whose hash matches the documented commitment.
- **Formal model**: The append-only ledger and proof-validity abstraction is captured in `docs/formal/OlympusAppendOnly.tla`.

## Normative References

- Canonicalization: `docs/02_canonicalization.md`
- Merkle Forest and hashing: `docs/03_merkle_forest.md`
- Ledger protocol and finality: `docs/04_ledger_protocol.md`
- ZK redaction: `docs/05_zk_redaction.md`
- Verification flows: `docs/06_verification_flows.md`
- External anchoring: `docs/11_external_anchoring.md`
- Federation protocol prototype: `docs/14_federation_protocol.md`
- Formal specification: `docs/15_formal_spec.md`
- Protocol vs applications: `docs/12_protocol_vs_applications.md`
