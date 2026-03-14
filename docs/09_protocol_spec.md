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
- **Signatures**: Ed25519 for ledger/shard headers and Signed Tree Heads (STHs). Threshold signatures (e.g., FROST) are a Phase 1+ extension point.
- **Timestamping**: RFC 3161 timestamp tokens over Merkle or ledger roots; TSA certificate fingerprints are part of the evidence.
- **Merkle Trees**: Binary trees with CT-style promotion (lone nodes promoted without hashing on odd counts); Sparse Merkle Forest uses fixed-depth Poseidon/BLAKE3 hybrids.

## Data Structures (Canonical)

- **Canonical Artifact**: Tuple of `(mode, version, canonical_bytes, canonical_hash, raw_hash, witness_anchor?)`. Emitted by `process_artifact()`.
- **Merkle Leaf**: `leaf_hash = leaf_hash(prefix || key || value_hash)` with `LEAF_PREFIX`.
- **Merkle Node**: `node_hash = node_hash(NODE_PREFIX || left || right)`. If odd leaf count, the lone node is promoted without hashing (CT-style).
- **Shard Header**:
  - Fields: `shard_id`, `seq`, `root_hash`, `previous_header_hash`, `timestamp`, `pubkey`, `signature`
  - `tree_size`: Number of SMT leaves committed by `root_hash` (binds size to the header)
  - Canonical serialization: canonical JSON with sorted keys and compact separators
  - Signature: Ed25519 over `shard_header_hash` (BLAKE3 of canonical header JSON)
- **Ledger Entry**:
  - Fields: `timestamp`, `document_hash`, `merkle_root`, `shard_id`, `source_signature`, `previous_hash`, optional `anchor` token reference
  - `entry_hash = hash_bytes(HASH_SEPARATOR.join([...]))`
  - Append-only; `previous_hash` is empty for genesis.
- **Signed Tree Head (STH)**:
  - Fields: `epoch_id`, `tree_size`, `merkle_root`, `timestamp`, `signature`, `signer_pubkey`
  - Canonical serialization: canonical JSON with sorted keys and compact separators
  - Signature: Ed25519 over `BLAKE3(TREE_HEAD_PREFIX || canonical_sth_payload)`
  - Purpose: Bind every proof to a specific operator-signed epoch root and tree size.
- **Consistency Proof**:
  - Fields: `old_tree_size`, `new_tree_size`, `proof_nodes` (list of 32-byte subtree hashes)
  - Demonstrates that a newer tree is an append-only extension of an older tree
  - Implements RFC 6962 Certificate Transparency style consistency proofs
  - Verification: Reconstruct both old and new roots from proof_nodes and validate they match the claimed STH roots
  - Purpose: Enable observers to detect split-view logs by comparing STHs across nodes
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
8. For consistency proofs, verify that newer STHs represent append-only extensions of older STHs using Certificate Transparency-style consistency proofs.

## Signed Tree Head Consistency Proofs

Olympus implements RFC 6962 Certificate Transparency-style consistency proofs to ensure append-only growth and enable detection of split-view logs.

### Append-Only Guarantees

A consistency proof demonstrates that a newer Merkle tree (with root `R_new` and size `n`) is an append-only extension of an older tree (with root `R_old` and size `m` where `m ≤ n`). The proof contains O(log n) subtree hashes that allow a verifier to:

1. Reconstruct `R_old` from the proof nodes
2. Reconstruct `R_new` from the proof nodes
3. Confirm both reconstructions match the claimed roots

If verification succeeds, the verifier knows that:
- No leaves from the old tree were modified
- No leaves from the old tree were removed
- Only new leaves were appended after position `m`

### Split-View Detection

Observers can detect split-view logs by:

1. **Collecting STHs**: Use the `/protocol/sth/latest` and `/protocol/sth/history` endpoints to collect Signed Tree Heads from multiple nodes
2. **Comparing Roots**: For the same epoch, all nodes must serve STHs with identical `merkle_root` values
3. **Verifying Consistency**: Between epochs, verify that newer STHs are append-only extensions of older STHs using consistency proofs
4. **Cross-Node Gossip**: Compare STHs across nodes; any discrepancy indicates a split-view attack

### Verification Protocol

To verify STH consistency:

```python
def verify_sth_consistency(old_sth, new_sth, proof):
    # Rule 1: Tree size must not decrease
    if new_sth.tree_size < old_sth.tree_size:
        return False

    # Rule 2: Both STH signatures must be valid
    if not old_sth.verify() or not new_sth.verify():
        return False

    # Rule 3: Merkle consistency proof must validate
    old_root = bytes.fromhex(old_sth.merkle_root)
    new_root = bytes.fromhex(new_sth.merkle_root)
    return verify_consistency_proof(old_root, new_root, proof)
```

### Enforced Epoch Transitions

Consistency is enforced automatically at the protocol level via `advance_epoch()`
(`protocol.epochs`).  All epoch transitions **must** use this function rather than
calling `SignedTreeHead.create()` directly.  `advance_epoch()` rejects any
transition where the new tree violates append-only growth:

1. **Non-decreasing tree size** — raises `ValueError` if the new tree has fewer
   leaves than the previous epoch.
2. **Monotonic epoch identifier** — raises `ValueError` if `epoch_id` does not
   strictly exceed the previous `epoch_id`.
3. **Automatic consistency proof generation and verification** — a
   `ConsistencyProof` is generated from the previous tree size to the new tree
   size and immediately verified against both STH roots.  The new STH is only
   signed and returned if verification succeeds.

```python
# Preferred way to transition between epochs
new_sth, proof = advance_epoch(
    previous_sth=previous_sth,  # None for genesis
    new_tree=new_tree,
    epoch_id=next_epoch_id,
    signing_key=signing_key,
)
# proof is None for genesis; a verified ConsistencyProof otherwise
```

For the genesis epoch `previous_sth=None` is passed; no consistency proof is
required and `None` is returned as the second element.

### Gossip Endpoints

Two public endpoints (no authentication required) enable independent monitoring:

- `GET /protocol/sth/latest?shard_id={shard}` — Returns the latest STH for a shard
- `GET /protocol/sth/history?shard_id={shard}&n={count}` — Returns recent STH history (up to 100 entries)

Monitors should:
1. Poll these endpoints regularly from multiple nodes
2. Verify consistency between sequential STHs
3. Alert on any inconsistencies (different roots for same epoch, missing consistency proofs, verification failures)

### Security Properties

**What the system guarantees:**
- If STH consistency verification passes, the tree has grown in an append-only manner
- Epoch transitions created via `advance_epoch()` are rejected unless the new tree
  provably extends the previous tree (append-only enforced at the protocol boundary)
- If two nodes serve different STHs for the same epoch, observers will detect it via gossip
- Operators cannot hide or rollback committed records without detection

**What the system does NOT guarantee:**
- Completeness (operators may omit records from the tree entirely)
- Timeliness (operators may delay publishing STHs)
- Single source of truth (multiple valid forks may exist; observers must choose which to trust)


See `protocol/consistency.py` and `protocol/epochs.py` for implementation details.

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
