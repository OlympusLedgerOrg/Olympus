# ADR 0006: Hash Function Separation (BLAKE3 for Ledger, Poseidon for Circuits)

## Status
Accepted

## Context
- Olympus needs two distinct hashing domains:
  - **Ledger/SMT/commitment path:** bandwidth-efficient, CPU-friendly, ideally post-quantum candidate → BLAKE3.
  - **ZK circuit path:** arithmetic-friendly field hash → Poseidon (BN128).
- Mixing the two domains risks cross-protocol collisions and complicates audits.

## Decision
- Maintain strict separation:
  - **BLAKE3** for ledger hashes, SMT leaves/nodes, shard headers, canonicalization hashes, verification bundle commitments.
  - **Poseidon** only inside ZK circuits and Poseidon-based Merkle trees used for redaction proofs.
- Enforce domain separation constants:
  - `HASH_SEPARATOR` for structured BLAKE3 hashing.
  - `POSEIDON_DOMAIN_LEAF`, `POSEIDON_DOMAIN_NODE`, `POSEIDON_DOMAIN_COMMITMENT` for Poseidon hashing.
- Provide explicit boundary helpers:
  - `poseidon_hash_with_domain` and CT-style Poseidon Merkle tree utilities in `protocol.poseidon_tree`.
  - Cross-root validation to prevent mixing of BLAKE3 and Poseidon proofs.

## Alternatives Considered
- Single hash (Poseidon everywhere): rejected due to performance and post-quantum considerations for ledger commitments.
- Single hash (BLAKE3 everywhere): rejected because circuits would require expensive hash gadgets and larger proofs.

## Consequences
- Clear audit boundary: BLAKE3 never enters circuits; Poseidon never commits ledger state.
- Performance remains optimized for both domains.
- Any future hash changes require coordinated versioning and new ADRs.
