# ADR 0007: Public Ledger vs Off-Ledger ZK Redaction Path

## Status
Accepted

## Context
- Olympus must support selective disclosure/redaction without weakening the append-only public ledger.
- Public ledger requirements: append-only, BLAKE3 SMT commitments, shard headers with quorum signatures.
- Redaction requirements: private data remains off-ledger but is provably linked to an on-ledger commitment using ZK proofs.
- Blending these paths risks leaking sensitive data on-ledger or weakening ledger integrity.

## Decision
- Keep **two explicit paths**:
  1. **Public ledger path**: commits BLAKE3 record hashes and SMT roots; replicated via shard headers and ledger entries.
  2. **Off-ledger redaction path**: Poseidon Merkle roots and Groth16 proofs validated against dual commitments; only roots touch the ledger.
- The redaction ledger (`protocol.redaction_ledger`) stores dual commitments and ZK verification artifacts but never raw document content.
- Cross-root validation ensures any redaction proof is anchored to the on-ledger BLAKE3 commitment.
- Governance: any change that moves private data on-ledger or weakens ledger append-only guarantees requires a new ADR and version bump.

## Alternatives Considered
- Store redaction data directly on-ledger: rejected due to privacy and ledger bloat.
- Circuit-bridged single-path design: rejected for complexity and inability to keep ledger hashing post-quantum-friendly.

## Consequences
- The ledger remains minimal and audit-friendly while the redaction path remains privacy-preserving.
- Integration points (dual commitments, verification bundles) are explicit and auditable.
- Threat model clarity: compromise of redaction tooling cannot mutate ledger history; compromise of ledger nodes cannot forge redaction proofs without failing Poseidon validation.
