# Threat Model

This document describes the threat model for the Olympus protocol. For an interactive walkthrough with attack scenarios and verification exercises, see `docs/threat_model_walkthrough.ipynb`.

## Assets and Invariants

- Canonical document bytes and hashes (BLAKE3 with domain separation)
- Ledger chain integrity (`previous_hash` linkage back to genesis)
- Shard header signatures (Ed25519 public keys)
- Merkle/Sparse Merkle roots and proofs
- External timestamp anchors (RFC 3161)
- Governance records (membership, rotations, anchors)

## Adversaries

- **Malicious submitters** attempting equivocation or ambiguous inputs.
- **Compromised ledger operator** seeking to rewrite or reorder history.
- **State-level actors** with the ability to coerce infrastructure or TSAs.
- **Insiders** leaking or tampering with signing keys or canonicalization code.
- **Network attacker** performing replay, downgrade, or fork-isolation attacks.

## Trust and Assumptions

- Cryptographic primitives (BLAKE3, Ed25519, Poseidon) are secure.
- Canonicalizers are deterministic and version-pinned; changes are explicit.
- Timestamps from TSAs are honest **only** to the extent of their published fingerprints.
- Guardians (Phase 1+) are independent and not simultaneously compromised beyond the quorum threshold.

## Security Goals

- **Tamper evidence**: Any mutation changes hashes/signatures.
- **Non-repudiation**: Signatures and anchors bind operators to emitted state.
- **Fork detection**: Conflicting shard headers or ledger tails are detectable via public comparison.
- **Availability under partial failure**: Replication and backpressure prevent silent gaps (Phase 1+).
- **Determinism**: Re-running canonicalization and hashing yields identical results.

## Attack Surfaces and Mitigations

- **Ambiguous inputs**: Rejected by canonicalizers that enforce NFC, duplicate-key rejection, and idempotency checks.
- **Replay or rollback**: Ledger entries chain via `previous_hash`; auditors walk back to genesis.
- **Key compromise**: Addressed via revocation + superseding signatures; verifiers reject post-compromise headers (see `docs/04_ledger_protocol.md`).
- **Fork isolation**: Public explorer and multi-node comparison expose divergent roots; Guardian acknowledgments add quorum weight (Phase 1+).
- **Anchor forgery**: RFC 3161 tokens verified against pinned TSA fingerprints (see `docs/11_external_anchoring.md`).
- **Canonicalizer drift**: Version pinning and golden vectors prevent silent behavioral changes; changes require a protocol version bump.
- **Side-channel/application bugs**: Separation between protocol and UI layers prevents UI compromise from changing canonical bytes (`docs/12_protocol_vs_applications.md`).

## Residual Risks (Accepted)

- Completeness of records is a policy/process problem, not a cryptographic guarantee.
- TSA compromise can misorder anchors but cannot alter ledger hashes; mitigation is multi-TSA anchoring and watchdog verification.
- Insider collusion above the Guardian quorum (Phase 1+) can finalize a fork; transparency plus public auditing lowers detection latency.

## Monitoring Hooks

- Continuous hash/signature verification against published headers and ledger tails.
- Anchor freshness alerts when TSA cadences slip.
- Governance registry diff alerts (membership, quorum size, fingerprints).
- Cross-node divergence detection in the public explorer.

## Non-Goals

- Preventing document submission or spam.
- Guaranteeing that all relevant documents were ingested.
- Enforcing confidentiality of unredacted content (redaction proves removals only).
- Replacing legal or organizational governance processes.
