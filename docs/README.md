# Olympus Documentation Index

This directory contains protocol specifications, design documents, threat model
material, and architectural decisions for Olympus.

**New here?** Start with [`architecture.md`](architecture.md) for a map of the
codebase, then read [`00_overview.md`](00_overview.md) for the full protocol
overview.

## Architecture & Pipeline

| Document | Purpose |
|----------|---------|
| [`architecture.md`](architecture.md) | Pipeline stages → module/file map; developer entrypoints |
| [`00_overview.md`](00_overview.md) | Full protocol overview: principles, pipeline, specification map |
| [`09_protocol_spec.md`](09_protocol_spec.md) | Normative protocol spec: data structures, verification rules |
| [`12_protocol_vs_applications.md`](12_protocol_vs_applications.md) | Boundary contract between protocol and application layers |

## Cryptographic Primitives

| Document | Purpose |
|----------|---------|
| [`02_canonicalization.md`](02_canonicalization.md) | JSON/HTML/DOCX/PDF canonicalization rules |
| [`03_merkle_forest.md`](03_merkle_forest.md) | Merkle tree and Sparse Merkle Forest design |
| [`04_ledger_protocol.md`](04_ledger_protocol.md) | Append-only ledger format and chain linkage |
| [`05_zk_redaction.md`](05_zk_redaction.md) | Zero-knowledge redaction proofs |
| [`11_external_anchoring.md`](11_external_anchoring.md) | RFC 3161 trusted timestamping / external anchoring |
| [`15_formal_spec.md`](15_formal_spec.md) | TLA+ formal specification |
| [`formal/`](formal/) | TLA+ model files |

## Security & Threat Model

| Document | Purpose |
|----------|---------|
| [`01_threat_model.md`](01_threat_model.md) | Attacker models and trust assumptions |
| [`threat_model.md`](threat_model.md) | Detailed threat model (canonical version) |
| [`threat_model_walkthrough.ipynb`](threat_model_walkthrough.ipynb) | Interactive threat model walkthrough notebook |
| [`pentest-scope.md`](pentest-scope.md) | Penetration test scope and rules of engagement |

## Federation (Phase 1+)

> ⚠️ **Guardian replication (multi-node federation) is not implemented in v1.0.**
> The documents below describe the planned Phase 1+ design.

| Document | Purpose |
|----------|---------|
| [`10_federation_governance.md`](10_federation_governance.md) | Federation governance model |
| [`14_federation_protocol.md`](14_federation_protocol.md) | Federation protocol wire format and quorum rules |
| [`PHASE_01_BEST_CASE.md`](PHASE_01_BEST_CASE.md) | Phase 1 implementation plan |
| [`PHASE_05.md`](PHASE_05.md) | Phase 5 roadmap |

## Application Layer & Interfaces

| Document | Purpose |
|----------|---------|
| [`13_public_explorer.md`](13_public_explorer.md) | Public explorer read-only interface spec |
| [`08_database_strategy.md`](08_database_strategy.md) | Database storage strategy |
| [`DATABASE_VALIDATION_CHECKLIST.md`](DATABASE_VALIDATION_CHECKLIST.md) | Database configuration validation checklist |

## Verification

| Document | Purpose |
|----------|---------|
| [`06_verification_flows.md`](06_verification_flows.md) | End-to-end verification flows |
| [`07_non_goals.md`](07_non_goals.md) | Explicit non-goals and out-of-scope items |

## Architecture Decision Records

ADR files live in [`adr/`](adr/).

## Quick Navigation for Contributors

| Question | Answer |
|----------|--------|
| Where is canonicalization? | `protocol/canonical.py`, `protocol/canonical_json.py`, `protocol/canonicalizer.py` |
| Where is hashing? | `protocol/hashes.py` |
| Where is the Merkle tree? | `protocol/merkle.py` |
| Where is ledger logic? | `protocol/ledger.py` |
| Where are redaction proofs? | `protocol/redaction.py` |
| Where are CLI tools? | `tools/` |
| Where are golden test vectors? | `verifiers/test_vectors/`, `examples/` |
| Where are schemas? | `schemas/` |
| How do I run all checks? | `make check` |
| How do I verify golden vectors? | `make vectors` |
| What commands exist? | `make help` |
