# Olympus

Olympus is an append-only public ledger for government documents with planned federation capabilities.

Its purpose is simple:

> Make it cryptographically obvious when public records are created, changed, hidden, or over-redacted.

Olympus is **not** a blockchain, not a DAO, and not a token system.
It is a civic integrity primitive built around deterministic canonicalization,
Merkle commitments, and verifiable proofs.

---

## What Olympus Does

Olympus provides verifiable guarantees that:

- A document existed at a specific time
- The document has not been altered since that time
- A redacted document is a faithful redaction of an original
- History cannot be silently rewritten without detection

It does this through a strict pipeline:

**Ingest → Canonicalize → Hash → Commit → Prove → Replicate → Verify**

We use BLAKE3 for hashing and Merkle commitments; we use Ed25519 for signatures.

---

## What Olympus Does *Not* Do

- It does not assert that governments are honest
- It does not guarantee completeness of public records
- It does not decide what *should* be redacted
- It does not require trust in a single institution

Olympus only guarantees the integrity of what it has seen.

---

## Repository Structure

- `docs/` — The protocol specification (read this first)
- `protocol/` — Reference implementations of core primitives
- `schemas/` — JSON schemas for external interoperability (see `schemas/README.md` for details)
- `proofs/` — Zero-knowledge circuits and notes
- `examples/` — Known-good test artifacts
- `tools/` — CLI utilities for canonicalization and verification
- `storage/` — PostgreSQL storage layer (production backend)
- `migrations/` — Database schema migrations

This repository is intended to be read and audited.

**Note on Schemas**: The JSON schemas in `schemas/` are specification artifacts for external integrators and cross-language implementations. Runtime validation uses Pydantic models defined in the API code. See `schemas/README.md` for the rationale.

---

## Database Backend

Olympus uses **PostgreSQL** as its production database backend.

**Production**: PostgreSQL 16+ only  
**Testing**: PostgreSQL for E2E tests; SQLite for lightweight proof logic tests

## What This Repository Is in Practice (from the DB model)

From the implemented schema and storage layer, this repository is currently a **cryptographic append-only audit database** built on PostgreSQL:
- `smt_leaves` + `smt_nodes` persist Sparse Merkle state
- `shard_headers` persists signed root commitments
- `ledger_entries` persists chained append-only ledger events

In other words: this is primarily a verifiable data-integrity backend and proof service, not a generalized blockchain platform.

See `docs/08_database_strategy.md` for detailed rationale and usage guidance.

---

## Status

This repository is in **protocol hardening phase** preparing for v1.0 release.

**v1.0 Scope:**
- Single-node append-only ledger with Ed25519 signatures
- Sparse Merkle Forest for efficient proofs
- Offline verifiable cryptographic commitments
- PostgreSQL storage backend
- Public audit API

**Phase 1+ Features (not in v1.0):**
- Guardian replication protocol (Phase 1+ only)
- Byzantine fault tolerance
- Multi-node consensus
- Fork detection and resolution

APIs, UIs, and production deployments are intentionally out of scope until
the core semantics are finalized.
