# Olympus

Olympus is a federated, append-only public ledger for government documents.

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

See `docs/08_database_strategy.md` for detailed rationale and usage guidance.

---

## Status

This repository is in **protocol hardening phase**.
APIs, UIs, and deployments are intentionally out of scope until
the core semantics are finalized.

