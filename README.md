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
- `schemas/` — Canonical data formats
- `proofs/` — Zero-knowledge circuits and notes
- `examples/` — Known-good test artifacts
- `tools/` — CLI utilities for canonicalization and verification

This repository is intended to be read and audited.

---

## Status

This repository is in **protocol hardening phase**.
APIs, UIs, and deployments are intentionally out of scope until
the core semantics are finalized.

