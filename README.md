# Olympus

Olympus is an append-only public ledger for government documents with planned federation capabilities.

Its purpose:

> Make it cryptographically obvious when public records are created, changed, hidden, or over-redacted.

Olympus is **not** a blockchain, not a DAO, and not a token system.
It is a deterministic integrity backend built on canonicalization, Merkle commitments, and verifiable proofs.

---

## What Olympus Guarantees

For any committed document, Olympus guarantees:

- **Existence at a specific time**
- **Tamper detection** (content cannot change silently)
- **Verifiable redaction integrity**
- **Append-only historical state**

Integrity violations are rejected or detectable.

---

## How It Works

**Deterministic pipeline:**

```
Ingest → Canonicalize → Hash → Commit → Prove → Verify
```

**Cryptographic primitives:**

- **BLAKE3** — hashing and Merkle commitments
- **Ed25519** — digital signatures

Documents are canonicalized, hashed, inserted into a Sparse Merkle Tree, anchored via signed shard headers, and recorded in a hash-chained ledger.

---

## What It Does Not Guarantee

Olympus does **not**:

- Guarantee completeness of public records
- Guarantee governments are honest
- Decide redaction policy
- Provide distributed consensus (planned Phase 1+)

It guarantees integrity of what it has observed and committed — nothing more.

---

## What This Repository Is (Implementation Reality)

Olympus is currently a:

> **PostgreSQL-backed cryptographic append-only audit database.**

**Core persisted structures:**

- `smt_leaves`, `smt_nodes` — Sparse Merkle state
- `shard_headers` — Ed25519-signed root commitments
- `ledger_entries` — Hash-chained append-only events

**Integrity enforcement layers:**

- Signature verification on read
- DB-level append-order trigger enforcement
- ACID guarantees via PostgreSQL 16+

This repository does not implement distributed networking or consensus.

---

## Threat Model

**Olympus defends against:**

- Retroactive data modification
- Ledger history rewriting
- Out-of-order ledger insertion
- Forged shard headers
- Direct SQL tampering attempts

**It does not defend against:**

- Key compromise
- Full database deletion without replication
- Data never being published
- Multi-node collusion (federation planned)

---

## Repository Structure

- `docs/` — Protocol specification
- `protocol/` — Canonicalization & primitives
- `storage/` — PostgreSQL backend
- `api/` — Public FastAPI audit API
- `migrations/` — Schema + integrity triggers
- `schemas/` — External spec artifacts
- `tests/` — Test suite

This repository is intended to be read and audited.

---

## Status

**Phase 0.5** — Protocol hardening

**v1.0 includes:**

- Single-node append-only ledger
- Signed shard headers
- Sparse Merkle proofs
- PostgreSQL storage
- Public audit API

Federation and consensus are future work.

---

## Quick Start

See [QUICKSTART.md](QUICKSTART.md).

```bash
git clone https://github.com/your-org/Olympus.git
cd Olympus
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest tests/ -v
uvicorn api.app:app --reload
```
