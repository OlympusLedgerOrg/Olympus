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

**Multi-format canonicalization (Phase 0.1):**

The hardened canonicalizer (`protocol/canonicalizer.py`) provides byte-stable, idempotent artifact ingestion with version-pinned canonicalization for:

- **JSON** — JCS (RFC 8785) with NFC normalization, duplicate key rejection, and `Decimal`-based numeric parsing
- **HTML** — NFC normalization, attribute sorting, active content stripping (requires `lxml`)
- **DOCX** — ZIP entry ordering, XML C14N, volatile metadata stripping (requires `lxml`)
- **PDF** — pikepdf-based normalization: volatile metadata scrub, static IDs, linearization, and LF line endings

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

See [threat-model.md](threat-model.md) for a plain-English one-page summary
suitable for auditors, policymakers, and grant committees.

---

## FOIA Workflow Support

Olympus is designed to bring cryptographic integrity to Freedom of Information
Act (FOIA) workflows.  The core problem it addresses: **an agency could alter a
document before responding to a FOIA request**, and the requester would have no
way to know.

### How the FOIA Workflow Works

```
Agency publishes document → Olympus commits hash → FOIA request arrives
→ Agency produces redacted version → Requestor verifies redacted version
  is derived from the same committed original
```

1. **Pre-commitment** — Before any FOIA request arrives, the agency commits
   the original document to Olympus.  A cryptographic fingerprint (BLAKE3 hash)
   and a signed Merkle commitment are written to the append-only ledger.

2. **Redaction proof** — When the agency produces a redacted FOIA response, it
   uses `protocol/redaction.py` to generate a `RedactionProof`.  This proof
   cryptographically ties each revealed paragraph or section back to the
   pre-committed Merkle root.

3. **Independent verification** — Any requester or auditor can call
   `RedactionProtocol.verify_redaction_proof(proof, revealed_content)` to
   confirm:
   - The revealed content matches its committed hash.
   - Each revealed section has a valid Merkle inclusion proof against the
     original root.
   - The root in the proof matches the root that was committed to the ledger
     before the FOIA request.

### What This Proves

| Property | Guarantee |
|----------|-----------|
| Original document was committed before the FOIA request | ✅ Ledger timestamp and hash-chain linkage |
| Revealed content was not altered between commitment and release | ✅ Hash comparison against committed leaf |
| Redacted sections cannot be silently un-redacted later | ✅ Merkle root is fixed at commitment time |
| The agency cannot claim a different original document | ✅ Signed shard header binds root to agency key |

### Key Code Entry Points for FOIA Auditors

| Component | Location | Purpose |
|-----------|----------|---------|
| Redaction proof creation | `protocol/redaction.py` — `RedactionProtocol.create_redaction_proof()` | Generates a proof for a FOIA redacted release |
| Redaction proof verification | `protocol/redaction.py` — `RedactionProtocol.verify_redaction_proof()` | Independently verifies a FOIA redaction proof |
| Document commitment | `protocol/redaction.py` — `RedactionProtocol.commit_document()` | Commits an original document before FOIA disclosure |
| Redacted document reconstruction | `protocol/redaction.py` — `RedactionProtocol.reconstruct_redacted_document()` | Rebuilds a redacted document with markers for omitted sections |
| Ledger chain verification | `protocol/ledger.py` — `Ledger.verify_chain()` | Confirms no entries have been added out-of-order or tampered with |

### Example: Verifying a FOIA Response

```python
from protocol.redaction import RedactionProtocol

# Receive the redaction proof from the agency (stored in the ledger)
# and the revealed content from the FOIA response
is_valid = RedactionProtocol.verify_redaction_proof(proof, revealed_content)

if is_valid:
    print("FOIA response is cryptographically consistent with the committed original.")
else:
    print("WARNING: FOIA response does NOT match the committed original.")
```

### What Olympus Does Not Guarantee for FOIA

- **Completeness** — Olympus cannot force an agency to commit all documents.
  It only guarantees the integrity of what has been committed.
- **Redaction policy** — Olympus does not decide what should or should not be
  redacted.  That judgment remains with the agency and applicable law.
- **Key honesty** — If an agency controls the signing keys, Olympus cannot
  detect colluding parties signing forged roots.  Federation (planned Phase 1+)
  addresses this.

---

## Repository Structure

- `docs/` — Protocol specification
- `protocol/` — Canonicalization, cryptographic primitives, and artifact ingestion
- `storage/` — PostgreSQL backend
- `api/` — Public FastAPI audit API
- `migrations/` — Schema + integrity triggers
- `schemas/` — External spec artifacts
- `tests/` — Test suite
- `tools/` — CLI utilities for canonicalization and verification

This repository is intended to be read and audited.

---

## Status

**Phase 0.5** — Protocol hardening

**v1.0 includes:**

- Single-node append-only ledger
- Signed shard headers
- Sparse Merkle proofs
- Version-pinned multi-format canonicalization (JSON/HTML/DOCX/PDF)
- PostgreSQL storage
- Public audit API

Federation and consensus are future work.

Phase 0.1 “best-case” expectations are captured in [docs/PHASE_01_BEST_CASE.md](docs/PHASE_01_BEST_CASE.md).

---

## Current State for Government Verification

- **Posture:** Reference integrity layer suitable for pilot deployments where an agency must prove document provenance and redaction correctness to the public.
- **What works today:** Cryptographic commitments (BLAKE3), Merkle proofs, Ed25519-signed shard headers, append-only ledger verification, and FOIA redaction proof tooling.
- **Immediate improvements being hardened:**
  - Guardian/replicated shard signing to reduce single-operator trust.
  - HSM-backed key custody and rotation runbooks for agency signing keys.
  - Operational assurances: tested backup/restore, external transparency anchoring, and audit logging defaults.
  - Ingest/egress automation for FOIA pipelines so commitments and proofs are published automatically.

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
