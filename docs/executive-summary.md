# Executive Summary

## Olympus — Executive Summary

**Olympus is a verifiable ledger for sensitive information.**  
It turns institutional data, compliance actions, and oversight decisions into **cryptographically provable facts**—not dashboards, not trust-me PDFs, not promises.

At its core, Olympus answers one question with mathematical certainty:

> **"Can any party independently verify that this record existed at a specific time, hasn't been altered, and is part of the official state?"**

The answer is **yes** — independently and offline.

---

## What Olympus Is

Olympus is a **CD-HS-ST (Constant-Depth Hierarchical Sparse Tree)**–backed integrity ledger that provides:

- **Append-only records** (no silent edits, no deletions)
- **Cryptographic proofs** of existence and non-existence
- **Jurisdictional sharding** encoded directly into the key space (county, period, stream)
- **A single global state root** — one 256-level Sparse Merkle Tree commits all records across all shards
- **Offline verification** using modern cryptography (BLAKE3 + Ed25519)

Think of it as **Certificate Transparency for institutions**, generalized to *any* sensitive record.

---

## What Problem It Solves

Today’s institutional accountability failures are not abstract—they are structural:

- Records quietly edited or “corrected”
- Audit responses that can’t be independently verified
- Reviews that rely on institutional trust instead of proof
- Stakeholders forced to believe screenshots, PDFs, or assurances

Olympus replaces **trust** with **verification**.

If a record is real, Olympus can prove it.  
If it’s missing, Olympus can prove *that too*.

---

## Architecture (Plain English)

### 1. One Global Tree (CD-HS-ST)
All records across all jurisdictions live in a **single 256-level Sparse Merkle Tree**. Shard identity is encoded directly into the leaf key:

```
key = H(GLOBAL_KEY_PREFIX || shard_id || record_key)
```

- Each record is a cryptographic leaf in this global tree
- Shard boundaries are logical (encoded in the key), not physical (no separate per-shard trees)
- Updates are append-only and ordered within each shard
- The tree root represents the **entire system state** across all shards

This replaces an earlier two-tree model (per-shard SMT + forest SMT) that had consistency hazards.

### 2. Shard Headers (Jurisdictional Snapshots)
Each update to a shard produces a **shard header** that captures the tree root at that point:

- Ed25519-signed commitment to the global tree root after the shard update
- Includes shard-specific metadata (shard ID, sequence number, timestamp)
- Anyone can verify authenticity without trusting the operator

### 3. Ledger Entries (Tamper-Evident Chain)
Every commit is recorded as a chained **ledger entry**:

- Each entry includes the hash of the previous entry (chain linkage)
- The global tree root is cryptographically bound into the entry hash
- Breaking or reordering the chain is detectable by any observer

---

## What Can Be Proven

Olympus supports cryptographic proofs for:

- **Record existence**  
  “This exact record was committed at this time.”

- **Record non-existence**  
  “This record did *not* exist at this time.”

- **Shard inclusion**  
  “This jurisdiction’s ledger is part of the global state.”

- **Global state verification**  
  “All shards roll up into this signed root.”

These proofs are small, fast, and verifiable in browsers, scripts, or court filings.

---

## Why This Is Different

| Typical GovTech | Olympus |
|-----------------|---------|
| Centralized databases | Cryptographic commitments |
| Editable records | Append-only ledger |
| Trust-based audits | Proof-based verification |
| APIs you must believe | Proofs you can verify |
| “Transparency portals” | Mathematical transparency |

Olympus does not *visualize* trust.  
It **eliminates the need for it**.

---

## Who This Is For

- **Stakeholders** who want proof, not promises
- **Auditors** who need receipts that survive scrutiny
- **Oversight bodies** who don’t trust PDFs
- **Institutions** that want credibility without reputational risk
- **Regulators** who need verifiable timelines

---

## Status

The Olympus protocol implementation includes:

- A working CD-HS-ST (single global 256-level Sparse Merkle Tree)
- Signed shard headers with Ed25519 and RFC 3161 timestamps
- Proof generation and verification (existence, non-existence, redaction)
- FastAPI endpoints, PostgreSQL storage, and comprehensive tests (≥85% coverage)
- Deterministic, auditable commit logic with SERIALIZABLE transactions
- Phase 1 Go sequencer and Rust cryptographic service (in progress, not yet primary write path)

The system is in **Phase 0** (protocol hardening). The Python API path is the current primary write path; the Go → Rust service path is being hardened in parallel.

---

## The Point

Olympus is built on a simple idea:

> **If an institutional action matters, it should be provable.**

No hype.  
No tokens.  
No vibes.

Just receipts.
