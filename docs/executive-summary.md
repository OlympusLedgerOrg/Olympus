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
- **Offline verification** using modern cryptography (BLAKE3, Ed25519,
  Poseidon over BN254, Groth16 zkSNARKs, Baby Jubjub EdDSA)

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

The Olympus protocol implementation (v0.10.x) includes:

- A working CD-HS-ST (per-shard 256-level Sparse Merkle Forest, `olympus_crypto::smt`).
- A signed depth-20 Poseidon ledger snapshot per record (Ed25519 over a canonical
  payload), generated at commit time and verifiable offline against the
  authority pubkey.
- Groth16 proof generation and verification for `document_existence`,
  `non_existence`, and `unified_canonicalization_inclusion_root_sign`,
  with `federation_quorum` available for quorum attestations. ADR-0030
  retired the former `redaction_validity` circuit in favor of signed
  Merkle replay for redaction verification.
- A Tauri 2 desktop app with an embedded Axum HTTP server and embedded
  PostgreSQL (`pg_embed`) — no external Python, Go, Node, or Docker
  required at runtime. Windows / Linux / macOS native installers are
  produced by `cargo tauri build`.
- Deterministic, auditable commit logic with SERIALIZABLE transactions and
  per-shard advisory locks for snapshot-index assignment.
- External anchoring (RFC 3161, Sigstore Rekor, OpenTimestamps) behind
  feature-gated `OLYMPUS_ANCHOR_*` env vars.
- Cross-language verifier conformance against Rust and JavaScript
  reference implementations (`verifiers/`).
- Multiple completed security audit rounds. Active rollout items and
  unfixed findings are tracked privately and **not** enumerated in this
  public summary.

The Python FastAPI server and the Go sequencer service were retired in
**v0.9.0**. The Tauri + Axum desktop is now the only first-party runtime.

---

## The Point

Olympus is built on a simple idea:

> **If an institutional action matters, it should be provable.**

No hype.
No tokens.
No vibes.

Just receipts.
