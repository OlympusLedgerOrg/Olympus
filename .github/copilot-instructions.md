# Copilot Instructions for Olympus

> **Authoritative source:** `CLAUDE.md` at the repo root is the canonical
> guidance file for AI assistants (commands, architecture, critical
> invariants, environment variables). This file is a Copilot-flavored
> summary; when the two disagree, `CLAUDE.md` wins. Keep them in sync.

## Project Overview

Olympus is an append-only, verifiable ledger for sensitive information. It
provides cryptographic guarantees about record integrity and provenance
without being a blockchain, DAO, or token system, built around deterministic
canonicalization, Sparse Merkle Tree commitments, and zero-knowledge proofs.

**Core Purpose:** Make it cryptographically obvious when sensitive records are
created, changed, hidden, or over-redacted — independently verifiable offline.

Current version: **v0.9.5**. Shipped as a **Tauri 2 desktop app**.

## Language Ownership — Hard Boundaries

```text
Rust       → Tauri app, embedded Axum HTTP server, crypto hot path (BLAKE3,
             Ed25519, Poseidon, SMT, canonicalization), embedded PostgreSQL
             (pg_embed), all DB ops, SBT issue/verify/revoke, ZK prove/verify,
             anchoring (RFC 3161 / Rekor / OpenTimestamps)
TypeScript → React + Vite frontend (app/public-ui/)
Python     → BUILD-TIME / VERIFIER-SIDE ONLY — circuit-setup helpers
             (proofs/*.py), cross-language conformance verifiers
             (verifiers/cli/, verifiers/python/), and dev scripts (scripts/)
```

**The running app never executes Python or Go.** The Python FastAPI server, the
Go sequencer, and the Go/Python operational stack were **retired in v0.9.0** and
replaced by the Tauri + Axum desktop. Do **not** reintroduce them, and do **not**
treat any `protocol/`, `api/`, `storage/`, or `tools/` Python package as live —
those directories no longer exist. Shared crypto lives solely in
`crates/olympus-crypto`.

## Architectural Principles (still binding)

1. **Append-Only Ledger** — all operations are additive; no modify/delete.
2. **Deterministic Canonicalization** — JCS/RFC 8785 raw UTF-8; semantically
   equivalent inputs must produce identical hashes. Canonicalization lives in
   Rust (`crates/olympus-crypto`) and is the single source of truth.
3. **Single global SMT (CD-HS-ST model)** — one logical Sparse Merkle Tree,
   logically sharded by keyspace. Do **NOT** reintroduce the old "per-shard tree
   + forest tree" pattern, and do **NOT** create separate `smt_nodes` vs
   `forest_nodes` tables. Persistent SMT writers must serialise through
   `NodeBackend::acquire_write_lock` across the read-modify-write.
4. **Verifiable Proofs** — every operation must be independently verifiable;
   `verifiers/rust` and `verifiers/javascript` are the maintained offline
   reference implementations.

## Where Things Live

- `src-tauri/` — Tauri 2 binary: entry (`main.rs`), Axum router (`server/`),
  route handlers (`api/`: `ingest`, `ledger`, `redaction`, `admin`,
  `admin_users`, `keys`, `zk`, `user_auth`, `credentials`, `shards`,
  `trusted_issuers`), state (`state.rs`), ZK (`zk/`), anchoring (`anchoring/`),
  quorum (`quorum/`), federation (`federation/`, feature-gated).
- `crates/olympus-crypto` — canonical shared crypto (BLAKE3 domain prefixes,
  `leaf_hash`/SMT, Poseidon, canonicalization, ADR-0005 constants).
- `proofs/` — Circom circuits + Groth16 setup pipeline (`setup_circuits.sh`,
  `phase2_ceremony.sh`, `CEREMONY_INTEGRITY.md`).
- `app/public-ui/` — React + TypeScript + Vite + Tailwind frontend.
- `migrations/` — sqlx migrations, applied by Tauri on startup.
- `verifiers/` — cross-language offline verifiers + conformance vectors.
- `docs/` — architecture, ADRs (`docs/adr/`), threat model, audits.

## Critical Invariants (see CLAUDE.md for the full list)

- **Leaf hash binds shard + parser provenance** — ADR-0005 structured binary
  prefix, then a count-framed body of
  `lp(key) || value_hash || lp(parser_id) || lp(cpv) || lp(model_hash)`.
  Changing the field set/layout is a breaking hash change: update
  `olympus-crypto`, both SMTs, both verifiers, the `smt_leaves` schema, AND
  regenerate the SSMF golden vectors
  (`cargo run -p olympus-crypto --example gen_ssmf_vectors --features smt`) in
  the **same commit**. `verifiers/test_vectors/vectors.json` is the single
  source of truth.
- **Domain prefixes are protocol-critical** — node hashes use `OLY:NODE:V1|`;
  empty-leaf sentinel uses `OLY:EMPTY-LEAF:V1`. Constants live in
  `crates/olympus-crypto/src/lib.rs`. Never change a prefix without breaking
  historical-proof compatibility.
- **Signing keys must be persisted** — ephemeral Ed25519 / Baby Jubjub keys make
  historical signed roots and existing SBTs unverifiable.
- **SBT scope mapping is hardcoded in `auth.rs`** and fail-closed: unknown
  `credential_type` grants no scopes. Treat it as security policy, not config.
- **Shard creation is operator-controlled** — first use of a `shard_id` is gated
  by the `shards` registry (`authorize_write`, fail-closed).
- **Ceremony manifests are atomic** — any vkey change requires regenerating its
  manifest in the same commit (`cargo build` panics on mismatch). Never
  hand-edit `proofs/keys/manifests/*.json`.

## Non-Goals

Olympus intentionally does NOT: assert that institutions are honest; guarantee
completeness of records; decide what should be redacted; require trust in a
single operator. Do not imply otherwise in code or docs.

## Documentation Style

Be precise and technical — this is an auditable protocol. Focus on what the code
proves cryptographically, avoid marketing language, reference the threat model
when discussing security properties, and document both what the system does and
does not guarantee.
