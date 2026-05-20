# Olympus

**Olympus is a verifiable ledger for sensitive information.**

It turns institutional data, compliance actions, and oversight decisions into **cryptographically provable facts**—not dashboards, not trust-me PDFs, not promises.

At its core, Olympus answers one question with mathematical certainty:

> **"Can any party independently verify that this record existed at a specific time, hasn't been altered, and is part of the official state?"**

The answer is **yes** — independently and offline.

## Start here

| I am a... | Start with |
|---|---|
| **Grant reviewer / outside evaluator** | [`GRANTS.md`](GRANTS.md) → [`DEMO.md`](DEMO.md) |
| **Security auditor** | [`docs/SECURITY_AUDIT_REPORT_V3.md`](docs/SECURITY_AUDIT_REPORT_V3.md) → [`docs/threat-model.md`](docs/threat-model.md) → [`src-tauri/src/`](src-tauri/src/) |
| **New contributor** | [`docs/quickstart.md`](docs/quickstart.md) → [`docs/development.md`](docs/development.md) → [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| **ZK / circuit reviewer** | [`proofs/circuits/`](proofs/circuits/) → [`src-tauri/src/zk/`](src-tauri/src/zk/) |

## Licensing

Olympus is licensed under **Apache License 2.0**.

All components are open source: protocol implementations, ZK circuits (`proofs/`), storage layer, schemas (`schemas/`), verification tools (`verifiers/`), and the desktop application.

**Why Apache 2.0?** Strong patent protection, enterprise-friendly, and protects cryptographic IP from patent trolls.

## Trust & Threat Model (60-second summary)

- **Adversaries:** malicious submitters, compromised operators, and network attackers who can observe and modify traffic but cannot break modern cryptography.
- **What we defend:** append-only ledger integrity (BLAKE3 CD-HS-ST + shard headers), verifiable provenance, and non-malleable redaction proofs (Poseidon + Groth16).
- **What we do not promise:** availability under single-operator failure, confidentiality of submitted content, or completeness of all possible records.
- **Why it holds:** dual-root commitments bind BLAKE3 ledger roots to Poseidon circuit roots; deterministic canonicalization removes parser ambiguity; shard headers are Ed25519-signed; verification bundles allow offline re-validation.
- See [`docs/threat-model.md`](docs/threat-model.md) for full threat/assurance boundaries.

## The Vision

A layered cryptographic infrastructure for real-world applications that require:

- **Legal/regulatory compliance** — immutable, independently auditable records for institutional documents, court records, and regulatory filings.
- **Auditable data provenance** — end-to-end verifiable data lineage for supply chains, financial audits, and any domain where chain-of-custody matters.
- **Privacy with accountability** — selective redaction capabilities (GDPR-compatible) that preserve cryptographic proofs of what was disclosed and what was withheld.
- **Cross-institutional consensus** — a federation of independent trusted parties that reaches quorum without requiring trust in any single institution.

## Technical Architecture

### CD-HS-ST: Constant-Depth Hierarchical Sparse Tree

Olympus is built on the **CD-HS-ST** — a single global 256-level Sparse Merkle Tree where shard identity is encoded directly into the leaf key rather than maintained as a separate per-shard tree.

```
key = H(GLOBAL_KEY_PREFIX || shard_id || record_key)
```

where `record_key = H(KEY_PREFIX || len(type) || type || len(id) || id || version)`.

Both inputs are **length-prefixed** before hashing to prevent field-boundary collisions. This replaces the earlier two-tree model (per-shard SMT + forest SMT), which had TOCTOU and consistency hazards.

### Service Architecture

```
+---------------------------------------------------+
|  Tauri 2 Desktop App                              |
|  - React + TypeScript + Vite frontend             |
|  - Native OS integration (file I/O, tray, etc.)  |
+-------------------+-------------------------------+
                    | Tauri commands / IPC
                    v
+---------------------------------------------------+
|  Axum HTTP Server (src-tauri/src/)                |
|  - Ingest, ledger, redaction, admin routes        |
|  - Auth middleware (API key validation)           |
|  - ZK proof generation (Baby Jubjub + Groth16)   |
+-------------------+-------------------------------+
                    | sqlx
                    v
+---------------------------------------------------+
|  pg_embed (embedded PostgreSQL)                   |
|  - No external database process required          |
|  - sqlx migrations (src-tauri/migrations/)        |
|  - Global 256-level SMT in smt_nodes table        |
+---------------------------------------------------+
```

### Pipeline

```text
Ingest -> Canonicalize -> Hash -> Commit -> Prove -> Verify
```

All stages are independently verifiable. The canonicalization version is currently **`canonical_v2`** (see [`CHANGELOG.md`](CHANGELOG.md)).

### Cryptographic Primitives

| Primitive | Where used |
|-----------|-----------|
| BLAKE3 (domain-separated) | All ledger hashing, CD-HS-ST leaf/node hashes, global keys |
| Ed25519 (ed25519-dalek) | Shard header signing, checkpoint roots |
| Baby Jubjub + Poseidon (BN254) | ZK circuit commitments and EdDSA signatures |
| Groth16 (native Rust / arkworks 0.5) | ZK proofs: document existence, redaction validity, non-existence |
| RFC 3161 | External timestamp tokens anchoring shard headers |

## Technology Stack

| Layer | Technology |
|-------|-----------|
| **Desktop shell** | Tauri 2 |
| **Backend / API** | Axum (Rust), tokio async runtime |
| **Storage** | pg_embed (embedded PostgreSQL), sqlx with compile-time queries |
| **Cryptography** | `crates/olympus-crypto`: BLAKE3, Ed25519, Poseidon BN254, Baby Jubjub, Groth16 (arkworks 0.5) |
| **ZK circuits** | Circom, circomlib (Poseidon); native Rust Groth16 prover |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, TanStack Query |
| **Quality tooling** | `cargo test`, `cargo clippy`, `cargo fmt`; frontend ESLint + TypeScript |

## Quick Start

```powershell
git clone https://github.com/OlympusLedgerOrg/Olympus.git
cd Olympus
pnpm install          # frontend deps
cargo tauri dev       # starts embedded DB, Axum server, and Vite UI
```

No external PostgreSQL, Python, or Go installation required.

### Build desktop app

```powershell
cargo tauri build
```

### Run frontend standalone

```powershell
cd app/public-ui
pnpm dev
```

### Run Rust tests

```powershell
cargo test
cargo clippy -- -D warnings
```

## Repository Layout

```text
src-tauri/           Tauri + Axum backend (Rust)
  src/
    main.rs          Tauri entry point, IPC command registration
    server.rs        Axum router setup
    auth.rs          API key middleware
    ingest.rs        Document ingest handlers
    ledger.rs        Ledger + merkle routes
    redaction.rs     Redaction link handlers
    admin.rs         Admin routes
    zk/              ZK proof generation (Baby Jubjub, Groth16)
  migrations/        sqlx migration files
app/public-ui/       React + TypeScript + Vite frontend
crates/              Shared Rust crates
  olympus-crypto/    Protocol-critical hash/key primitives (BLAKE3, Poseidon, SMT)
proofs/              Circom ZK circuits and proving keys
schemas/             JSON schema definitions
verifiers/           Cross-language verifiers (Rust, JavaScript)
test_vectors/        Golden test vectors for cross-language determinism
docs/                Architecture, threat model, security audits, ADRs
```

## Current Repository State

**Current phase:** Tauri 2 desktop application with embedded Axum server and pg_embed storage. The app is self-contained — no external services required to run.

**What is live:**
- Tauri 2 desktop shell with React frontend
- Axum HTTP server (ingest, ledger, redaction, admin, auth routes)
- Embedded PostgreSQL via pg_embed + sqlx migrations
- BLAKE3 CD-HS-ST sparse Merkle tree
- Ed25519 root signing
- Native Rust Groth16 prover (Baby Jubjub + Poseidon BN254)
- RFC 3161 timestamps

**External dependency:** Groth16 trusted setup ceremony (required before ZK proofs are production-valid). See [`ceremony/`](ceremony/).

## Key Developer Entrypoints

| What | Where |
|------|-------|
| Tauri entry point | `src-tauri/src/main.rs` |
| Axum server / router | `src-tauri/src/server.rs` |
| ZK proof generation | `src-tauri/src/zk/` |
| Shared crypto crate | `crates/olympus-crypto/` |
| Frontend API client | `app/public-ui/src/lib/api.ts` |
| sqlx migrations | `src-tauri/migrations/` |
| ZK circuits | `proofs/circuits/` |
| Verifiers | `verifiers/` |
| Security audit | [`docs/SECURITY_AUDIT_REPORT_V3.md`](docs/SECURITY_AUDIT_REPORT_V3.md) |
| Threat model | [`docs/threat-model.md`](docs/threat-model.md) |
| Architecture decisions | [`docs/architecture.md`](docs/architecture.md) |

## External Security Review

Olympus is designed to be audit-friendly, and external review is encouraged:

- Security policy and coordinated disclosure: [`SECURITY.md`](SECURITY.md)
- Threat model for auditors and policymakers: [`docs/threat-model.md`](docs/threat-model.md)
- Latest security audit report (May 2026 - V3): [`docs/SECURITY_AUDIT_REPORT_V3.md`](docs/SECURITY_AUDIT_REPORT_V3.md)
- Prior audit rounds: [`docs/SECURITY_AUDIT_REPORT.md`](docs/SECURITY_AUDIT_REPORT.md), [`docs/SECURITY_AUDIT_REPORT_V2.md`](docs/SECURITY_AUDIT_REPORT_V2.md)
