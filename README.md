# Olympus

When a document gets leaked, altered, or denied — there's usually no way to prove what it originally said, when it existed, or whether it's been tampered with.

Olympus fixes that.

It's a tool for organizations that handle sensitive records — journalists, lawyers, oversight bodies, human rights investigators — that need to prove a document is real, unaltered, and existed at a specific point in time. Not because someone says so. Because the math says so.

No server to trust. No company to subpoena. No way to quietly alter the record after the fact. Your documents never leave your computer — only a cryptographic proof is published, and that proof can't be reverse-engineered back into the original document. And if you want to go further, you can run your own node and become part of the network that makes the whole system trustworthy.

You don't have to trust us. You can be us.

---

## How Olympus is different

There are other tools that solve pieces of this problem. None solve all of it.

| Tool | What it does | What it doesn't do |
|------|-------------|-------------------|
| **SecureDrop** | Anonymously receives leaked documents | Doesn't prove authenticity, timing, or whether a document was altered |
| **OpenTimestamps** | Proves a document existed at a point in time via Bitcoin | No redaction, no inclusion proof, no federation, no offline verification |
| **Sigstore / Rekor** | Public transparency log for software | Built for code, not documents; no ZK redaction; requires network access |
| **C2PA** | Certifies photos and media at the moment of capture | Requires signing at creation time; doesn't work on existing documents |
| **Arweave / Filecoin** | Stores documents on a decentralized network | Trust depends on the chain; not offline-verifiable; not redaction-aware |

Olympus does the whole chain: prove a document existed, prove it hasn't been altered, prove that anything redacted was redacted honestly — and do all of that offline, without trusting any single organization, in a format a court can verify years later.

Notably, Olympus actually uses OpenTimestamps and Sigstore Rekor as anchoring layers — so you get Bitcoin-level timestamping and public transparency logging inside the stronger proof system, not instead of it.

---

## Who it's for

| I am a... | Start with |
|-----------|-----------|
| Journalist or investigator | [`docs/court-evidence.md`](docs/court-evidence.md) |
| Lawyer or expert witness | [`docs/court-evidence.md`](docs/court-evidence.md) → [`verifiers/`](verifiers/) |
| Grant reviewer / outside evaluator | [`GRANTS.md`](GRANTS.md) → [`DEMO.md`](DEMO.md) |
| Security auditor | [`docs/SECURITY_AUDIT_REPORT_V5.md`](docs/SECURITY_AUDIT_REPORT_V5.md) → [`docs/threat-model.md`](docs/threat-model.md) |
| Developer or contributor | [`docs/quickstart.md`](docs/quickstart.md) → [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| ZK / circuit reviewer | [`proofs/circuits/`](proofs/circuits/) → [`src-tauri/src/zk/`](src-tauri/src/zk/) |

---

## What it does, in plain language

- **Proves a document existed** at a specific moment in time — anchored to Bitcoin, a public transparency log, and accredited timestamps simultaneously
- **Proves it hasn't been altered** — any change, no matter how small, produces a different cryptographic proof
- **Proves redactions were honest** — if sensitive information is removed before sharing, Olympus proves what was removed without revealing it
- **Your documents never leave your computer** — Olympus only publishes a cryptographic proof. That proof confirms the document existed and hasn't changed. The document itself stays with you. Nobody — not Olympus, not a server, not a network — ever sees it
- **Runs on your machine** — no external server, no cloud dependency, no single organization that can be pressured or subpoenaed
- **Works offline** — verification bundles can be checked by anyone, anywhere, without an internet connection
- **You can be part of the trust network** — anyone can run an Olympus node. The more independent nodes that exist, the harder it is for any single government, company, or bad actor to pressure the system. You don't have to trust us. You can be us.
- **Built for court** — see [`docs/court-evidence.md`](docs/court-evidence.md)

---

## Current status

Olympus is in active development at v0.10. The core ledger, cryptographic proofs, and desktop application are live. The remaining pre-launch milestone is a multi-contributor cryptographic ceremony that eliminates the last single point of trust. See [`ROADMAP.md`](ROADMAP.md).

---

## Trust & threat model

Olympus is honest about what it protects and what it doesn't.

It defends against: malicious record alteration, tampered timestamps, and operators who can't be fully trusted.

It does not promise: that all relevant records were submitted, that submitted content is confidential, or that the system remains available if the operator goes offline.

Full details: [`docs/threat-model.md`](docs/threat-model.md)

---

## Licensing

Apache 2.0. Everything is open source — the protocol, the cryptographic circuits, the storage layer, the verification tools, and the desktop application. See [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).

---

*Everything below this line is the technical documentation for developers, auditors, and contributors.*

---

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
|  - sqlx migrations (migrations/)                  |
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
| Groth16 (native Rust / arkworks 0.6) | ZK proofs: `document_existence`, `non_existence`, `unified_canonicalization_inclusion_root_sign`, `federation_quorum` |
| Tor (arti-client 0.31) | Federation hidden services + peer checkpoint gossip (optional `federation` feature) |
| RFC 3161 | Accredited TSA receipts on every checkpoint (`anchoring/rfc3161.rs`) |
| Sigstore Rekor | Append-only public transparency log entry per checkpoint (`anchoring/rekor.rs`) |
| OpenTimestamps + Bitcoin | Bitcoin-anchored receipts upgradeable from pending → full block-header path (`anchoring/ots.rs`) |

## Technology Stack

| Layer | Technology |
|-------|-----------|
| **Desktop shell** | Tauri 2 |
| **Backend / API** | Axum (Rust), tokio async runtime |
| **Storage** | pg_embed (embedded PostgreSQL), sqlx with compile-time queries |
| **Cryptography** | `crates/olympus-crypto`: BLAKE3, Ed25519, Poseidon BN254, Baby Jubjub, Groth16 (arkworks 0.6) |
| **ZK circuits** | Circom, circomlib (Poseidon); native Rust Groth16 prover |
| **Frontend** | React 19, TypeScript, Vite, Tailwind CSS, TanStack Query |
| **Quality tooling** | `cargo test`, `cargo clippy`, `cargo fmt`; frontend ESLint + TypeScript |

## Quick Start

Cross-platform (Linux / macOS / WSL Ubuntu):

```bash
git clone https://github.com/OlympusLedgerOrg/Olympus.git
cd Olympus
pnpm install          # frontend deps
cargo tauri dev       # starts embedded DB, Axum server, and Vite UI
```

No external PostgreSQL, Python, or Go installation required for the base app.

For the in-process ZK prover (`/zk/prove` returning real proofs), see [Groth16 trusted setup](#groth16-trusted-setup) below.

### Build desktop app

```bash
cargo tauri build
```

### Run frontend standalone

```bash
cd app/public-ui
pnpm dev
```

### Run Rust tests

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

### Groth16 trusted setup

Two scripts, sharing the same Phase 1 input (`proofs/keys/powersOfTau28_hez_final_20.ptau`):

- **`proofs/setup_circuits.sh`** — fast all-in-one path for development. Single dev Phase 2 contribution per circuit + automatic `export_ark_zkey` conversion to the runtime `.ark.zkey` format. Not production-safe (single contributor).
- **`proofs/phase2_ceremony.sh prepare | contribute | verify | finalize`** — multi-contributor Phase 2 ceremony for v1.0 releases. Each contributor adds independent entropy on their own machine; the coordinator verifies the chain and finalizes with an optional public-randomness beacon.

The Hermez Phase 1 file is checksum-verified (BLAKE2b `89a66eb5…`) on every run; you can either let the script download it or drop your own copy at `proofs/keys/powersOfTau28_hez_final_20.ptau` first.

Under `OLYMPUS_ENV=production` the binary refuses to start if any circuit artifact is a `PLACEHOLDER` (i.e. the setup hasn't been run). See [`proofs/README.md`](proofs/README.md) for the full pipeline.

## Repository Layout

```text
src-tauri/                       Tauri + Axum backend (Rust)
  src/
    main.rs                      Tauri entry point, proofs_dir resolution, IPC commands
    bootstrap.rs                 Bootstrap admin API key + BJJ authority key
    db.rs                        pg_embed + connect_external (with migrations)
    server/                      Axum router setup
    api/                         HTTP route handlers
      ingest.rs, ledger.rs, redaction.rs, admin.rs, keys.rs
      user_auth.rs, credentials.rs
      zk.rs                      /zk/verify, /zk/prove (scope-gated)
      middleware/auth.rs         API key + rate limit extractors
    routes/                      Additional Axum routes
      public_stats.rs            Public ledger statistics
    zk/                          Native Rust Groth16 prover + verifier
      prove.rs, verify.rs, vkey.rs, zkey.rs, poseidon.rs
      witness/                   Per-circuit witness assembly + BJJ EdDSA
    federation/                  Tor hidden service, peer mgmt, checkpoint gossip
      api.rs, peer.rs, checkpoint.rs, equivocation.rs, gossip.rs
    anchoring/                   RFC 3161 / Sigstore Rekor / OpenTimestamps
      rfc3161.rs, rekor.rs, ots.rs, store.rs, api.rs
    bin/export_ark_zkey.rs       snarkjs .zkey → arkworks .ark.zkey converter
    state.rs                     AppState (pool, BJJ key, proofs_dir, anchoring …)
  build.rs                       Tauri build + ZK artifact placeholder shim
  tauri.conf.json                Bundle config (resources include proofs/keys/*)
  migrations/                    sqlx migration files (applied at startup)
app/public-ui/                   React + TypeScript + Vite frontend
crates/
  olympus-crypto/                Protocol-critical hash/key primitives (BLAKE3, Poseidon, SMT)
  light-poseidon/                Vendored Light Protocol Poseidon, ark-* 0.6 compatible
proofs/                          Circom circuits + Groth16 tooling
  circuits/                      4 circuits: document_existence, non_existence,
                                 unified_canonicalization_inclusion_root_sign,
                                 federation_quorum
  setup_circuits.sh              Dev: PTAU → compile → Phase 2 → vkey → .ark.zkey
  phase2_ceremony.sh             Production: multi-contributor Phase 2 orchestration
  keys/verification_keys/        Committed Groth16 vkey JSONs
schemas/                         JSON schema definitions
verifiers/                       Cross-language verifiers (Rust, JavaScript)
test_vectors/                    Golden test vectors for cross-language determinism
docs/                            Architecture, threat model, security audits, ADRs
```

## Current Repository State

**Current phase:** v0.10 — Tauri 2 desktop application with embedded Axum server and pg_embed storage. The app is self-contained — no external services required to run the base node.

**What is live:**
- Tauri 2 desktop shell with React frontend
- Axum HTTP server (ingest, ledger, redaction, admin, auth, federation, ZK, anchoring routes)
- Embedded PostgreSQL via pg_embed + sqlx migrations (also runs migrations against external `DATABASE_URL`)
- BLAKE3 CD-HS-ST sparse Merkle tree
- Ed25519 root signing (persistent authority key)
- Native Rust Groth16 prover + verifier (arkworks 0.6, Baby Jubjub + Poseidon BN254)
- `/zk/prove` and `/zk/verify` HTTP endpoints (scope-gated via API key)
- Federation feature (`--features federation`): Tor hidden service, peer trust management, checkpoint gossip, equivocation detection
- **External anchoring** (RFC 3161 / Sigstore Rekor / OpenTimestamps): every checkpoint can be co-signed by an accredited TSA, registered in a public transparency log, and committed to Bitcoin via OTS — giving outside parties (courts, auditors, journalists) verification paths that don't require trusting the Olympus federation. See [`docs/court-evidence.md`](docs/court-evidence.md).

**External dependency (one-time):** Groth16 trusted setup. Two paths:
- **Dev/single-contributor** — `bash proofs/setup_circuits.sh` (acceptable pre-v1.0, not for v1.0)
- **Multi-contributor ceremony** — `bash proofs/phase2_ceremony.sh {prepare|contribute|verify|finalize}` (required before tagging v1.0)

Under `OLYMPUS_ENV=production` the binary refuses to start if any circuit artifact is a build-time placeholder.

## Key Developer Entrypoints

| What | Where |
|------|-------|
| Tauri entry point | `src-tauri/src/main.rs` |
| Axum server / router | `src-tauri/src/server/mod.rs` |
| ZK proof generation | `src-tauri/src/zk/` |
| Shared crypto crate | `crates/olympus-crypto/` |
| Frontend API client | `app/public-ui/src/lib/api.ts` |
| sqlx migrations | `migrations/` |
| ZK circuits | `proofs/circuits/` |
| Verifiers | `verifiers/` |
| Security audit | [`docs/SECURITY_AUDIT_REPORT_V5.md`](docs/SECURITY_AUDIT_REPORT_V5.md) |
| Threat model | [`docs/threat-model.md`](docs/threat-model.md) |
| Architecture decisions | [`docs/architecture.md`](docs/architecture.md) |

## External Security Review

Olympus is designed to be audit-friendly, and external review is encouraged:

- Security policy and coordinated disclosure: [`SECURITY.md`](SECURITY.md)
- Threat model for auditors and policymakers: [`docs/threat-model.md`](docs/threat-model.md)
- Latest security audit report (June 2026 - V5): [`docs/SECURITY_AUDIT_REPORT_V5.md`](docs/SECURITY_AUDIT_REPORT_V5.md)
- Prior audit rounds (archived): [`V1`](docs/audits/archive/SECURITY_AUDIT_REPORT.md), [`V2`](docs/audits/archive/SECURITY_AUDIT_REPORT_V2.md), [`V3`](docs/audits/archive/SECURITY_AUDIT_REPORT_V3.md), [`V4`](docs/audits/archive/SECURITY_AUDIT_REPORT_V4.md)

## Community & Governance

Olympus is open to contributors and is actively growing its maintainer pool.

| Topic | Document |
|-------|----------|
| How to contribute (DCO sign-off) | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Expected behavior & enforcement | [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) |
| Who maintains what & the contributor ladder | [`MAINTAINERS.md`](MAINTAINERS.md) |
| How decisions are made, voted, and released | [`docs/governance.md`](docs/governance.md) |
| Proposing substantial changes | [`docs/rfcs/README.md`](docs/rfcs/README.md) |
| Where the project is headed | [`ROADMAP.md`](ROADMAP.md) |
| Reporting a vulnerability | [`SECURITY.md`](SECURITY.md) |

Interested in a maintainer role? See
[Becoming a maintainer](MAINTAINERS.md#becoming-a-maintainer).
