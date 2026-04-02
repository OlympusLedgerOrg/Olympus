# Olympus

**Olympus is a verifiable ledger for sensitive information.**

It turns institutional data, compliance actions, and oversight decisions into **cryptographically provable facts**—not dashboards, not trust-me PDFs, not promises.

At its core, Olympus answers one question with mathematical certainty:

> **"Can any party independently verify that this record existed at a specific time, hasn't been altered, and is part of the official state?"**

The answer is **yes**, offline, forever.

The repository is in a protocol-hardening phase: deterministic canonicalization, Merkle commitments, verifiable proofs, and developer tooling for inspecting and validating those primitives.

## Start here

| I am a... | Start with |
|---|---|
| **Security auditor** | [`threat-model.md`](threat-model.md) → [`storage/postgres.py`](storage/postgres.py) → [`protocol/`](protocol/) |
| **New contributor** | [`QUICKSTART.md`](QUICKSTART.md) → [`DEVELOPMENT.md`](DEVELOPMENT.md) → [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| **Integrator / API user** | [`api/routers/`](api/routers/) → [`schemas/`](schemas/) → [`tools/verify_cli.py`](tools/verify_cli.py) |
| **Operator / deployer** | [`QUICKSTART.md`](QUICKSTART.md) → [`docs/`](docs/) → [`alembic/`](alembic/) |
| **ZK / circuit reviewer** | [`proofs/circuits/`](proofs/circuits/) → [`ceremony/`](ceremony/) → [`api/services/zkproof.py`](api/services/zkproof.py) |

## Licensing

Olympus is licensed under **Apache License 2.0**.

All components are open source: protocol implementations (`protocol/`), ZK circuits (`proofs/`), storage layer (`storage/`), API gateway (`api/`), debug UI (`ui/`), schemas (`schemas/`), verification tools (`verifiers/`), CLI tools (`tools/`), and examples (`examples/`, `test_vectors/`).

**Why Apache 2.0?** Strong patent protection, enterprise-friendly, and protects cryptographic IP from patent trolls.

## Trust & Threat Model (60-second summary)

- **Adversaries:** malicious submitters, compromised operators, and network attackers who can observe and modify traffic but cannot break modern cryptography.
- **What we defend:** append-only ledger integrity (BLAKE3 CD-HS-ST + shard headers), verifiable provenance, and non-malleable redaction proofs (Poseidon + Groth16).
- **What we do not promise:** availability under single-operator failure (Guardian replication is Phase 1+), confidentiality of submitted content, or completeness of all possible records.
- **Why it holds:** dual-root commitments bind BLAKE3 ledger roots to Poseidon circuit roots; deterministic canonicalization removes parser ambiguity; shard headers are Ed25519-signed and RFC 3161 timestamp-tokened; verification bundles allow offline re-validation.
- See [`threat-model.md`](threat-model.md) for the full threat/assurance boundaries.

## The Vision

A layered cryptographic infrastructure for real-world applications that require:

- **Legal/regulatory compliance** — immutable, independently auditable records for institutional documents, court records, and regulatory filings.
- **Auditable data provenance** — end-to-end verifiable data lineage for supply chains, financial audits, and any domain where chain-of-custody matters.
- **Privacy with accountability** — selective redaction capabilities (GDPR-compatible) that preserve cryptographic proofs of what was disclosed and what was withheld.
- **Cross-institutional consensus** — a federation of independent trusted parties that reaches quorum without requiring trust in any single institution. *(Basic federation quorum signing is prototyped in v1.0; full Guardian multi-node replication is a Phase 1+ roadmap item.)*

## Technical Architecture

### CD-HS-ST: Constant-Depth Hierarchical Sparse Tree

Olympus is built on the **CD-HS-ST** — a single global 256-level Sparse Merkle Tree where shard identity is encoded directly into the leaf key rather than maintained as a separate per-shard tree.

```
key = H(GLOBAL_KEY_PREFIX || shard_id || record_key)
```

where `record_key = H(KEY_PREFIX || len(type) || type || len(id) || id || version)`.

Both inputs are **length-prefixed** before hashing to prevent field-boundary collisions between `shard_id` and `record_key`. This replaces the earlier two-tree model (per-shard SMT + forest SMT), which had TOCTOU and consistency hazards.

### Service Layers

Olympus has three service layers with strict responsibility boundaries:

```
+---------------------------------------------------+
|  Python FastAPI  (api/)                           |
|  - FOIA, dataset, and public-records endpoints    |
|  - Metadata, policy, and orchestration            |
+-------------------+-------------------------------+
                    | HTTP / gRPC
                    v
+---------------------------------------------------+
|  Go Sequencer  (services/sequencer-go/)              |
|  - Trillian-shaped log API                        |
|  - QueueLeaf, GetLatestRoot, GetInclusionProof    |
|  - Postgres persistence for SMT node deltas       |
+-------------------+-------------------------------+
                    | Protobuf over gRPC
                    v
+---------------------------------------------------+
|  Rust CD-HS-ST Service (services/cdhs-smf-rust/) |
|  - BLAKE3 hashing (domain-separated)              |
|  - Composite key generation (length-prefixed)     |
|  - SMT insert / inclusion-proof / non-membership  |
|  - Ed25519 root signing                           |
|  - Deterministic canonicalization                 |
+---------------------------------------------------+
```

> **Go never computes Merkle hashes itself.** All SMT operations are delegated to the Rust service over protobuf. Python talks to Go/Rust as external services, never as libraries.

### Pipeline

```text
Ingest -> Canonicalize -> Hash -> Commit -> Prove -> Verify
                                                ^
                            (Replicate -- Phase 1+, not yet live)
```

All stages are independently verifiable. The canonicalization version is currently **`canonical_v2`** (see [`CHANGELOG.md`](CHANGELOG.md)).

### Cryptographic Primitives

| Primitive | Where used |
|-----------|-----------|
| BLAKE3 (domain-separated) | All ledger hashing, CD-HS-ST leaf/node hashes, global keys |
| Ed25519 (PyNaCl / ed25519-dalek) | Shard header signing, federation votes |
| Poseidon (BN128) | ZK circuit commitments only (separate from BLAKE3 ledger layer) |
| Groth16 (snarkjs / Circom) | ZK proofs: document existence, redaction validity, non-existence |
| RFC 3161 | External timestamp tokens anchoring shard headers |

## Technology Stack

| Layer | Technology |
|-------|-----------|
| **Python API** | FastAPI 0.135, SQLAlchemy 2 async, psycopg 3, Pydantic v2, Uvicorn |
| **Go sequencer** | Go 1.24, gRPC (google.golang.org/grpc v1.79), lib/pq |
| **Rust crypto core** | Rust 2021 edition, blake3 1.5, ed25519-dalek 2.1, tonic 0.10 (gRPC), pyo3 0.24 |
| **ZK circuits** | Circom, snarkjs, circomlib (Poseidon); Halo2 gated behind `OLYMPUS_HALO2_ENABLED` |
| **Database** | PostgreSQL 16 with Alembic migrations |
| **Quality tooling** | Ruff, mypy, Bandit, pytest (>=85% coverage floor), Hypothesis, pip-audit |
| **CI** | GitHub Actions: lint, typecheck, unit, smoke, verifier-conformance, CodeQL, dependency-lock |
| **Wire format** | Protobuf between Go <-> Rust (`proto/cdhs_smf.proto`, `proto/olympus.proto`) |

Python version: **>=3.10** (3.12 used for CI tooling and dependency locking).

## Current Repository State

The repository is at **Phase 0** (pre-public protocol hardening). The three phase-0 blockers are:

1. **Groth16 trusted setup ceremony** — ceremony infrastructure lives in `ceremony/`; the production ceremony is an external dependency.
2. **Federation decomposition** — in progress; `protocol/federation/` now splits gossip, identity, quorum, replication, and rotation into focused modules.
3. **E2E CI integration test against real PostgreSQL** — covered by the `smoke` workflow and `pytest -m postgres`.

**Phase 1** (greenfield, no migration) services are underway:
- Go sequencer: `services/sequencer-go/` and `go/sequencer/`
- Rust CD-HS-ST service: `services/cdhs-smf-rust/`
- Shared protobuf definitions: `proto/`

> **What is live vs in progress**
>
> **Working now:** Python API, PostgreSQL storage, BLAKE3 CD-HS-ST,
> Ed25519 signing, RFC 3161 timestamps, cross-language verifiers,
> arkworks BN254 Groth16 verifier (native Rust).
>
> **In progress:** Go sequencer → Rust service integration (proto wired,
> hardened, not yet primary write path). Federation multi-node replication
> (quorum signing prototyped, Guardian replication Phase 1+).
>
> **External dependency:** Groth16 trusted setup ceremony (required before
> ZK proofs are production-valid). See [`ceremony/`](ceremony/).

### Developer Workflows

```bash
python -m pip install -e ".[dev]"   # install package + dev tooling
make help                            # list all make targets
make check                           # Ruff + mypy + Bandit + full test suite (>=85% coverage)
make lint                            # Ruff + mypy + Bandit, no tests
make format                          # auto-format with Ruff
make vectors                         # verify golden canonicalization + hash vectors
make boundary-check                  # verify protocol import boundaries are intact
make smoke                           # PostgreSQL-backed smoke test (requires Docker Compose)
make dev                             # FastAPI on :8000 + debug UI on :8080
make federation-dev                  # three-node local federation via Docker Compose
```

## Repository Layout

```text
api/             FastAPI application -- FOIA, dataset, ledger, and document endpoints
alembic/         Database migration scripts (Alembic)
app/             Application utility module
assets/          Static assets
benchmarks/      Performance benchmarks (Merkle proofs, ZK proofs, canonicalization)
ceremony/        Groth16 trusted setup ceremony infrastructure and transcripts
examples/        Sample artifacts, federation registry, and runnable demos
go/              Go sequencer module (go/sequencer/)
integrations/    Lightweight Ethereum and IPFS bridge helpers
proofs/          Circom ZK circuits (document_existence, redaction_validity,
                   non_existence), proving keys, and proof-generation tooling
proto/           Protobuf definitions shared between Go and Rust services
                   (cdhs_smf.proto, olympus.proto)
protocol/        Python reference implementations -- hashing, CD-HS-ST,
                   canonicalization, Merkle trees, ledger, redaction, federation,
                   attestations, checkpoints, RFC 3161
scaffolding/     Non-production test wiring and view-change scaffolding
schemas/         JSON schema definitions validated by tools/validate_schemas.py
scripts/         Utility scripts
services/        Microservices:
                   cdhs-smf-rust/  -- Rust gRPC CD-HS-ST cryptographic core
                   sequencer-go/   -- Go gRPC log sequencer
src/             Rust PyO3 extension (olympus-core) -- accelerated hashing and
                   canonicalization callable from Python
storage/         PostgreSQL persistence layer and schema bootstrap
test_vectors/    Golden test vectors for cross-language determinism harness
tests/           Python test suite (unit, integration, postgres, adversarial, chaos)
tools/           CLI helpers: canonicalize_cli.py, verify_cli.py, olympus.py, etc.
ui/              FastAPI debug console and public verification portal
verifiers/       Cross-language verifiers -- Python, Go, Rust, JavaScript
```

## Quick Start

```bash
git clone https://github.com/wombatvagina69-crypto/Olympus.git
cd Olympus
python -m pip install -e ".[dev]"
```

### Quality gate

```bash
make check
```

### Smoke test (requires Docker / Docker Compose)

```bash
make smoke
```

### Run the API + debug UI locally

```bash
docker compose up -d                   # start PostgreSQL + Traefik
export DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
export TEST_DATABASE_URL="$DATABASE_URL"
python -m alembic upgrade head         # apply database migrations
make dev                               # API on :8000, debug UI on :8080
```

See [`QUICKSTART.md`](QUICKSTART.md) for a step-by-step walkthrough and [`DEVELOPMENT.md`](DEVELOPMENT.md) for the full developer workflow.

## Federation Architecture

Olympus operates as a federated transparency log. Multiple independent nodes maintain shard state and sign shard headers so no single node can rewrite history once a federation quorum has acknowledged a header.

Components in this repository:

- `protocol/federation/` — node identity and registry (`identity.py`), quorum signing (`quorum.py`), gossip and VRF committee selection (`gossip.py`), state replication (`replication.py`), key rotation (`rotation.py`)
- `examples/federation_registry.json` — static federation membership for local development and tests
- `docker-compose.federation.yml` and `make federation-dev` — local three-node federation simulation

Useful prototype commands:

```bash
python tools/olympus.py node list
python tools/olympus.py federation status
python tools/olympus.py ingest examples/pipeline_golden_example.json \
  --api-key demo-key --generate-proof --verify --json
make federation-dev
bash examples/run_local_testnet_demo.sh
```

Olympus is influenced by the operational model of Certificate Transparency and Sigstore: transparency logs, multiple operators, and independent verification.

## Key Developer Entrypoints

| What | Where |
|------|-------|
| Python API application | `api/app.py` |
| Debug UI / verification portal | `ui/app.py` |
| Rust CD-HS-ST service | `services/cdhs-smf-rust/src/main.rs` |
| Go sequencer service | `services/sequencer-go/` |
| Protobuf definitions | `proto/cdhs_smf.proto`, `proto/olympus.proto` |
| Services architecture | `services/README.md` |
| Canonicalization + verification CLIs | `tools/canonicalize_cli.py`, `tools/verify_cli.py`, `tools/olympus.py` |
| ZK proof setup and circuits | `proofs/README.md`, `proofs/circuits/` |
| Runnable demos | `examples/README.md` |
| Interoperability helpers | `integrations/README.md` |
| Extended setup guide | [`QUICKSTART.md`](QUICKSTART.md) |
| Full developer workflow | [`DEVELOPMENT.md`](DEVELOPMENT.md) |
| Governance & sustainability | [`GOVERNANCE.md`](GOVERNANCE.md) |
| Contribution workflow | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Architecture & structural decisions | [`ARCHITECTURE.md`](ARCHITECTURE.md) |

## Notes

- Python requirement: `>=3.10` (3.12 is used for CI tooling and dependency locking).
- The debug console is disabled by default; set `OLYMPUS_DEBUG_UI=true` when running the UI directly.
- The public verification portal is always available at `/verification-portal` even when debug-only routes are disabled.
- `canonical_v2` is the current canonicalization version. `canonical_v1` remains in `SUPPORTED_VERSIONS` with a deprecation warning.
- The Rust PyO3 extension (`src/`, built with `maturin`) accelerates hashing and canonicalization. It is optional; the pure-Python fallback in `protocol/hashes.py` is always active when the extension is not built.
- The Halo2 ZK backend is gated behind `OLYMPUS_HALO2_ENABLED` and is not yet production-ready.

## External Security Review

Olympus is designed to be audit-friendly, and external review is encouraged:

- Security policy and coordinated disclosure: [`SECURITY.md`](SECURITY.md)
- Threat model for auditors and policymakers: [`threat-model.md`](threat-model.md)
