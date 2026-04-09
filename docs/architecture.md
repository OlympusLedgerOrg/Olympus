# Olympus Architecture

This is the single authoritative navigation reference for the Olympus
repository. It describes structural decisions, compilation targets, and
the relationship between current and target architectures.

For a 5-minute orientation see [`README.md`](README.md).

## The three Rust stories

There are three separate Rust compilation targets in this repository.
Each serves a distinct purpose and has its own build, dependency tree,
and deployment model.

### 1. `src/` — olympus-core PyO3 extension (cdylib)

Accelerates Python-side hashing, canonicalization, and Groth16
verification. Built with [maturin](https://github.com/PyO3/maturin) as
a native Python extension module.

**Optional at runtime.** A pure-Python fallback in `protocol/hashes.py`
is always available when the extension is not built. CI builds and tests
both code paths.

### 2. `services/cdhs-smf-rust/` — CD-HS-ST gRPC service

The Rust CD-HS-ST service owns all Sparse Merkle Tree operations:

- Composite key derivation (`H(GLOBAL_KEY_PREFIX || shard_id || record_key)`)
- BLAKE3 hashing with domain separation
- SMT insert, inclusion proof, and non-inclusion proof
- Ed25519 root signing
- Poseidon canonicalization for ZK witness generation

Speaks protobuf over gRPC to the Go sequencer. Defined by
[`proto/cdhs_smf.proto`](proto/cdhs_smf.proto).

### 3. `verifiers/rust/` — standalone cross-language verifier

No gRPC, no PyO3. A minimal binary that reads a verification bundle
(proof + root + public inputs) and exits 0/1. Used for conformance
testing and offline proof verification across language boundaries.

## Current vs target architecture

| | Current working system | Target architecture |
|---|---|---|
| **Entry point** | Python FastAPI (`api/`) | Python FastAPI (`api/`) |
| **Sequencing** | Python `storage/postgres.py` (direct SQL) | Go sequencer (`services/sequencer-go/`) |
| **Crypto core** | Python `protocol/` + optional Rust PyO3 | Rust gRPC service (`services/cdhs-smf-rust/`) |
| **Database** | PostgreSQL via psycopg 3 | PostgreSQL via psycopg 3 (same database) |
| **Wire format** | In-process function calls | Protobuf over gRPC (Go ↔ Rust) |

Both paths write to the **same PostgreSQL database**. The service split
is in progress, not complete. During Phase 1, the Python path remains
the primary write path while the Go → Rust path is hardened.

## Where things live

| Concern | Directory |
|---|---|
| Protocol truth (hashing, canonicalization, Merkle, ledger, federation) | [`protocol/`](../protocol/) |
| Current API (FastAPI endpoints, auth, schemas) | [`api/`](../api/) |
| Target services (Go sequencer, Rust CD-HS-ST) | [`services/`](../services/) |
| ZK proof system (Circom circuits, proving keys, ceremony) | [`proofs/`](../proofs/), [`ceremony/`](../ceremony/) |
| Independent verification (Python, Go, Rust, JavaScript verifiers) | [`verifiers/`](../verifiers/) |
| Operator tooling (CLI, schema validation, benchmarks) | [`tools/`](../tools/), [`schemas/`](../schemas/), [`benchmarks/`](../benchmarks/) |
| Assurance (tests, test vectors, threat model) | [`tests/`](../tests/), [`test_vectors/`](../test_vectors/), [`threat-model.md`](threat-model.md) |

## Document hierarchy

| Document | Purpose |
|---|---|
| [`README.md`](../README.md) | 5-minute orientation |
| [`quickstart.md`](quickstart.md) | Get running in 20 minutes |
| [`development.md`](development.md) | Day-to-day developer workflow |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Contribution process |
| `architecture.md` (this file) | Structural decisions and navigation |
| [`threat-model.md`](threat-model.md) | Security posture for auditors |
| [`adr/`](adr/) | Architectural Decision Records |

## Phase definitions

These definitions are the canonical source for phase references
scattered across other documents.

### Phase 0 — Pre-public blockers

Do not defer, do not refactor around. The three hard blockers for going
public:

1. **Groth16 trusted setup ceremony** — external dependency, not code.
   Infrastructure in [`ceremony/`](../ceremony/).
2. **Federation decomposition** — `protocol/federation/` now splits
   gossip, identity, quorum, replication, and rotation into focused
   modules.
3. **E2E CI integration test against real PostgreSQL** — covered by the
   `smoke` workflow and `pytest -m postgres`.

### Phase 1 — Greenfield (new code only, no migration)

- Go sequencer and witness transport layer (`services/sequencer-go/`)
- Rust standalone binary with protobuf socket API
  (`services/cdhs-smf-rust/`)
- `.proto` definitions shared between Go and Rust (`proto/`)

Phase 1 code is built as greenfield services alongside the existing
Python implementation. No migration of existing Python code is required.

### Phase 2 — Post-public migration (deferred)

- Moving existing Python SMT/ledger logic out of FastAPI handlers and
  into Go/Rust services
- Replacing any remaining Python canonicalization calls with Rust
  service calls
- Halo2 backend (currently gated behind `OLYMPUS_HALO2_ENABLED`; keep
  it gated until circuits are stable)
