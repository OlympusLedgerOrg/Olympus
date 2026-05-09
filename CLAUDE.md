# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Quality gate (lint + type-check + tests + coverage ≥85%)
make check

# Individual checks
make lint              # ruff + mypy + bandit
make format            # ruff auto-fix
make smoke             # PostgreSQL-backed integration smoke tests
make pre-push          # Fast local CI gate (run before pushing)
make vectors           # Verify golden test vectors
make mutation-test     # Mutation testing on crypto modules
make fuzz-smoke        # Hypothesis fuzzing (<3 min)

# Dev server
make dev               # FastAPI on :8000

# Tests
pytest tests/ -v                                          # All tests
pytest tests/ -v -m "not postgres"                       # Skip DB-required tests
pytest tests/test_file.py::test_name -v                  # Single test
pytest tests/ -v --cov=protocol --cov=storage --cov=api  # With coverage

# Rust extension
maturin develop                                           # Build olympus_core PyO3 extension

# Database
python -m alembic upgrade head                            # Apply migrations
docker compose up -d                                      # Start full local stack (PostgreSQL on :5432)
```

## Architecture

### Language Ownership — Hard Boundaries

```
Python  → API, policy, orchestration, ALL database operations
Rust    → Cryptographic hot path: BLAKE3, Ed25519, Poseidon, SMT, canonicalization (olympus_core PyO3 extension)
Go      → Trillian-shaped log sequencer — client of Rust, never computes Merkle hashes itself
```

These boundaries are enforced by `tools/check_import_boundaries.py` (run in pre-commit). Violations are blocking.

### Deployment Phases

- **Phase 0 (current)**: Python FastAPI → `storage/postgres.py` → PostgreSQL directly
- **Phase 1 (target)**: Python FastAPI → Go sequencer (`services/sequencer-go/`) → Rust SMT service (`services/cdhs-smf-rust/`) → PostgreSQL

### Protocol Layer (`protocol/`)

The source of truth for all cryptographic logic. Python calls Rust via PyO3 (`olympus_core`); if `OLYMPUS_REQUIRE_RUST=1` and the extension fails to load, the process **must hard-fail** — no silent fallback to Python crypto.

Key files:
- `protocol/hashes.py` — BLAKE3 domain-separated hashing; all leaf/node hashes use `OLY:LEAF:V1|` / `OLY:NODE:V1|` prefixes with **pipe** separators (not colons)
- `protocol/canonical.py` — JCS/RFC 8785 canonical JSON; never use `ensure_ascii=True` or bare `json.dumps`
- `protocol/merkle.py` — SMT inclusion/non-inclusion proofs
- `protocol/checkpoints.py` — Checkpoint serialization and Ed25519-signed roots

### Storage Layer (`storage/`)

`storage/postgres.py` is the single entry point for all DB operations (~119KB). The SMT is a 256-level global sparse Merkle tree; incremental proof generation reads `smt_nodes` (not full leaf scan). Migrations live in `alembic/versions/`.

### API Layer (`api/`)

FastAPI with lifespan startup in `api/main.py`. Auth via `api/auth.py` (API key validation + rate limiting). Routers under `api/routers/` map to: agencies, appeals, documents, datasets, ledger, shards, federation, keys, witness, public_stats, user_auth, admin.

The `/oracle/refine` and `/oracle/appeal` endpoints call the Anthropic API — requires `ANTHROPIC_API_KEY`.

### ZK Proof Layer (`proofs/`)

Circom circuits for document existence, non-existence, redaction validity, and inclusion. Python calls snarkjs via `proofs/snarkjs_bridge.py`. Verification keys in `proofs/keys/verification_keys/`.

### Frontend (`app/public-ui/`)

React + TypeScript + Vite + Tailwind + React Query. API client in `app/public-ui/src/lib/api.ts`.

### Cross-Language Verifiers (`verifiers/`)

Reference implementations in Python, Go, Rust, and JavaScript — used for differential fuzzing and offline proof verification. Test vectors in `verifiers/test_vectors/vectors.json`.

## Critical Invariants

- **Domain prefixes**: All leaf/node hashes must use `OLY:LEAF:V1|` / `OLY:NODE:V1|`. Both `olympus_core` (PyO3) and `cdhs-smf-rust` share these prefixes via the `crates/olympus-crypto` crate. Global SMT keys use `BLAKE3.derive_key("olympus 2025-12 global-smt-leaf-key", ...)` with length-prefixed inputs — not a raw prefix tag.
- **Ed25519 signing keys must be persisted** — ephemeral keys make historical signed roots unverifiable. Any code generating an Ed25519 keypair needs a persistence strategy.
- **Canonical JSON**: Always JCS/RFC 8785 raw UTF-8. Never `json.dumps` without JCS normalization.
- **Go sequencer batch inserts**: All 256 delta inserts for a batch must happen inside a single outer DB transaction.
- **`datetime.timezone.utc`** not `datetime.UTC` — Python 3.10 compatibility required.
- **Demo API keys are rejected** by pre-commit hook (`tools/check_demo_keys.py`).
- Coverage minimum is **85%** on `protocol/`, `storage/`, `api/`.

## Environment

Key `.env` variables:
- `DATABASE_URL` / `PSYCOPG_URL` — async/sync PostgreSQL connection strings
- `OLYMPUS_API_KEYS_JSON` — JSON array of `{key_hash, key_id, scopes, expires_at}`
- `OLYMPUS_INGEST_SIGNING_KEY` — persistent Ed25519 key (production); use `OLYMPUS_DEV_SIGNING_KEY` for dev auto-generation
- `OLYMPUS_REQUIRE_RUST=1` — hard-fail if `olympus_core` extension unavailable
- `OLYMPUS_USE_GO_SEQUENCER=true` — route through Go sequencer
- `CORS_ORIGINS` — explicit comma-separated origins (no wildcards)
- `RATE_LIMIT_BACKEND` — `"memory"` or `"redis"`

## Test Markers

`postgres`, `smoke`, `slow`, `layer4` (ZK circuits), `fuzz`, `security`, `differential` (cross-implementation), `api`, `storage`, `xdist_group`
