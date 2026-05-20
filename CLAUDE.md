# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Desktop app (primary)
cargo tauri dev                # Dev build with hot-reload frontend
cargo tauri build              # Production Tauri binary

# Rust
cargo check --workspace        # Fast type/lint check
cargo test --workspace         # All Rust unit tests
cargo clippy --workspace       # Lints

# Frontend
pnpm install                   # Install JS deps
pnpm --filter app/public-ui build   # Production frontend build
pnpm --filter app/public-ui dev     # Vite dev server

# Database migrations (sqlx, applied by Tauri on startup)
# Migration files live in migrations/ — sqlx applies them automatically

# Go sequencer
cd services/sequencer-go && go test ./...

# Verifiers
cd verifiers/go && go test ./...
cd verifiers/rust && cargo test
cd verifiers/javascript && npm test
```

## Architecture

### Language Ownership — Hard Boundaries

```
Rust    → Tauri app, Axum HTTP server, cryptographic hot path: BLAKE3, Ed25519, Poseidon, SMT,
          canonicalization, embedded PostgreSQL (pg_embed), all DB operations
Go      → Trillian-shaped log sequencer — client of Rust, never computes Merkle hashes itself
TypeScript → React frontend (app/public-ui/)
```

### Deployment

- **Desktop app (primary)**: Tauri 2 binary with embedded Axum HTTP server + pg_embed PostgreSQL. Double-click `start.bat` (Windows) or run `cargo tauri dev`. No Python or Docker required.

### Tauri App (`src-tauri/`)

Axum HTTP server embedded in the Tauri process. Handles all API requests. Runs pg_embed for an embedded PostgreSQL instance. sqlx migrations in `migrations/` are applied on startup.

Key files:
- `src-tauri/src/lib.rs` — Tauri app entry point, Axum router setup
- `src-tauri/src/api/` — Axum route handlers
- `src-tauri/Cargo.toml` — dependencies

### ZK Proof Layer (`proofs/`)

Circom circuits for document existence, non-existence, redaction validity, and inclusion. Verification keys in `proofs/keys/verification_keys/`.

### Frontend (`app/public-ui/`)

React + TypeScript + Vite + Tailwind + React Query. API client in `app/public-ui/src/lib/api.ts`.

### Cross-Language Verifiers (`verifiers/`)

Reference implementations in Python, Go, Rust, and JavaScript — used for differential fuzzing and offline proof verification. Test vectors in `verifiers/test_vectors/vectors.json`. The Python reference verifier lives in `verifiers/python/`.

## Critical Invariants

- **Domain prefixes**: All leaf/node hashes must use `OLY:LEAF:V1|` / `OLY:NODE:V1|`. Constants defined in `src/crypto.rs`.
- **Ed25519 signing keys must be persisted** — ephemeral keys make historical signed roots unverifiable.
- **Canonical JSON**: Always JCS/RFC 8785 raw UTF-8.
- **Go sequencer batch inserts**: All 256 delta inserts for a batch must happen inside a single outer DB transaction.

## Environment

Key `.env` variables:
- `OLYMPUS_API_PORT` — HTTP port for the embedded Axum server (default 3737)
- `OLYMPUS_INGEST_SIGNING_KEY` — persistent Ed25519 key (production); use `OLYMPUS_DEV_SIGNING_KEY` for dev auto-generation
- `CORS_ORIGINS` — explicit comma-separated origins (no wildcards)
