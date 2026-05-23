# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Current version: **v0.9.1** (May 2026).

## Commands

```bash
# Desktop app (primary)
cargo tauri dev                # Dev build with hot-reload frontend
cargo tauri build              # Production Tauri binary + bundled installers

# Rust
cargo check --workspace        # Fast type/lint check
cargo test --workspace         # All Rust unit tests
cargo clippy --workspace       # Lints

# Frontend
pnpm install                   # Install JS deps
pnpm --filter app/public-ui build   # Production frontend build
pnpm --filter app/public-ui dev     # Vite dev server (standalone)

# Database migrations (sqlx, applied by Tauri on startup)
# Migration files live in migrations/ — sqlx applies them automatically.

# ZK setup (run once before cargo tauri build)
cd proofs && bash setup_circuits.sh        # compile circuits + Groth16 setup
# Then: cargo run --release --bin export_ark_zkey -- <in.zkey> <out.ark.zkey>
# for each circuit, staging into proofs/keys/

# Verifiers (offline / cross-impl conformance)
cd verifiers/rust && cargo test
cd verifiers/javascript && npm test
```

## Architecture

### Language Ownership — Hard Boundaries

```
Rust       → Tauri app, Axum HTTP server, cryptographic hot path: BLAKE3, Ed25519, Poseidon, SMT,
             canonicalization, embedded PostgreSQL (pg_embed), all DB operations,
             SBT issue/verify/revoke, anchoring (RFC 3161 / Rekor / OTS)
TypeScript → React frontend (app/public-ui/)
```

Python and Go are retired. The Python FastAPI server, the Go sequencer, and
the Go/Python verifiers were replaced by the Tauri + Axum desktop in v0.9.0.

### Deployment

- **Desktop app (primary)**: Tauri 2 binary with embedded Axum HTTP server + pg_embed PostgreSQL.
  - Windows: install the MSI or NSIS bundle produced by `cargo tauri build`.
  - Linux: install the deb / rpm / AppImage bundle.
  - macOS: bundle is produced but not yet code-signed for distribution.
- No external Python, Go, Node, or Docker required at runtime.

### Tauri App (`src-tauri/`)

Axum HTTP server embedded in the Tauri process. Handles all API requests. Runs
pg_embed for an embedded PostgreSQL instance. sqlx migrations in `migrations/`
are applied on startup (both `init_embedded` and `connect_external` paths).

Key files:
- `src-tauri/src/main.rs` — Tauri entry, `resolve_proofs_dir`, placeholder gate, IPC commands
- `src-tauri/src/server/mod.rs` — Axum router setup
- `src-tauri/src/api/` — Axum route handlers (`ingest`, `ledger`, `redaction`, `admin`, `admin_users`, `keys`, `zk`, `user_auth`, `credentials`, `anchors`)
- `src-tauri/src/routes/public_stats.rs` — public ledger statistics endpoint
- `src-tauri/src/api/zk.rs` — `/zk/verify`, `/zk/prove` (scope-gated)
- `src-tauri/src/api/credentials.rs` — Olympus-native SBTs (issue / list / revoke / verify)
- `src-tauri/src/api/middleware/auth.rs` — `AuthenticatedKey`, `RateLimit`, `derive_api_key_from_bjj`, SBT-driven scope resolver
- `src-tauri/src/state.rs` — `AppState` (pool, BJJ keys, `proofs_dir`, …)
- `src-tauri/src/federation/` — Tor hidden service + checkpoint gossip (feature-gated)
- `src-tauri/src/anchoring/` — external anchors (RFC 3161 / Sigstore Rekor / OpenTimestamps); see `docs/court-evidence.md`
- `src-tauri/src/bin/export_ark_zkey.rs` — snarkjs `.zkey` → arkworks `.ark.zkey`
- `src-tauri/build.rs` — placeholder shim so Tauri's resource glob doesn't fail pre-setup
- `src-tauri/Cargo.toml` — dependencies (arkworks 0.6, ark-circom 0.6, vendored light-poseidon)

### ZK Proof Layer (`proofs/`)

Four Circom circuits: `document_existence`, `non_existence`,
`redaction_validity`, and `unified_canonicalization_inclusion_root_sign`
(the last requires PTAU power 20 for the unified `/zk/prove` path). All four
are compiled by `setup_circuits.sh` and wired for both `/zk/prove` and
`/zk/verify`. The unified circuit's verification key is produced by the trusted
setup and is gitignored until then; the other three vkeys are committed in
`proofs/keys/verification_keys/`.

`src-tauri/build.rs` drops ~60-byte `PLACEHOLDER` stubs for all four into
`proofs/keys/` so Tauri's resource glob and `include_str!` resolve pre-setup;
running `proofs/setup_circuits.sh` overwrites them with real artifacts. With
`OLYMPUS_ENV=production`, startup refuses (`exit 2`) if any artifact is still
a placeholder; dev mode logs a warning and continues.

Runtime artifacts (`.wasm`, `.r1cs`, `.ark.zkey`) are staged into
`proofs/keys/` by the setup pipeline.

- `proofs/setup_circuits.sh` — dev / single-contributor all-in-one path
- `proofs/phase2_ceremony.sh` — multi-contributor Phase 2 (`prepare` / `contribute` / `verify` / `finalize`) for v1.0 release ceremonies
- Both share the Hermez Phase 1 ptau (`proofs/keys/powersOfTau28_hez_final_20.ptau`) and produce the same `.ark.zkey` runtime artifacts.

### Frontend (`app/public-ui/`)

React + TypeScript + Vite + Tailwind + React Query. API client in
`app/public-ui/src/lib/api.ts`. Notable v0.9.x components:

- `InitialSecretsModal.tsx` — one-shot bootstrap dialog surfacing the API key + BJJ key on first launch
- `StartupErrorScreen.tsx` — production startup-error landing page
- `WhoAmIChip.tsx` — current-user / scope chip in the header
- `CredentialsPage.tsx` — SBT issue / list / revoke / verify UI
- `AdminUsersPage.tsx` — admin Users page (mint keys, edit scopes, promote roles)

### Cross-Language Verifiers (`verifiers/`)

Reference implementations in Rust and JavaScript — used for differential
fuzzing and offline proof verification. Test vectors in
`verifiers/test_vectors/vectors.json`.

## Critical Invariants

- **Domain prefixes**: All leaf/node hashes must use `OLY:LEAF:V1|` / `OLY:NODE:V1|`. Constants live in `crates/olympus-crypto/src/lib.rs` (`LEAF_PREFIX`, `NODE_PREFIX`, `KEY_PREFIX`, `EMPTY_LEAF_PREFIX`, `PEDERSEN_H_PREFIX`). The desktop crate consumes them via the `olympus-crypto` workspace dep.
- **Ed25519 signing keys must be persisted** — ephemeral keys make historical signed roots unverifiable.
- **Baby Jubjub authority key must be persisted** — same reasoning; required for SBT signing and the unified-API-key derivation (`derive_api_key_from_bjj`).
- **Canonical JSON**: Always JCS/RFC 8785 raw UTF-8.
- **SBT scope mapping is hardcoded in `auth.rs`** — fail-closed: unknown `credential_type` grants no scopes. Treat the mapping as security policy, not config.

## Environment

Key `.env` variables:
- `OLYMPUS_API_PORT` — HTTP port for the embedded Axum server (default ephemeral; tests pin to 3737)
- `OLYMPUS_INGEST_SIGNING_KEY` — persistent Ed25519 key (production); use `OLYMPUS_DEV_SIGNING_KEY=true` for dev auto-generation
- `OLYMPUS_BJJ_AUTHORITY_KEY` — persistent Baby Jubjub authority key (32-byte hex); auto-generated by bootstrap if absent
- `OLYMPUS_PROOFS_DIR` — override the resolved ZK artifacts directory (precedence: env > Tauri resource_dir > exe-relative > `proofs/keys`)
- `OLYMPUS_ENV=production` — refuse to start with `exit 2` if any ZK artifact is a `PLACEHOLDER` stub
- `OLYMPUS_ADMIN_KEY` — separate header `x-admin-key` required by `/key/admin/generate` and `/key/admin/reload-keys`
- `OLYMPUS_ANCHOR_RFC3161_URL` — RFC 3161 TSA endpoint (e.g. `https://freetsa.org/tsr`); enables RFC 3161 anchoring
- `OLYMPUS_ANCHOR_REKOR_URL` — Sigstore Rekor URL (e.g. `https://rekor.sigstore.dev`); enables Rekor anchoring
- `OLYMPUS_ANCHOR_OTS_CALENDARS` — comma-separated OpenTimestamps calendar URLs; enables OTS anchoring
- `OLYMPUS_ANCHOR_SIGN_KEY` — Ed25519 hex key for Rekor signatures (falls back to `OLYMPUS_INGEST_SIGNING_KEY`)
- `DATABASE_URL` — external Postgres URL; if set, skips pg_embed but still applies migrations
- `CORS_ORIGINS` — explicit comma-separated origins (no wildcards)
