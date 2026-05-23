# Olympus — Onboarding Guide

> Last updated: 2026-05-23. Reflects the post-v0.9.x state on `main`. If you find anything stale, fix it — onboarding docs decay fastest.

Olympus is a cryptographic credential ledger with a ZK proof layer, shipped as a Tauri 2 desktop app. The Python FastAPI server and Go sequencer were retired in v0.9.0; the desktop binary embeds everything (HTTP server + database + prover).

---

## Stack at a Glance

```
Rust       → Tauri 2 app, embedded Axum HTTP server, all crypto + DB
TypeScript → React frontend (app/public-ui/)
Python     → Cross-language verifiers, CLI tooling, circuit-setup scripts only
```

Hard boundary: **the running app never executes Python or Go.** Python is a build-time / verifier-side tool, not a runtime dependency.

---

## Quick Start

```bash
# Install JS deps once
pnpm install

# Run the desktop app in dev (Vite + Tauri, hot-reload frontend)
cargo tauri dev

# Build a production bundle
cargo tauri build
```

First-time ZK setup (run once before `cargo tauri build`):

```bash
cd proofs && bash setup_circuits.sh
# Then for each circuit:
cargo run --release --bin export_ark_zkey -- <in.zkey> <out.ark.zkey>
# Output staged into proofs/keys/
```

### Test commands

```bash
cargo check --workspace          # Fast type/lint check
cargo test --workspace           # All Rust tests
cargo clippy --workspace         # Lints
cargo fmt --all                  # Format

# Frontend
pnpm --filter app/public-ui build
pnpm --filter app/public-ui dev  # Standalone Vite dev server

# Offline / cross-impl verifier conformance
cd verifiers/rust && cargo test
cd verifiers/javascript && npm test
```

---

## Repository Layout

| Path | What lives here |
|---|---|
| `src-tauri/` | Tauri 2 app — entry, HTTP API, federation, anchoring, ZK prover |
| `src-tauri/src/api/` | Axum route handlers (`ingest`, `ledger`, `credentials`, `zk`, `redaction`, etc.) |
| `src-tauri/src/zk/` | In-process ZK prover (arkworks + ark-circom 0.6) |
| `src-tauri/src/federation/` | Tor hidden-service + checkpoint gossip (feature-gated) |
| `src-tauri/src/anchoring/` | RFC 3161 / Sigstore Rekor / OpenTimestamps anchoring |
| `app/public-ui/` | React + TypeScript + Vite + Tailwind + React Query |
| `proofs/` | Circom circuits, setup scripts, ZK keys |
| `migrations/` | `sqlx` SQL migrations (applied on app startup) |
| `crates/` | Shared Rust crates (`olympus-crypto`, vendored `light-poseidon`) |
| `pg-embed-local/` | Vendored fork of `pg_embed` (drives the embedded PostgreSQL) |
| `verifiers/rust/`, `verifiers/javascript/` | Cross-implementation reference verifiers + differential-fuzz harnesses |
| `verifiers/python/`, `verifiers/cli/` | Python verifier + cross-language conformance CLI |
| `fuzz/` | `cargo-fuzz` targets (crypto primitives, SMT, witness cosig) |
| `docs/` | Architecture notes, ADRs, court-evidence guide |

---

## Architecture

### Deployment

A single Tauri binary. The Tauri process embeds:

- An **Axum HTTP server** that serves the same API the frontend talks to.
- **`pg_embed` PostgreSQL** with `sqlx` migrations applied on startup.
- The **in-process ZK prover** (arkworks 0.6 + ark-circom 0.6), no Node.js required at runtime.

Installers: MSI / NSIS (Windows), `.deb` / `.rpm` / AppImage (Linux), unsigned `.app` bundle (macOS).

### Key files to know

- `src-tauri/src/main.rs` — Tauri entry, `resolve_proofs_dir`, IPC commands.
- `src-tauri/src/server/mod.rs` — Axum router setup.
- `src-tauri/src/state.rs` — `AppState` (pool, BJJ keys, `proofs_dir`).
- `src-tauri/src/api/middleware/auth.rs` — `AuthenticatedKey`, `RateLimit`, SBT-driven scope resolver.
- `src-tauri/src/api/zk.rs` — `/zk/verify`, `/zk/prove` (scope-gated).
- `src-tauri/src/api/credentials.rs` — Olympus-native SBTs (issue / list / revoke / verify).
- `src-tauri/src/bin/export_ark_zkey.rs` — snarkjs `.zkey` → arkworks `.ark.zkey` converter.
- `src-tauri/build.rs` — placeholder shim so Tauri's resource glob doesn't fail before `setup_circuits.sh` has run.

### Frontend

`app/public-ui/` is a single SPA. API client lives in `app/public-ui/src/lib/api.ts`; all hooks use the `getApiBase()` helper so the same code works in Tauri and standalone-Vite. Notable v0.9.x surfaces:

- `InitialSecretsModal.tsx` — first-launch dialog that surfaces the API key + BJJ key once.
- `CredentialsPage.tsx` — SBT issue / list / revoke / verify.
- `AdminUsersPage.tsx` — mint keys, edit scopes, promote roles.
- `StartupErrorScreen.tsx` — production startup-error landing page.

### ZK layer

Three Circom circuits ship as authoritative: `document_existence`, `non_existence`, `redaction_validity`. The legacy `unified_canonicalization_inclusion_root_sign` circuit source still ships but is excluded from `setup_circuits.sh` and not loaded at runtime.

Two ceremony paths share the same Hermez Phase-1 ptau (`proofs/keys/powersOfTau28_hez_final_20.ptau`) and produce the same `.ark.zkey` runtime artifacts:

- `proofs/setup_circuits.sh` — dev / single-contributor all-in-one path.
- `proofs/phase2_ceremony.sh` — multi-contributor Phase 2 (`prepare` / `contribute` / `verify` / `finalize`) for v1.0 release ceremonies.

---

## Critical Invariants

These are the non-negotiables. If you break one, security analysis breaks.

- **Domain prefixes**: All leaf/node hashes must use `OLY:LEAF:V1|` / `OLY:NODE:V1|` constants (defined in `src-tauri/src/crypto.rs`).
- **Persistent Ed25519 signing key**: ephemeral keys make historical signed roots unverifiable. In dev, set `OLYMPUS_DEV_SIGNING_KEY=true` for auto-generation; in production, `OLYMPUS_INGEST_SIGNING_KEY` is mandatory.
- **Persistent Baby Jubjub authority key**: required for SBT signing and the unified-API-key derivation in `derive_api_key_from_bjj`. Auto-generated by bootstrap if absent.
- **Canonical JSON**: JCS / RFC 8785, raw UTF-8. No bare `serde_json` for anything that gets signed or hashed.
- **SBT scope mapping is hardcoded in `auth.rs`** — fail-closed: an unknown `credential_type` grants no scopes. Treat the mapping as security policy, not configuration.
- **Production placeholder gate**: with `OLYMPUS_ENV=production`, the app refuses to start (`exit 2`) if any ZK artifact in `proofs/keys/` is still a `PLACEHOLDER` stub.

---

## Environment

Common `.env` variables (full list in [CLAUDE.md](CLAUDE.md)):

| Variable | Purpose |
|---|---|
| `OLYMPUS_API_PORT` | HTTP port for the embedded Axum server (default ephemeral; tests pin to 3737) |
| `OLYMPUS_INGEST_SIGNING_KEY` | Persistent Ed25519 key (production) |
| `OLYMPUS_DEV_SIGNING_KEY=true` | Dev auto-generation |
| `OLYMPUS_BJJ_AUTHORITY_KEY` | Persistent Baby Jubjub authority key (32-byte hex) |
| `OLYMPUS_PROOFS_DIR` | Override resolved ZK artifacts directory |
| `OLYMPUS_ENV=production` | Enables the placeholder gate |
| `OLYMPUS_ADMIN_KEY` | Required by `/key/admin/generate` and `/key/admin/reload-keys` (header `x-admin-key`) |
| `OLYMPUS_ANCHOR_RFC3161_URL` | RFC 3161 TSA endpoint (enables RFC 3161 anchoring) |
| `OLYMPUS_ANCHOR_REKOR_URL` | Sigstore Rekor URL (enables Rekor anchoring) |
| `OLYMPUS_ANCHOR_OTS_CALENDARS` | Comma-separated OpenTimestamps calendars |
| `DATABASE_URL` | External Postgres URL — skips `pg_embed`, still applies migrations |
| `CORS_ORIGINS` | Explicit comma-separated origins (no wildcards) |

---

## CI / Pre-commit

Per-PR CI jobs (`.github/workflows/ci.yml`):

- `tauri desktop unit tests` — `cargo test --workspace` on Linux.
- `frontend type-check + build` — `pnpm install` (frozen lockfile) + Vite build.
- `Cargo fuzz Olympus verifier (30 s per target)` — short cargo-fuzz smoke per target in `fuzz/fuzz_targets/`.
- `Rust verifier conformance` — runs `verifiers/rust/` against the shared `verifiers/test_vectors/vectors.json`.
- `CodeQL (javascript-typescript)` — static analysis on the frontend.
- `supply-chain (sbom + audit)` — `cargo audit` + `npm audit` + SBOM generation.
- `require-human-approval` — policy gate on Dependabot PRs (not a code-fix failure).

Pre-commit hooks live in `.githooks/`. There's no `.pre-commit-config.yaml` in this repo — the historical `pre-commit` framework messages you may see (`No .pre-commit-config.yaml file was found`) are harmless. Set `PRE_COMMIT_ALLOW_NO_CONFIG=1` to silence them.

### Common gotchas

| Pattern | Fix |
|---|---|
| `ERR_PNPM_OUTDATED_LOCKFILE` on a Rust-only PR | Lockfile drift on `main` — refresh with `pnpm install --lockfile-only` on a separate PR before debugging the Rust change |
| Dependabot bumps for `rand 0.9` / `hmac 0.13` | Closed pending arkworks 0.7 / digest 0.11 ecosystem migration. See tracking issues #990 / #991 |
| `blake3` / `blake3-wasm` 3.0.0 bumps | Closed — broken upstream package metadata. See tracking issue #993 |
| `require-human-approval` red on a Dependabot PR | Not a failure — it's the policy gate, click approve |

---

## Platform Notes

Olympus targets **Windows, Linux, and macOS** (in that priority order — Anthony develops on Windows). Don't dismiss non-Windows feedback.

- **Windows**: MSI / NSIS bundle. CRLF line endings enforced on `*.cmd` / `*.bat` via `.gitattributes`.
- **Linux**: `.deb` / `.rpm` / AppImage.
- **macOS**: bundle is produced by `cargo tauri build` but **not yet code-signed for distribution**.

There's no Docker requirement at runtime. Any historical `docker-compose.yml` references are from the retired FastAPI stack.

---

## Where to Look Next

- [CLAUDE.md](CLAUDE.md) — the source-of-truth file for working with Claude in this repo. Read this first.
- [docs/architecture.md](docs/architecture.md) — deeper architecture notes.
- [docs/court-evidence.md](docs/court-evidence.md) — how the anchoring stack maps to legal evidence requirements.
- [docs/adr/](docs/adr/) — Architecture Decision Records.
- [CHANGELOG.md](CHANGELOG.md) — what landed in each release.

If you're reading this as a new contributor: start by running `cargo tauri dev`, poking at the UI, then read [src-tauri/src/main.rs](src-tauri/src/main.rs) and [src-tauri/src/server/mod.rs](src-tauri/src/server/mod.rs) — those two files plus the layout table above are enough to get oriented.
