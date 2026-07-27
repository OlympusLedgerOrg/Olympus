# Olympus — Onboarding Guide

> Last updated: 2026-07-15. Reflects the v0.10.x Rust/Tauri desktop state on
> `main`. If you find anything stale, fix it — onboarding docs decay fastest.

Olympus is a cryptographic credential ledger with a ZK proof layer, shipped as a Tauri 2 desktop app. The Python FastAPI server and Go sequencer were retired in v0.9.0; the desktop binary embeds everything (HTTP server + database + prover).

---

## Stack at a Glance

```
Rust       → Tauri 2 app, embedded Axum HTTP server, all crypto + DB
TypeScript → React frontend (app/public-ui/)
Python     → Optional client SDK / ad hoc tooling only; not runtime or verifier
```

Hard boundary: **the running app never executes Python or Go.** Rust owns the
security-critical runtime and database path; the maintained offline reference
verifiers are Rust and JavaScript.

---

## Quick Start

Use [`docs/quickstart.md`](docs/quickstart.md) for the complete prerequisite and
platform instructions. The minimum contributor toolchain includes Rust 1.94 or
newer, Node.js 22.12 or newer, pnpm 11.1.2, the Tauri CLI 2, and the native
Tauri system dependencies for your operating system.

```bash
# Install JS deps once
pnpm install --frozen-lockfile

# Run the desktop app in development (Vite + Tauri, hot-reload frontend)
OLYMPUS_ENV=development OLYMPUS_API_PORT=3737 cargo tauri dev
```

PowerShell equivalent:

```powershell
$env:OLYMPUS_ENV = "development"
$env:OLYMPUS_API_PORT = "3737"
cargo tauri dev
```

Olympus deliberately treats an unset or unrecognized `OLYMPUS_ENV` as
production. Development mode must therefore be explicit. A fresh clone's
placeholder ZK artifacts are allowed in development; `/zk/prove` returns 503
until real artifacts are generated.

Production bundling and trusted setup are separate from first-time contributor
startup. Before `OLYMPUS_ENV=production cargo tauri build`, run:

```bash
cd proofs && bash setup_circuits.sh
# The script compiles circuits, exports .ark.zkey files, and writes manifests.
# Output is staged into proofs/keys/.
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
| `verifiers/rust/`, `verifiers/javascript/` | Maintained offline reference verifiers + conformance tests |
| `docs/` | Architecture notes, ADRs, court-evidence guide |

---

## Architecture

### Deployment

A single Tauri binary. The Tauri process embeds:

- An **Axum HTTP server** that serves the same API the frontend talks to.
- **`pg_embed` PostgreSQL** with `sqlx` migrations applied on startup.
- The **in-process ZK prover** (arkworks 0.6 + ark-circom 0.6), no Node.js required at runtime.

Bundle targets: MSI / NSIS (Windows), `.deb` / `.rpm` / AppImage (Linux), and an
unsigned `.app` bundle (macOS). Check GitHub Releases before claiming a specific
installer version is published.

### Key files to know

- `src-tauri/src/main.rs` — Tauri entry, `resolve_proofs_dir`, IPC commands.
- `src-tauri/src/server/mod.rs` — Axum router setup.
- `src-tauri/src/state.rs` — `AppState` (pool, BJJ keys, `proofs_dir`).
- `src-tauri/src/api/middleware/auth.rs` — `AuthenticatedKey`, `RateLimit`, SBT-driven scope resolver.
- `src-tauri/src/api/zk/` — `/zk/verify`, `/zk/prove` (scope-gated).
- `src-tauri/src/api/credentials/` — Olympus-native SBTs (issue / list / revoke / verify).
- `src-tauri/src/bin/export_ark_zkey.rs` — snarkjs `.zkey` → arkworks `.ark.zkey` converter.
- `src-tauri/build.rs` — placeholder shim so Tauri's resource glob doesn't fail before `setup_circuits.sh` has run.

### Frontend

`app/public-ui/` is a single SPA. API client lives in `app/public-ui/src/lib/api.ts`; all hooks use the `getApiBase()` helper so the same code works in Tauri and standalone-Vite. Notable v0.9.x surfaces:

- `InitialSecretsModal.tsx` — first-launch dialog that surfaces the API key + BJJ key once.
- `CredentialsPage.tsx` — SBT issue / list / revoke / verify.
- `AdminUsersPage.tsx` — mint keys, edit scopes, promote roles.
- `StartupErrorScreen.tsx` — production startup-error landing page.

### ZK layer

Three production Circom artifacts ship: `document_existence`, `non_existence`,
and the historical artifact stem
`unified_canonicalization_inclusion_root_sign`. The live API exposes the last
artifact's structured-commitment and inclusion statement as
`unified_section_commitment_inclusion_root`; it proves neither canonicalization
nor a signature. The public `unified_canonicalization_inclusion_root` protocol
composes that Groth16 proof with a verified fixed-image RISC Zero receipt that
runs the shared Rust canonicalizer. Requests using the historical `_sign`
identifier return 410 Gone. The `federation_quorum` circuit also ships for the
next-phase quorum path behind the `quorum-circuit` feature. ADR-0030 removed
`redaction_validity`; redaction now uses a signed Merkle fold over
format-agnostic segment leaves, not a Groth16 proof.

Two ceremony paths share the same Hermez Phase-1 ptau (`proofs/keys/powersOfTau28_hez_final_20.ptau`) and produce the same `.ark.zkey` runtime artifacts:

- `proofs/setup_circuits.sh` — dev / single-contributor all-in-one path.
- `proofs/phase2_ceremony.sh` — multi-contributor Phase 2 (`prepare` / `contribute` / `verify` / `finalize`) for v1.0 release ceremonies.

---

## Critical Invariants

These are the non-negotiables. If you break one, security analysis breaks.

- **Domain prefixes**: Node hashes use `OLY:NODE:V1`; leaf hashes use the
  ADR-0005 structured binary prefix in `crates/olympus-crypto/src/lib.rs`
  (`u8(0x01) || "OLY" || u8(LEAF) || u8(V1) || lp(shard_id)`) plus the
  count-framed parser/model body. `OLY:LEAF:V1` is only a pinned legacy marker.
- **Persistent Ed25519 signing key**: ephemeral keys make historical signed roots unverifiable. In dev, set `OLYMPUS_DEV_SIGNING_KEY=true` for auto-generation; in production, `OLYMPUS_INGEST_SIGNING_KEY` is mandatory.
- **Persistent Baby Jubjub authority key**: required for SBT signing and the unified-API-key derivation in `derive_api_key_from_bjj`. Auto-generated by bootstrap if absent.
- **Canonical JSON**: JCS / RFC 8785, raw UTF-8. No bare `serde_json` for anything that gets signed or hashed.
- **SBT scope mapping is hardcoded in `auth.rs`** — fail-closed: an unknown `credential_type` grants no scopes. Treat the mapping as security policy, not configuration.
- **Production placeholder gate**: with `OLYMPUS_ENV=production`, the app refuses to start (`exit 2`) if any ZK artifact in `proofs/keys/` is still a `PLACEHOLDER` stub.

---

## Environment

Common `.env` variables (full list in [AGENTS.md](AGENTS.md)):

| Variable | Purpose |
|---|---|
| `OLYMPUS_ENV=development` | Explicitly enables local development; placeholder ZK artifacts are allowed |
| `OLYMPUS_ENV=production` | Enables production fail-closed gates; unset, empty, and unknown values are also treated as production |
| `OLYMPUS_API_PORT` | HTTP port for the embedded Axum server (default ephemeral; contributor docs pin to 3737) |
| `OLYMPUS_INGEST_SIGNING_KEY` | Persistent Ed25519 key (production) |
| `OLYMPUS_DEV_SIGNING_KEY=true` | Dev auto-generation |
| `OLYMPUS_BJJ_AUTHORITY_KEY` | Persistent Baby Jubjub authority key (32-byte hex) |
| `OLYMPUS_PROOFS_DIR` | Override resolved ZK artifacts directory |
| `OLYMPUS_ADMIN_KEY` | Required by `/key/admin/generate` and `/key/admin/reload-keys` (header `x-admin-key`) |
| `OLYMPUS_ANCHOR_RFC3161_URL` | RFC 3161 TSA endpoint (enables RFC 3161 anchoring) |
| `OLYMPUS_ANCHOR_REKOR_URL` | Sigstore Rekor URL (enables Rekor anchoring) |
| `OLYMPUS_ANCHOR_OTS_CALENDARS` | Comma-separated OpenTimestamps calendars |
| `DATABASE_URL` | External PostgreSQL runtime role — skips `pg_embed`; production requires `sslmode=verify-full` |
| `OLYMPUS_DATABASE_MIGRATION_URL` | Distinct migrated-object owner used only for startup migrations; Olympus retains the configured schema and installs the exact table/column matrix in [the external-role contract](docs/external-postgresql-roles.md) |
| `OLYMPUS_DEV_ALLOW_SINGLE_DATABASE_URL=true` | Explicit local/CI compatibility mode that reuses `DATABASE_URL`; refused in production |
| PostgreSQL `PG*` variables | All connection-shaping variables listed in the external-role contract must be unset; URL session/target overrides are also forbidden |
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

Pre-commit hooks live in `.githooks/`. Activate them once per clone:

```bash
bash scripts/install-hooks.sh
```

That points `core.hooksPath` at `.githooks/` and enables:
- **pre-commit** on staged files: `cargo fmt --all`, `cargo clippy --workspace -- -D warnings`, `eslint --fix` on `app/public-ui/**`, `tsc --noEmit`. Re-stages files that fmt/eslint rewrote.
- **pre-push**: full workspace clippy + tests + frontend build.

Bypass once with `git commit --no-verify` / `git push --no-verify`, or per-session with `OLYMPUS_SKIP_PRECOMMIT=1` / `OLYMPUS_SKIP_PREPUSH=1`.

There's no `.pre-commit-config.yaml` in this repo — the historical `pre-commit` framework messages you may see (`No .pre-commit-config.yaml file was found`) are harmless. Set `PRE_COMMIT_ALLOW_NO_CONFIG=1` to silence them.

### Common gotchas

| Pattern | Fix |
|---|---|
| `cargo tauri` is not a recognized command | Install Tauri CLI 2 with `cargo install tauri-cli --version "^2.0.0" --locked` |
| App exits 2 on a fresh clone with placeholder ZK files | Set `OLYMPUS_ENV=development`; unset intentionally fails closed to production |
| `ERR_PNPM_OUTDATED_LOCKFILE` on a Rust-only PR | Lockfile drift on `main` — refresh with `pnpm install --lockfile-only` on a separate PR before debugging the Rust change |
| Dependabot bumps for `rand 0.9` / `hmac 0.13` | Closed pending arkworks 0.7 / digest 0.11 ecosystem migration. See tracking issues #990 / #991 |
| `blake3` / `blake3-wasm` 3.0.0 bumps | Closed — broken upstream package metadata. See tracking issue #993 |
| `require-human-approval` red on a Dependabot PR | Not a failure — it's the policy gate, click approve |

---

## Platform Notes

Olympus targets **Windows, Linux, and macOS** (in that priority order — Anthony develops on Windows). Don't dismiss non-Windows feedback.

- **Windows**: MSI / NSIS bundle target. CRLF line endings enforced on `*.cmd` / `*.bat` via `.gitattributes`.
- **Linux**: `.deb` / `.rpm` / AppImage bundle targets.
- **macOS**: bundle is produced by `cargo tauri build` but **not yet code-signed for distribution**.

There's no Docker requirement at runtime. Any historical `docker-compose.yml` references are from the retired FastAPI stack.

---

## Where to Look Next

- [CLAUDE.md](CLAUDE.md) — the source-of-truth file for working with Claude in this repo. Read this first.
- [docs/architecture.md](docs/architecture.md) — deeper architecture notes.
- [docs/court-evidence.md](docs/court-evidence.md) — how the anchoring stack maps to legal evidence requirements.
- [docs/adr/](docs/adr/) — Architecture Decision Records.
- [CHANGELOG.md](CHANGELOG.md) — what landed in each release.

If you're reading this as a new contributor: start with
`OLYMPUS_ENV=development OLYMPUS_API_PORT=3737 cargo tauri dev`, poke at the UI,
then read [src-tauri/src/main.rs](src-tauri/src/main.rs) and
[src-tauri/src/server/mod.rs](src-tauri/src/server/mod.rs) — those two files plus
the layout table above are enough to get oriented.
