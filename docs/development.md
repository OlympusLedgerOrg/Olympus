# Development Guide

Common workflows for hacking on Olympus v0.10.0.

For first-time install (including the one-time ZK setup), see
[`quickstart.md`](quickstart.md).

## Prerequisites

- **Rust** (stable, 2021 edition) — `rustup install stable`
- **Node.js ≥ 18** and **pnpm** — `corepack enable && corepack prepare pnpm@11.1.2 --activate`
- **Tauri 2 system dependencies** — see [Tauri prereqs](https://v2.tauri.app/start/prerequisites/)
- **circom ≥ 2.2** — only needed if you change ZK circuits; otherwise the
  staged artifacts in `proofs/keys/` are enough

No Python, no Docker, no external PostgreSQL. Everything runs out of
`cargo tauri dev`.

## Initial setup

```bash
git clone https://github.com/OlympusLedgerOrg/Olympus.git
cd Olympus
pnpm install
```

If `proofs/keys/*.wasm` are 60-byte stubs, run the ZK setup from
[`quickstart.md`](quickstart.md#one-time-zk-trusted-setup) before
`cargo tauri build` (the placeholder gate aborts a production build).

## Running the app

```bash
cargo tauri dev            # hot-reload frontend + Rust restart on src-tauri/ changes
cargo tauri build          # production binary + installer bundles
```

The Tauri process:

- Provisions a per-user data dir for `pg_embed` PostgreSQL
- Applies sqlx migrations from `migrations/` on startup
- Loads or generates the Baby Jubjub authority key (`OLYMPUS_BJJ_AUTHORITY_KEY`)
- Derives the bootstrap API key from the BJJ key (`derive_api_key_from_bjj`)
- Issues the bootstrap authority SBT
- Starts the embedded Axum HTTP server on `OLYMPUS_API_PORT` (default ephemeral)

## Useful commands

```bash
# Type and lint
cargo check --workspace
cargo clippy --workspace --all-targets
cargo fmt --all -- --check

# Tests
cargo test --workspace                            # all Rust unit + integration
cargo test --lib api::middleware::auth            # one module
cargo test --features federation                  # Tor + checkpoint gossip path

# Frontend only
pnpm --filter app/public-ui build
pnpm --filter app/public-ui test:run
pnpm --filter app/public-ui dev                   # standalone Vite at :5173

# Verifiers
cd verifiers/rust && cargo test
cd verifiers/javascript && npm test

# Coverage (see docs/coverage.md for details)
cargo llvm-cov --workspace --summary-only
pnpm --filter app/public-ui coverage
```

### Git hooks (optional)

Shared hooks live in [.githooks/](../.githooks/). Activate them per-clone:

```bash
bash scripts/install-hooks.sh
```

That sets `core.hooksPath = .githooks` so commits run `cargo fmt` (auto-fix
on staged files) + `cargo clippy`, and pushes run the full per-PR CI gate
locally. Bypass per-invocation with `--no-verify`, or set
`OLYMPUS_SKIP_PRECOMMIT=1` / `OLYMPUS_SKIP_PREPUSH=1`.

## Environment variables

All optional in dev; defaults Just Work. See [`CLAUDE.md`](../CLAUDE.md#environment)
for the authoritative list. Common overrides:

| Variable | Purpose |
|---|---|
| `OLYMPUS_API_PORT` | Pin the HTTP port (default: ephemeral; tests pin 3737) |
| `OLYMPUS_DEV_SIGNING_KEY=true` | Auto-generate an Ed25519 dev key on startup |
| `OLYMPUS_BJJ_AUTHORITY_KEY` | Persistent BJJ key (32-byte hex); auto-generated if absent |
| `OLYMPUS_PROOFS_DIR` | Override ZK artifact location (precedence: env > Tauri resource_dir > exe-relative > `proofs/keys`) |
| `OLYMPUS_ENV=production` | Refuse to start with `exit 2` if any ZK artifact is a `PLACEHOLDER` |
| `DATABASE_URL` | Skip `pg_embed`, use external PostgreSQL; migrations still applied |
| `OLYMPUS_ANCHOR_RFC3161_URL` / `_REKOR_URL` / `_OTS_CALENDARS` | Enable external anchoring backends |

## Working with migrations

Migrations live in `migrations/<NNNN>_<name>.sql` and are applied on
startup by `sqlx::migrate!`. To add one:

```bash
ls migrations/ | tail -3                          # find the next NNNN
$EDITOR migrations/0029_my_new_migration.sql      # add SQL
cargo tauri dev                                   # restart applies it
```

If you point `DATABASE_URL` at a Postgres that already has the schema
seeded out-of-band, sqlx may try to replay 0001 and fail with
"type already exists". Workaround: drop the DB and let migrations run
fresh. Tracked as a follow-up in
[`docs/session-report-2026-05-22.md`](session-report-2026-05-22.md).

## Working with SBTs and scopes

The SBT-driven scope resolver in `src-tauri/src/api/middleware/auth.rs`
unions the legacy `api_keys.scopes` column with scopes derived from
active `key_credentials` rows joined via
`holder_key = "bjj:{x}:{y}"`. The `credential_type → scopes` mapping is
hardcoded in `scopes_for_credential_type` and **fail-closed**: unknown
types grant nothing.

To grant a holder press credentials end-to-end:

```bash
# As admin (X-API-Key: <admin_key>)
curl -X POST http://127.0.0.1:$PORT/credentials \
  -H "X-API-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{
    "holder_key": "bjj:'"$HOLDER_X"':'"$HOLDER_Y"'",
    "credential_type": "press_credential",
    "details": {"outlet": "Example Press"}
  }'
```

The holder's existing API key now resolves with `read`, `verify`,
`ingest`, `commit` scopes added. No re-mint required.

## Frontend conventions

- React + TypeScript + Vite + Tailwind + React Query
- API client in [`app/public-ui/src/lib/api.ts`](../app/public-ui/src/lib/api.ts) — use the typed `ApiError`
- Routes registered in [`app/public-ui/src/App.tsx`](../app/public-ui/src/App.tsx)
- Page components in `app/public-ui/src/pages/`, reusable in `components/`
- Skins/themes in `app/public-ui/src/skins/`
- Reduced-motion respect is a hard requirement for any new motion (see GlitchMentor, BootTicker, SkylineBackdrop for examples)

## Pre-commit hooks

Shared hooks live in [.githooks/](../.githooks/) and are documented under
**Git hooks (optional)** above. Activate with `bash scripts/install-hooks.sh`.
The repo does not use the Python `pre-commit` framework — if you previously
installed it here, delete `.git/hooks/pre-commit` before running the
install script.

## Troubleshooting

**`cargo tauri build` fails with "placeholder artifact rejected"** —
`OLYMPUS_ENV=production` is set and `proofs/keys/` contains 60-byte
stubs. Run the ZK setup from
[`quickstart.md`](quickstart.md#one-time-zk-trusted-setup) or unset
`OLYMPUS_ENV` for a dev build.

**`/admin/users` returns 500 with a valid admin key** — should be fixed
in v0.9.1 (#944). If it recurs, check that `users.created_at` decodes
as `chrono::DateTime<chrono::Utc>` (TIMESTAMPTZ), not `NaiveDateTime`.

**WSL2 governor rate-limit oddities** — the `governor` crate uses
`std::time::Instant`. If the WSL2 clock drifts from the Windows host,
tokens may appear exhausted. Run `sudo hwclock -s` to resync. See
[`src-tauri/src/state.rs`](../src-tauri/src/state.rs) for the full note.

**WSL2 webkit2gtk crashes / blank window** — set:
```bash
export WEBKIT_DISABLE_DMABUF_RENDERER=1
export WEBKIT_DISABLE_COMPOSITING_MODE=1
export LIBGL_ALWAYS_SOFTWARE=1
```
before launching the dev build or the AppImage.

**Vite build chunk warning > 500 KB** — known. The single index bundle
is ~509 KB; code-splitting is on the v1.0 backlog.
