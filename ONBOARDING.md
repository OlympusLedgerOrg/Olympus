# Olympus Dev Standards — Onboarding Guide

> Last updated: 2026-05-16. Covers the current state of the `main` branch plus active feature work.

---

## Repo at a Glance

Olympus is a cryptographic credential ledger with a ZK proof layer. Three languages, hard ownership boundaries:

```
Python  → API, policy, orchestration, ALL database operations
Rust    → Crypto hot path: BLAKE3, Ed25519, Poseidon, SMT, canonicalization (olympus_core PyO3)
Go      → Trillian-shaped log sequencer — never computes Merkle hashes itself
```

Boundary violations are blocked by `tools/check_import_boundaries.py` (runs in pre-commit).

---

## Quick Start

```bash
docker compose up -d                     # Full stack: PostgreSQL, Go sequencer, Rust SMT, API, TSA worker, UI
python -m alembic upgrade head           # Apply migrations
make dev                                 # FastAPI on :8000 (local dev only — no Docker)

maturin develop                          # Build Rust extension (olympus_core)
```

> **TSA worker is a required sidecar.** `POST /datasets/commit` returns `timestamp_status="pending"` immediately; the `tsa-worker` service drains the `tsa_jobs` queue and fetches RFC 3161 tokens in the background. If you run only the `app` service without `tsa-worker`, timestamps will stay `pending` indefinitely. `docker compose up -d` starts all services including the worker.

### Essential Make Targets

```bash
make check          # Full quality gate: lint + typecheck + tests + coverage ≥85%
make lint           # ruff + mypy + bandit
make format         # ruff auto-fix
make pre-push       # Fast local CI gate — run before every push
make smoke          # PostgreSQL-backed integration smoke tests
make vectors        # Verify golden cryptographic test vectors
make mutation-test  # Mutation testing on crypto modules
make fuzz-smoke     # Hypothesis fuzzing (<3 min)
```

### Test Commands

```bash
pytest tests/ -v                                           # All tests
pytest tests/ -v -m "not postgres"                        # Skip DB-required
pytest tests/test_file.py::test_name -v                   # Single test
pytest tests/ -v --cov=protocol --cov=storage --cov=api   # With coverage
```

**Test markers:** `postgres`, `smoke`, `slow`, `layer4` (ZK circuits — require WASM + Node.js), `fuzz`, `security`, `differential`, `api`, `storage`, `xdist_group`

Do not skip `layer4` silently — the CI unit lane runs with `-m "not layer4"`. Tests that instantiate Halo2 components must use `pytest.raises(RuntimeError, match="Phase 1\\+")` — `Halo2Backend.__init__` raises immediately.

---

## Architecture

### Deployment Phases

- **Phase 0 (current):** Python FastAPI → `storage/postgres.py` → PostgreSQL
- **Phase 1 (target):** Python FastAPI → Go sequencer (`services/sequencer-go/`) → Rust SMT (`services/cdhs-smf-rust/`) → PostgreSQL

### Key Layers

| Layer | Entry point | Notes |
|---|---|---|
| Protocol | `protocol/` | Source of truth for all crypto logic |
| Storage | `storage/postgres.py` (~119 KB) | Single DB entry point; never bypass it |
| API | `api/main.py`, `api/routers/` | FastAPI; auth in `api/auth.py` |
| ZK Proofs | `proofs/` | Circom circuits; Python calls snarkjs via `proofs/snarkjs_bridge.py` |
| EVM (optional) | `api/services/evm_mint.py` | ERC-5484 soulbound token mirror — not the authoritative source |
| Frontend | `app/public-ui/` | React + TypeScript + Vite + Tailwind + React Query |
| Verifiers | `verifiers/` | Cross-language reference impls for differential fuzzing |

### Protocol Layer (`protocol/`)

- `hashes.py` — BLAKE3 domain-separated hashing
- `canonical.py` — JCS/RFC 8785 canonical JSON
- `merkle.py` — SMT inclusion/non-inclusion proofs
- `checkpoints.py` — Ed25519-signed roots
- `poseidon_smt.py` / `poseidon_tree.py` — Poseidon hash trees for ZK circuits

### Storage Layer

The SMT is a 256-level global sparse Merkle tree. Incremental proof generation reads `smt_nodes` — never do a full leaf scan. Migrations live in `alembic/versions/`.

The `_NODE_REHASH_GATE` (in `storage/_pg_utils.py`) is a BLAKE3-derived session variable that guards SMT node updates. It's set via `SET LOCAL olympus.allow_node_rehash = <gate>` inside transactions. Set `OLYMPUS_NODE_REHASH_GATE_SECRET` in `.env`.

### API Layer

Routers: `agencies`, `appeals`, `documents`, `datasets`, `ledger`, `shards`, `federation`, `keys`, `witness`, `public_stats`, `user_auth`, `admin`, `redaction`, `sbt_metadata`, `operator`.

`/ingest/files` uses FastAPI `Form()` params — tests must use `data=` not `params=` with the test client.

The `/oracle/refine` and `/oracle/appeal` endpoints call the Anthropic API (`ANTHROPIC_API_KEY` required).

---

## Critical Invariants — Do Not Break These

### Cryptographic

- **Hash domain prefixes:** All leaf/node hashes use `OLY:LEAF:V1|` / `OLY:NODE:V1|` with **pipe** separators (not colons). Shared between `olympus_core` and `cdhs-smf-rust` via the `crates/olympus-crypto` crate.
- **Global SMT keys:** Use `BLAKE3.derive_key("olympus 2025-12 global-smt-leaf-key", ...)` with length-prefixed inputs — no raw prefix tag.
- **Ed25519 signing keys must be persisted.** Ephemeral keys make historical signed roots unverifiable. Any keypair generation needs a persistence strategy.
- **Canonical JSON:** Always JCS/RFC 8785, raw UTF-8. Never bare `json.dumps` — always normalize first.
- **Signing fields:** Use `encode_signing_fields()` for pipe-injection protection. Never build signing payloads by hand.

### Runtime

- **Rust extension:** If `OLYMPUS_REQUIRE_RUST=1` and `olympus_core` fails to load, the process **must hard-fail** — no silent Python fallback.
- **Go sequencer batch inserts:** All 256 delta inserts for a batch must be inside a single outer DB transaction.
- **`datetime.timezone.utc`** not `datetime.UTC` — Python 3.10 compatibility required.
- **Coverage minimum is 85%** on `protocol/`, `storage/`, `api/`.

### Security

- **Demo API keys are rejected** by pre-commit hook (`tools/check_demo_keys.py`). Never commit a demo/placeholder key.
- **CORS:** Explicit comma-separated origins only (`CORS_ORIGINS`). No wildcards.
- **Equivocation protection:** `EquivocationSeenCache` in `partition.py` guards against duplicate root submissions.

---

## EVM / SBT Layer (Optional)

The `api/services/evm_mint.py` module is an **optional** ERC-5484 on-chain mirror. Olympus-native credentials (`KeyCredential`) are the authoritative source — the on-chain SBT is a projection only.

Calling order:
1. Ed25519 consent flow (`POST /key/signing/{key_id}/consent/...`)
2. `POST /key/credential` → `KeyCredential` created, verifiable via SMT proof
3. *(optional)* Wallet binding (`POST /key/signing/{key_id}/wallet/...`)
4. *(optional)* `mint_credential_on_chain()` → ERC-5484 token

Required env vars for EVM: `OLYMPUS_EVM_CONTRACT_ADDRESS`, `OLYMPUS_EVM_RPC_URL`, `OLYMPUS_EVM_HOT_WALLET_KEY`.

`web3` and `eth-account` are in `pyproject.toml` deps and covered by `mypy.overrides` (`ignore_missing_imports = true`) so they don't need inline `# type: ignore` comments.

---

## Lockfile Management

Lockfiles are generated with uv and committed:

```bash
python -m uv pip compile pyproject.toml --extra dev \
  --python-version 3.10 --universal --generate-hashes --upgrade \
  -o requirements-dev.txt

python -m uv pip compile pyproject.toml \
  --python-version 3.10 --universal --generate-hashes --upgrade \
  -o requirements.txt
```

**Always use `--upgrade`** to pick up latest transitive deps. After merging Dependabot PRs:
1. Update direct pins in `pyproject.toml`
2. Regenerate both lockfiles
3. Open a single PR (don't merge Dependabot lockfile edits directly — they conflict with each other)

Dependabot known pattern: `boto3` and `botocore` bump together; `mypy` and `librt` bump together. Merge the transitive dep first, then `@dependabot rebase` the main package PR.

---

## Environment Variables

| Variable | Purpose |
|---|---|
| `DATABASE_URL` / `PSYCOPG_URL` | Async/sync PostgreSQL connection strings |
| `OLYMPUS_API_KEYS_JSON` | JSON array of `{key_hash, key_id, scopes, expires_at}` |
| `OLYMPUS_INGEST_SIGNING_KEY` | Persistent Ed25519 key (production) |
| `OLYMPUS_DEV_SIGNING_KEY` | Dev auto-generation (never in production) |
| `OLYMPUS_REQUIRE_RUST=1` | Hard-fail if `olympus_core` extension unavailable |
| `OLYMPUS_USE_GO_SEQUENCER=true` | Route through Go sequencer |
| `OLYMPUS_NODE_REHASH_GATE_SECRET` | Required in production; guards SMT node updates |
| `CORS_ORIGINS` | Explicit comma-separated origins |
| `RATE_LIMIT_BACKEND` | `"memory"` or `"redis"` |
| `ANTHROPIC_API_KEY` | Required for `/oracle/refine` and `/oracle/appeal` |
| `OLYMPUS_EVM_*` | EVM mirror config (only needed if using SBT layer) |

---

## CI / Pre-commit

The pre-commit stack runs: `ruff` (lint + format) → `mypy` → `bandit` → end-of-file + trailing whitespace fixers → TOML/YAML checks → demo-key check.

**Common CI failure patterns and fixes:**

| Failure | Cause | Fix |
|---|---|---|
| `warn_unused_ignores` on `# type: ignore[import-not-found]` | Module now has `ignore_missing_imports` in `pyproject.toml` mypy overrides | Remove the inline comment |
| `reveal_mask length N does not match redaction_max_leaves 64` | `CircuitConfig.default()` returns 64 leaves; test uses 4-element mask | `dataclasses.replace(CircuitConfig.default(), redaction_max_leaves=4)` |
| `/ingest/files` test 422 | Endpoint uses `Form()` params | Use `data=` not `params=` in the test client |
| Go fuzz `t.Skip()` inside `f.Fuzz()` | `t.Skip` is unsupported in fuzz bodies | Use `return` instead |
| `pip check` fails on EVM deps | `eth-account`/`web3` not in `requirements-dev.txt` | Add explicit `pip install eth-account web3` step before `pip install -e . --no-deps` in CI |

The `require-human-approval` check on Dependabot PRs is a policy gate (not a CI failure) — it needs a human merge, not a code fix.

---

## Windows Native Dev

See `setup-windows.ps1` for the full Windows-native setup (PostgreSQL portable or Docker, Go sequencer, Vite dev server). Key notes:

- `*.cmd` and `*.bat` files must have CRLF line endings (enforced via `.gitattributes`)
- The Windows firewall script (`scripts/firewall-peer-windows.ps1`) creates separate IPv4 (`0.0.0.0/0`) and IPv6 (`::/0`) block rules
- Peer API binds to `127.0.0.1` (not `0.0.0.0`) per `.env.peer.example`
