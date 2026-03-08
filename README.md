# Olympus

Olympus is an append-only public ledger for government documents. The repository
is focused on protocol hardening: deterministic canonicalization, Merkle
commitments, verifiable proofs, and developer tooling for inspecting and
validating those primitives.

## Current repository state

The primary local developer workflows are:

- `python -m pip install -e ".[dev]"` — install the package plus development
  tooling.
- `make check` — run schema validation, Ruff, mypy, Bandit, and the Python test
  suites.
- `make smoke` — run the PostgreSQL-backed smoke path defined in
  `tools/dev_smoke.sh`.
- `make dev` — start the FastAPI API on `127.0.0.1:8000` and the debug UI on
  `127.0.0.1:8080`.

The smoke test currently provisions PostgreSQL with Docker Compose, initializes
the schema, imports the test-only app, and runs the `postgres`-marked pytest
suite.

## Repository scaffold

```text
api/        FastAPI application and ingestion routes
app_testonly/  test-only application wiring used by smoke/dev flows
docs/       protocol notes, threat model material, and walkthroughs
examples/   sample artifacts and notebook examples
proofs/     Circom circuits, proving assets, and JS-based proof tooling
protocol/   reference implementations of hashing, Merkle, and redaction logic
schemas/    JSON schema definitions validated by tools/validate_schemas.py
storage/    persistence layer implementations and schema bootstrap logic
tests/      regression tests for protocol, API, UI, and smoke/dev workflows
tools/      command-line helpers, schema validation, and dev smoke script
ui/         FastAPI debug console and public verification portal
```

## Quick start

```bash
git clone https://github.com/wombatvagina69-crypto/Olympus.git
cd Olympus
python -m pip install -e ".[dev]"
```

### Quality gate

```bash
make check
```

### Smoke test

The smoke target expects Docker Compose so it can start PostgreSQL locally.

```bash
make smoke
```

### Run the API + UI locally

```bash
export DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
export TEST_DATABASE_URL="$DATABASE_URL"
make dev
```

## Key developer entrypoints

- API application: `api/app.py`
- Debug UI / verification portal: `ui/app.py`
- Canonicalization + verification CLIs: `tools/canonicalize_cli.py`,
  `tools/verify_cli.py`, and `tools/verify_bundle_cli.py`
- Zero-knowledge proof setup and smoke docs: `proofs/README.md`
- Extended setup guide: `QUICKSTART.md`
- Contribution workflow: `CONTRIBUTING.md`

## Notes

- Python requirement: `>=3.10` (3.12 is used in CI/dev tooling).
- The debug console is disabled by default; set `OLYMPUS_DEBUG_UI=true` when
  running the UI directly.
- The public verification portal remains available at `/verification-portal`
  even when debug-only routes are disabled.
