# Olympus Quick Start Guide

This guide provides copy-paste commands to get Olympus up and running quickly.

---

## Prerequisites

- **Python 3.10+** (3.12 recommended)
- **PostgreSQL 16+** (for E2E tests and production)
- **Git**

---

## 1. Clone and Setup Environment

```bash
# Clone repository
git clone https://github.com/wombatvagina69-crypto/Olympus.git
cd Olympus

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # On macOS/Linux
# .venv\Scripts\activate   # On Windows

# Upgrade pip
pip install -U pip

# Install all dependencies
pip install -r requirements.txt -r requirements-dev.txt
```

---

## 2. Database Setup (PostgreSQL)

### macOS (Homebrew)

```bash
# Install PostgreSQL
brew install postgresql@16
brew services start postgresql@16

# Create database
createdb olympus

# Set environment variable
export DATABASE_URL='postgresql://yourusername@localhost:5432/olympus'
```

### Ubuntu/Debian

```bash
# Install PostgreSQL
sudo apt update
sudo apt install postgresql-16
sudo systemctl start postgresql

# Create database and user
sudo -u postgres createuser olympus
sudo -u postgres createdb -O olympus olympus

# Set environment variable
export DATABASE_URL='postgresql://olympus@localhost:5432/olympus'
```

### Docker (Recommended for Development)

The easiest way to run PostgreSQL locally is with Docker Compose:

```bash
# Start API + PostgreSQL (and UI) using docker-compose (runs in background)
docker compose up -d

# Verify it's running
docker compose ps

# Set environment variables
export DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
export TEST_DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
```

**Alternative: Docker Run (one-liner)**

```bash
# Run PostgreSQL in Docker
docker run --name olympus-postgres \
  -e POSTGRES_USER=olympus \
  -e POSTGRES_PASSWORD=olympus \
  -e POSTGRES_DB=olympus \
  -p 5432:5432 \
  -d postgres:16

# Set environment variable
export DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
export TEST_DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
```

**Verify database connection:**

```bash
# Check if PostgreSQL is ready
docker compose exec db pg_isready -U olympus -d olympus

# Or test with Python
python -c "from psycopg import connect; connect('$DATABASE_URL'); print('Connected!')"
```

### Environment Variable Reference

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes (API/DB tests) | PostgreSQL connection string |
| `TEST_DATABASE_URL` | No | Separate connection string for test runs |
| `LOG_LEVEL` | No | Python log level (`DEBUG`, `INFO`, …) |
| `OLYMPUS_DEBUG_UI` | No | Set to `true` to enable the debug UI |
| `OLYMPUS_HALO2_ENABLED` | No | Set to `true` to enable the Halo2 proof backend. **Intentionally a no-op in v1.0** — Halo2 support is planned for Phase 1+. The flag exists so deployment tooling can reference it before the backend ships. |

---

## 3. Verify Installation

```bash
# Validate schemas
python tools/validate_schemas.py

# Run linting
ruff check protocol/ storage/ api/ scaffolding/ tests/

# Run type checking
mypy protocol/ storage/ api/

# Run tests (without PostgreSQL)
pytest tests/ -m "not postgres" -v

# Run tests (with PostgreSQL - requires DATABASE_URL)
pytest tests/ -m "postgres" -v

# Run all tests
pytest tests/ -v
```

---

## 4. Development Workflow

### Lint and Format

```bash
# Check code style
ruff check protocol/ storage/ api/ scaffolding/ tests/

# Auto-fix issues
ruff check protocol/ storage/ api/ scaffolding/ tests/ --fix

# Format code
ruff format protocol/ storage/ api/ scaffolding/ tests/

# Check formatting (without changing)
ruff format --check protocol/ storage/ api/ scaffolding/ tests/
```

### Type Checking

```bash
# Run mypy
mypy protocol/ storage/ api/
```

### Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_ledger.py -v

# Run with coverage
pytest tests/ -m "not postgres" \
  --cov=protocol --cov=storage --cov=api --cov=scaffolding \
  --cov-report=term-missing --cov-report=html

# View coverage report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

### Security Scanning

```bash
# Run bandit security scan
bandit -r protocol/ storage/ api/ scaffolding/

# Generate baseline (optional)
bandit-baseline -r protocol/ storage/ api/ scaffolding/
```

---

## 5. Running the Application

### Development Mode (with hot reload)

```bash
# Using uvicorn directly (works without PostgreSQL, DB endpoints return 503)
uvicorn api.app:app --reload --host 0.0.0.0 --port 8000

# Or using the run script
python run_api.py
```

**Note:** The API can start without PostgreSQL. Non-DB endpoints (`/`, `/health`) always work.
DB-dependent endpoints (`/shards`, `/proof`, `/ledger`) return HTTP 503 if the database is not available.

### Production Mode

```bash
# Set environment variables
export DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'

# Run with multiple workers
uvicorn api.app:app --host 0.0.0.0 --port 8000 --workers 4

# Or with gunicorn (install separately)
pip install gunicorn
gunicorn api.app:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000
```

### Access the Application

```bash
# API is available at
open http://localhost:8000

# API documentation (Swagger UI)
open http://localhost:8000/docs

# API documentation (ReDoc)
open http://localhost:8000/redoc
```

---

## 6. Docker Setup

### Build Docker Image

```bash
# Build development image
docker build --target development -t olympus:dev .

# Build production image
docker build --target production -t olympus:prod .
```

### Run in Docker

```bash
# Development mode (with volume mount)
docker run -it --rm \
  -p 8000:8000 \
  -v $(pwd):/app \
  -e DATABASE_URL='postgresql://olympus:olympus@host.docker.internal:5432/olympus' \
  -e OLYMPUS_DEV_SIGNING_KEY=true \
  olympus:dev

# Production mode
docker run -d \
  -p 8000:8000 \
  -e DATABASE_URL='postgresql://olympus:olympus@host.docker.internal:5432/olympus' \
  -e OLYMPUS_INGEST_SIGNING_KEY='your-64-hex-char-signing-key' \
  --name olympus-api \
  olympus:prod

# View logs
docker logs -f olympus-api

# Stop container
docker stop olympus-api
docker rm olympus-api
```

### Docker Compose

A `docker-compose.yml` is included in the repository. Run:

```bash
# Start just the database
docker compose up -d db

# Start database and app together
docker compose up -d

# View logs
docker compose logs -f

# Stop all services
docker compose down
```

The Docker Compose configs enable `OLYMPUS_DEV_SIGNING_KEY` to generate an ephemeral
signing key for local-only runs. For production deployments, supply a persistent
`OLYMPUS_INGEST_SIGNING_KEY` instead and disable the dev flag.

### Windows/PowerShell Notes

- Ensure text files use **LF** line endings inside the repo. In VS Code, check the bottom-right
  status bar (shows `LF` or `CRLF`). If it shows `CRLF`, click it, switch to `LF`, and save.
- The `.env` file **must** use LF line endings (CRLF can break Docker builds in Linux containers).

PowerShell equivalents for `export`:

```powershell
$env:DATABASE_URL="postgresql://olympus:olympus@localhost:5432/olympus"
$env:TEST_DATABASE_URL=$env:DATABASE_URL
```

#### Windows Docker Setup (Full Stack)

Use `curl.exe` (not the PowerShell `curl` alias) and `docker compose` (V2 CLI):

```powershell
# 1. Copy the example env file (use LF line endings — see note above)
copy .env.example .env

# 2. Start all services
docker compose up -d

# 3. Verify containers are running
docker compose ps

# 4. Check API health (use curl.exe to avoid PowerShell's Invoke-WebRequest alias)
curl.exe http://localhost:8000/health

# 5. Confirm database tables were created
docker compose exec db psql -U olympus -d olympus -c "\dt"
```

The `app` container runs `scripts/startup.sh` on boot, which:
1. Waits for PostgreSQL to accept connections.
2. Runs Alembic migrations and prints results.
3. Starts the API server only if migrations succeed.

#### Troubleshooting database not initializing

If `curl.exe http://localhost:8000/health` returns `"database":"not_initialized"`:

```powershell
# Check app container logs for migration errors
docker compose logs app

# Re-run migrations manually
docker compose exec app python -m alembic upgrade head

# Verify the database has the expected tables
docker compose exec db psql -U olympus -d olympus -c "\dt"

# Full clean restart (removes the postgres volume)
docker compose down -v
docker compose up -d
```

Common causes on Windows:
- **CRLF line endings in `.env`**: Open `.env` in your editor and convert line endings to LF
  (in VS Code: click `CRLF` in the bottom-right status bar and change to `LF`; in other
  editors look for an "End of Line" or "Line Endings" setting). Then `docker compose down -v && docker compose up -d`.
- **Port 5432 already in use**: A local PostgreSQL instance may be binding the port. Stop it
  or change the `db` port mapping in `docker-compose.yml`.
- **Docker Desktop not running**: Make sure Docker Desktop is started before running
  `docker compose` commands.

### Three-node federation demo

For a Dockerized federation-style deployment with three independent API nodes and a shared observer UI, use the included `docker-compose.federation.yml`:

```bash
# Start three Olympus nodes plus the federation debug UI
docker compose -f docker-compose.federation.yml up -d

# Federation dashboard / SMT diff viewer
curl http://localhost:8081 | head

# Stop the federation demo
docker compose -f docker-compose.federation.yml down
```

What this demo provides:

- **Three independent nodes** (`node1-app`, `node2-app`, `node3-app`) with separate PostgreSQL backends
- **Federation health dashboard** showing shard sync status, chain integrity, and root agreement
- **Historical shard views** via `GET /shards/{shard_id}/history`
- **SMT diff viewer** via `GET /shards/{shard_id}/diff?from_seq=&to_seq=`

Important protocol note:

- This Docker setup demonstrates **observer-side majority agreement** across three nodes.
- It does **not** change the v1.0 protocol finality model, which remains single-node signed headers as described in `docs/04_ledger_protocol.md`.
- Treat the dashboard quorum as an operational visibility tool for federation rollouts, not as a replacement for the Phase 1+ guardian consensus protocol.

---

## 7. Pre-commit Hooks

### Install Pre-commit

```bash
# Install pre-commit
pip install pre-commit

# Install git hooks
pre-commit install

# Run on all files (first time)
pre-commit run --all-files
```

### What Pre-commit Does

- Runs `ruff check --fix` (auto-fix linting issues)
- Runs `ruff format` (auto-format code)
- Fixes end-of-file issues
- Removes trailing whitespace
- Validates YAML and TOML files
- Checks for debug statements

---

## 8. CI/CD Local Replication

To replicate CI checks locally before pushing:

```bash
#!/bin/bash
# Save as check.sh and run: chmod +x check.sh && ./check.sh

set -e  # Exit on error

echo "🔍 Validating schemas..."
python tools/validate_schemas.py

echo "🔍 Running ruff linting..."
ruff check protocol/ storage/ api/ scaffolding/ tests/

echo "🔍 Running ruff format check..."
ruff format --check protocol/ storage/ api/ scaffolding/ tests/

echo "🔍 Running mypy type checking..."
mypy protocol/ storage/ api/

echo "🔍 Running bandit security scan..."
bandit -r protocol/ storage/ api/ scaffolding/ || true

echo "🔍 Running pytest (fast lane)..."
pytest tests/ -m "not postgres" \
  --cov=protocol --cov=storage --cov=api --cov=scaffolding \
  --cov-report=term-missing

echo "✅ All checks passed!"
```

---

## 9. Common Tasks

### Add a New Dependency

```bash
# Add to requirements.txt
echo "new-package>=1.0.0" >> requirements.txt

# Install
pip install -r requirements.txt

# For dev dependency
echo "new-dev-package>=1.0.0" >> requirements-dev.txt
pip install -r requirements-dev.txt
```

### Run Specific Protocol Tests

```bash
# Test canonicalization
pytest tests/test_canonical*.py -v

# Test hashing
pytest tests/test_hash*.py -v

# Test Merkle trees
pytest tests/test_merkle*.py -v

# Test ledger
pytest tests/test_ledger.py -v

# Test storage
pytest tests/test_storage.py -v -m postgres
```

### Debug Test Failures

```bash
# Run with full traceback
pytest tests/test_name.py -vv --tb=long

# Run with debugger (pdb)
pytest tests/test_name.py -vv --pdb

# Run single test function
pytest tests/test_name.py::test_function_name -vv

# Show print statements
pytest tests/test_name.py -vv -s
```

### Update Coverage Report

```bash
# Generate coverage report
pytest tests/ -m "not postgres" \
  --cov=protocol --cov=storage --cov=api --cov=app \
  --cov-report=html --cov-report=term-missing

# View in browser
open htmlcov/index.html
```

---

## 10. Troubleshooting

### "Cannot connect to database"

```bash
# Check if PostgreSQL is running
pg_isready -h localhost -p 5432

# macOS
brew services restart postgresql@16

# Linux
sudo systemctl status postgresql
sudo systemctl restart postgresql
```

### "Database olympus does not exist"

```bash
# Create database
createdb olympus

# Or with specific user
createdb -U postgres olympus
```

### "Permission denied for database"

```bash
# Grant permissions
psql postgres -c "ALTER USER yourusername CREATEDB;"

# Or create superuser
psql postgres -c "ALTER USER yourusername WITH SUPERUSER;"
```

### "Module not found"

```bash
# Ensure virtual environment is activated
source .venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt -r requirements-dev.txt
```

### Test failures

```bash
# Clear pytest cache
rm -rf .pytest_cache/

# Clear Python cache
find . -type d -name __pycache__ -exec rm -rf {} +
find . -type f -name "*.pyc" -delete

# Reinstall and rerun
pip install -r requirements.txt -r requirements-dev.txt
pytest tests/ -v
```

---

## 11. Zero-Knowledge Proof Setup (Groth16 Ceremony)

Olympus uses Circom circuits with Groth16 proofs for cryptographic verifiability.
The ZK tooling lives under `proofs/`.

### Prerequisites

- **Node.js ≥ 18** and **npm**
- **circom compiler** — install from https://docs.circom.io/getting-started/installation/
  or via `cargo install circom` (Rust required)

### Run the full Groth16 setup ceremony

```bash
# From repo root — install npm deps, compile circuits, generate dev keys
./tools/groth16_setup.sh
```

This single command:
1. Installs npm dependencies (`snarkjs`, `circomlib`, `circomlibjs`)
2. Downloads the Hermez Powers of Tau file (2^17, ~130K constraints)
   — falls back to generating locally if the download is unavailable
3. Compiles all three main circuits to R1CS + WASM
4. Runs Groth16 Phase 2 setup with a single dev contribution
5. Exports verification keys to `proofs/keys/verification_keys/`

Alternatively, use the npm scripts from the `proofs/` directory:

```bash
cd proofs/
npm install

# Compile circuits only (R1CS + WASM, no keys)
npm run circom:build

# Full Groth16 setup (Phase 1 + Phase 2 + key export)
npm run groth16:setup
```

### Output artifacts

| Artifact | Path | Committed? |
|---|---|---|
| R1CS constraint system | `proofs/build/<circuit>.r1cs` | No (build artifact) |
| WASM witness generator | `proofs/build/<circuit>_js/` | No (build artifact) |
| Proving key (zkey) | `proofs/build/<circuit>_final.zkey` | No (contains toxic waste) |
| Verification key | `proofs/keys/verification_keys/<circuit>_vkey.json` | Yes (public artifact) |

### Security notes

- Dev keys use a **single contribution** and are NOT suitable for production.
- Production requires a Phase 2 ceremony with ≥ 3 independent contributors
  and publicly published ceremony transcript.
- The proving key (`.zkey`) contains toxic waste from the setup; do not share it.
- No private randomness or secrets are checked into the repository.

### Production ceremony infrastructure

For production deployments, use the ceremony infrastructure in `ceremony/`:

```bash
# Verify a ceremony transcript
python -m ceremony.verification_tools.verify_ceremony --production ceremony/transcript/<id>.json

# Output verification result as JSON
python -m ceremony.verification_tools.verify_ceremony --json ceremony/transcript/<id>.json
```

The ceremony verification tools check:
- Chain integrity (each contribution builds on the previous)
- Signature validity (all contributions are properly signed)
- Beacon binding (randomness anchored to drand beacon)
- Hash consistency (all hashes match their computed values)
- Minimum contributor requirements (≥3 per phase for production)

See `ceremony/README.md` for full ceremony documentation.

### Smoke test (prove + verify)

After running the setup, validate everything works end-to-end:

```bash
cd proofs/ && npm run smoke
```

See `proofs/README.md` for full circuit documentation.

---

## 12. Next Steps

1. **Read the documentation**: Start with `README.md` and `docs/00_overview.md`
2. **Explore the protocol**: Check `protocol/` for core primitives
3. **Run examples**: See `examples/` for usage patterns and the new walkthrough notebooks (`*.ipynb`)
4. **Review tests**: `tests/` shows expected behavior
5. **Read CONTRIBUTING.md**: Development guidelines and workflow
6. **Review ASSESSMENT.md**: Repository health and improvement roadmap

---

## 13. Resources

- **Repository**: https://github.com/wombatvagina69-crypto/Olympus
- **Documentation**: `docs/` directory
- **Protocol Specs**: `docs/00_overview.md` → `docs/07_*.md`
- **API Docs** (when running): http://localhost:8000/docs
- **Coverage Reports**: `htmlcov/index.html` (after running tests)

---

## 14. Quick Reference Card

```bash
# Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# Lint & format
ruff check . --fix && ruff format .

# Type check
mypy protocol/ storage/ api/

# Test
pytest tests/ -v

# Coverage
pytest --cov=protocol --cov=scaffolding

# Security
bandit -r protocol/ storage/ api/ scaffolding/

# Run app
uvicorn api.app:app --reload

# Docker
docker compose up -d
```

---

**Happy coding! 🚀**

### Unified check command

Run the full local check suite (schemas, lint/format, mypy, pytest fast lane, pytest postgres). Set `DOCKER_BUILD=1` to include the optional Docker build.

```bash
make check
# Optional Docker build
DOCKER_BUILD=1 make check
```
