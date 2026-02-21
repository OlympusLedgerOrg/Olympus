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

---

## 3. Verify Installation

```bash
# Validate schemas
python tools/validate_schemas.py

# Run linting
ruff check protocol/ storage/ api/ app_testonly/ tests/

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
ruff check protocol/ storage/ api/ app_testonly/ tests/

# Auto-fix issues
ruff check protocol/ storage/ api/ app_testonly/ tests/ --fix

# Format code
ruff format protocol/ storage/ api/ app_testonly/ tests/

# Check formatting (without changing)
ruff format --check protocol/ storage/ api/ app_testonly/ tests/
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
  --cov=protocol --cov=storage --cov=api --cov=app_testonly \
  --cov-report=term-missing --cov-report=html

# View coverage report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

### Security Scanning

```bash
# Run bandit security scan
bandit -r protocol/ storage/ api/ app_testonly/

# Generate baseline (optional)
bandit-baseline -r protocol/ storage/ api/ app_testonly/
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
  olympus:dev

# Production mode
docker run -d \
  -p 8000:8000 \
  -e DATABASE_URL='postgresql://olympus:olympus@host.docker.internal:5432/olympus' \
  --name olympus-app \
  olympus:prod

# View logs
docker logs -f olympus-app

# Stop container
docker stop olympus-app
docker rm olympus-app
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
ruff check protocol/ storage/ api/ app_testonly/ tests/

echo "🔍 Running ruff format check..."
ruff format --check protocol/ storage/ api/ app_testonly/ tests/

echo "🔍 Running mypy type checking..."
mypy protocol/ storage/ api/

echo "🔍 Running bandit security scan..."
bandit -r protocol/ storage/ api/ app_testonly/ || true

echo "🔍 Running pytest (fast lane)..."
pytest tests/ -m "not postgres" \
  --cov=protocol --cov=storage --cov=api --cov=app_testonly \
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

## 11. Next Steps

1. **Read the documentation**: Start with `README.md` and `docs/00_overview.md`
2. **Explore the protocol**: Check `protocol/` for core primitives
3. **Run examples**: See `examples/` for usage patterns
4. **Review tests**: `tests/` shows expected behavior
5. **Read CONTRIBUTING.md**: Development guidelines and workflow
6. **Review ASSESSMENT.md**: Repository health and improvement roadmap

---

## 12. Resources

- **Repository**: https://github.com/wombatvagina69-crypto/Olympus
- **Documentation**: `docs/` directory
- **Protocol Specs**: `docs/00_overview.md` → `docs/07_*.md`
- **API Docs** (when running): http://localhost:8000/docs
- **Coverage Reports**: `htmlcov/index.html` (after running tests)

---

## 13. Quick Reference Card

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
pytest --cov=protocol --cov=app_testonly

# Security
bandit -r protocol/ storage/ api/ app_testonly/

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
