# Contributing to Olympus

Thank you for your interest in contributing to Olympus!

This guide explains how to set up your development environment and run tests.

---

## Development Environment Setup

### Prerequisites

- **Python 3.12+**
- **PostgreSQL 16+** (required for development and E2E tests)

### Installing PostgreSQL

**macOS (Homebrew):**
```bash
brew install postgresql@16
brew services start postgresql@16
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install postgresql-16
sudo systemctl start postgresql
```

**Windows:**
Download and install from [postgresql.org](https://www.postgresql.org/download/windows/)

### Creating the Database

```bash
# Create the development database
createdb olympus

# Create a test database (optional, for isolation)
createdb olympus_test
```

### Setting Environment Variables

```bash
# Development database
export DATABASE_URL='postgresql://yourusername@localhost:5432/olympus'

# Test database (optional, defaults to same as DATABASE_URL)
export TEST_DATABASE_URL='postgresql://yourusername@localhost:5432/olympus_test'
```

**Note**: Replace `yourusername` with your PostgreSQL username. If you set a password, use:
```
postgresql://username:password@localhost:5432/olympus
```

### Installing Python Dependencies

```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies (includes pytest, ruff, mypy)
pip install -r requirements-dev.txt
```

### Initializing the Database Schema

```bash
python -c "from storage.postgres import StorageLayer; StorageLayer('$DATABASE_URL').init_schema()"
```

---

## Running Tests

### Database Strategy

Olympus uses two different databases for testing (see `docs/08_database_strategy.md`):

- **PostgreSQL**: For E2E tests and storage layer tests
- **SQLite**: Only for lightweight API proof logic tests

### Running All Tests

```bash
pytest tests/ -v
```

This will:
1. Run E2E tests against PostgreSQL (requires `TEST_DATABASE_URL`)
2. Run storage tests against PostgreSQL
3. Run API proof tests against temporary SQLite databases

### Running Specific Test Suites

```bash
# E2E audit tests (requires PostgreSQL)
pytest tests/test_e2e_audit.py -v

# Storage layer tests (requires PostgreSQL)
pytest tests/test_storage.py -v

# API proof tests (uses SQLite automatically)
pytest tests/test_api_proofs.py -v

# Protocol tests (no database required)
pytest tests/test_canonicalization.py tests/test_hash_functions.py -v
```

---

## Code Quality

### Linting

We use [ruff](https://docs.astral.sh/ruff/) for linting:

```bash
ruff check protocol/ storage/ api/ app/ tests/
```

### Type Checking

We use [mypy](https://mypy.readthedocs.io/) for static type checking:

```bash
mypy protocol/ storage/ api/
```

### Pre-commit Checks

Before committing, ensure:

1. All tests pass: `pytest tests/ -v`
2. No linting errors: `ruff check protocol/ storage/ api/ app/ tests/`
3. No type errors: `mypy protocol/ storage/ api/`

---

## Database Guidelines for Contributors

### When to Use PostgreSQL

Use PostgreSQL when:
- Implementing storage layer features (`storage/postgres.py`)
- Testing ledger chain logic
- Testing concurrent access patterns
- Running end-to-end audit flows
- Developing any feature that requires persistence

### When SQLite is Acceptable

SQLite is **only** acceptable for:
- Testing proof generation logic (`protocol/ssmf.py`)
- Testing API endpoint response formats (not storage behavior)
- **Never for production code**

**Rule of thumb**: If your code imports `storage.postgres`, use PostgreSQL for testing.

---

## Common Issues

### "Cannot connect to database"

**Solution**: Ensure PostgreSQL is running:
```bash
# macOS
brew services restart postgresql@16

# Linux
sudo systemctl status postgresql
```

### "Database does not exist"

**Solution**: Create the database:
```bash
createdb olympus
```

### "Permission denied for database"

**Solution**: Grant yourself permissions:
```bash
psql postgres -c "ALTER USER yourusername CREATEDB;"
```

### Test failures in CI but not locally

**Possible cause**: CI uses PostgreSQL 16 with specific settings. Ensure your local PostgreSQL version matches (16+).

---

## Documentation

### Writing Documentation

- Protocol documentation lives in `docs/`
- Use numbered prefixes for ordered reading (e.g., `00_overview.md`)
- Be precise and technical; avoid marketing language
- Focus on cryptographic guarantees

### Updating Documentation

When adding features:
1. Update relevant protocol docs in `docs/`
2. Add examples if introducing new APIs
3. Update `README.md` if changing setup procedures
4. Update this `CONTRIBUTING.md` if changing dev workflow

---

## Questions?

For questions about:
- **Database setup**: See `docs/08_database_strategy.md`
- **Protocol semantics**: See `docs/00_overview.md`
- **Testing strategy**: See `docs/PHASE_05.md`

---

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (see `LICENSE`).
