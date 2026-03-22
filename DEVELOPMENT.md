# Development Guide

This guide covers common development workflows for the Olympus project.

## Prerequisites

- Python 3.10 or higher (3.12 recommended)
- PostgreSQL 16+ (for database-dependent tests and API)
- Docker and Docker Compose (optional, for running PostgreSQL)

## Initial Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/wombatvagina69-crypto/Olympus.git
   cd Olympus
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

   Key environment variables:

   | Variable | Required | Description |
   |---|---|---|
   | `DATABASE_URL` | Yes (API/DB tests) | PostgreSQL connection string |
   | `TEST_DATABASE_URL` | No | Separate connection string for test runs |
   | `LOG_LEVEL` | No | Python log level (`DEBUG`, `INFO`, …) |
   | `OLYMPUS_DEBUG_UI` | No | Deprecated — debug UI is now always enabled. No longer required. |
   | `OLYMPUS_HALO2_ENABLED` | No | Set to `true` to enable the Halo2 proof backend. **Intentionally a no-op in v1.0** — Halo2 support is planned for Phase 1+. The flag exists so deployment tooling can reference it before the backend ships. |

5. **Start PostgreSQL** (if using Docker)
   ```bash
   docker compose up -d
   ```

6. **Apply database migrations**
   ```bash
   python -m alembic upgrade head
   ```

## Running Tests

### Run all tests
```bash
pytest tests/ -v
```

### Run tests without PostgreSQL
```bash
pytest tests/ -v -m "not postgres"
```

### Run tests with coverage
```bash
pytest tests/ -v --cov=protocol --cov=storage --cov=api --cov-report=term-missing
```

### Run specific test file
```bash
pytest tests/test_canonical_json.py -v
```

### Run specific test
```bash
pytest tests/test_canonical_json.py::test_canonical_json_encode -v
```

## Benchmarks

```bash
# Merkle proof generation timing
python benchmarks/bench_proofs.py

# Groth16 proof generation + circuit metrics (requires snarkjs + circuits)
python benchmarks/bench_zk_proofs.py

# Canonicalization throughput (PDF normalization)
python benchmarks/bench_canonicalizer.py --copies 8 --workers 4
```

## Code Quality Checks

### Run all checks (as done in CI)
```bash
make check
```

This runs:
- Schema validation
- Ruff linter and formatter
- MyPy type checker
- Bandit security scanner
- Full test suite with coverage

### Individual checks

**Validate JSON schemas:**
```bash
python tools/validate_schemas.py
```

**Lint and format code:**
```bash
ruff check protocol/ storage/ api/ scaffolding/ tests/
ruff format protocol/ storage/ api/ scaffolding/ tests/
```

**Type checking:**
```bash
mypy protocol/ storage/ api/
```

**Security scanning:**
```bash
bandit -r protocol/ storage/ api/ scaffolding/ -f txt
```

## Running the Application

### Run the API server
```bash
# Make sure PostgreSQL is running and DATABASE_URL is set
uvicorn api.app:app --host 127.0.0.1 --port 8000 --reload
```

### Run the UI
```bash
# In a separate terminal
UI_API_BASE=http://127.0.0.1:8000 uvicorn ui.app:app --host 127.0.0.1 --port 8080
```

### Run both API and UI together
```bash
make dev
```

## Development Workflows

### Adding a new feature

1. Create a feature branch
   ```bash
   git checkout -b feature/my-feature
   ```

2. Implement your changes following the coding conventions

3. Add or update tests
   ```bash
   pytest tests/ -v
   ```

4. Run code quality checks
   ```bash
   make check
   ```

5. Commit your changes
   ```bash
   git add .
   git commit -m "Add feature: description"
   ```

6. Push and create a pull request

### Fixing a bug

1. Write a failing test that demonstrates the bug
2. Fix the bug
3. Verify the test now passes
4. Run full test suite
5. Submit pull request with test and fix

### Updating dependencies

1. Update version in `requirements.txt` or `requirements-dev.txt`
2. Install updated dependencies
   ```bash
   pip install -r requirements.txt -r requirements-dev.txt
   ```
3. Run full test suite to ensure compatibility
4. Update `pyproject.toml` if needed

## Release / Supply-Chain Hygiene

- CI generates a CycloneDX SBOM and runs `pip-audit` with a baseline allowlist.
- Record dependency changes in `requirements.txt` and `requirements-dev.txt`.
- **If publishing Docker images**, sign them with `cosign` and publish the
  signature alongside the image tag.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes (API/DB tests) | PostgreSQL connection string |
| `TEST_DATABASE_URL` | No | Separate connection string for test runs |
| `LOG_LEVEL` | No | Python log level (`DEBUG`, `INFO`, …) |
| `OLYMPUS_DEBUG_UI` | No | Deprecated — debug UI is now always enabled. No longer required. |
| `OLYMPUS_HALO2_ENABLED` | No | Set to `true` to enable the Halo2 proof backend. **Intentionally a no-op in v1.0** — Halo2 support is planned for Phase 1+. The flag exists so deployment tooling can reference it before the backend ships. |

## Debugging

### Enable debug logging
```bash
export LOG_LEVEL=DEBUG
```

### Use Python debugger
```python
import pdb; pdb.set_trace()  # Add breakpoint in code
```

### Debug failing tests
```bash
pytest tests/test_file.py -vvs --tb=long
```

### Check database state
```bash
psql postgresql://olympus:olympus@localhost:5432/olympus
```

## Common Issues

### PostgreSQL connection errors
- Ensure PostgreSQL is running: `docker compose ps`
- Check connection string in `.env`
- Verify credentials: `olympus:olympus` (default)

### Import errors
- Ensure virtual environment is activated
- Reinstall dependencies: `pip install -r requirements.txt -r requirements-dev.txt`

### Test failures
- Check if PostgreSQL is required but not running
- Use `-m "not postgres"` to skip database tests
- Check for conflicting environment variables

### Type errors (mypy)
- Add type hints to function signatures
- Use `# type: ignore` sparingly and with justification
- Consult `pyproject.toml` for mypy configuration

## IDE Setup

### VS Code
The repository includes `.vscode/settings.json` with recommended settings:
- Python interpreter: `.venv/bin/python`
- Ruff extension for linting and formatting
- MyPy extension for type checking

### PyCharm
1. Set Python interpreter to `.venv/bin/python`
2. Enable Ruff as external tool
3. Configure test runner to use pytest

## Documentation

### Update documentation
When making changes, update relevant documentation:
- `docs/` for protocol specifications
- `README.md` for high-level overview
- Docstrings in code for API documentation

### Generate documentation
```bash
# API documentation is in docstrings
# View with: python -m pydoc protocol.canonical_json
```

## CI/CD

The project uses GitHub Actions for continuous integration:
- `.github/workflows/ci.yml` - Main CI pipeline
- Runs on every push and pull request
- Must pass before merging

## Additional Resources

- [README.md](README.md) - Project overview
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [SECURITY.md](SECURITY.md) - Security policy
- [threat-model.md](threat-model.md) - Threat model
- [docs/](docs/) - Protocol specifications
