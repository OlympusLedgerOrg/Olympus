# Olympus Development Readiness Checklist

## ✅ Quick Setup (Copy-Paste Commands)

```bash
# Clone and enter repository
git clone https://github.com/wombatvagina69-crypto/Olympus.git
cd Olympus

# Set up Python environment (Python 3.10+)
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install package in editable mode with dev dependencies
python -m pip install --upgrade pip
pip install -e ".[dev]"

# Verify installation
python -c "from protocol import hashes; print('✓ Protocol imports working')"
```

## 🔍 Pre-Commit Quality Gates

### 1. Code Linting & Formatting
```bash
# Check code quality (E, W, F, I, UP rules)
ruff check protocol/ storage/ api/ app_testonly/ tests/

# Auto-fix issues
ruff check protocol/ storage/ api/ app_testonly/ tests/ --fix

# Check formatting
ruff format --check protocol/ storage/ api/ app_testonly/ tests/

# Auto-format code
ruff format protocol/ storage/ api/ app_testonly/ tests/
```

### 2. Type Checking
```bash
# Run mypy on core modules
mypy protocol/ storage/ api/
```

### 3. Security Scanning
```bash
# Bandit security scan
bandit -r protocol/ storage/ api/ app_testonly/ -f txt

# Check dependencies for known vulnerabilities
pip-audit -r requirements.txt
```

### 4. Testing & Coverage

#### Fast Tests (No Database)
```bash
# Run non-postgres tests
pytest -q -m "not postgres"

# With coverage
pytest -q -m "not postgres" --cov=protocol --cov=storage --cov=api --cov=app --cov-report=term-missing
```

#### Full Test Suite (Requires PostgreSQL)
```bash
# Set up PostgreSQL locally (example with Docker)
docker run --name olympus-postgres -e POSTGRES_USER=olympus \
  -e POSTGRES_PASSWORD=olympus -e POSTGRES_DB=olympus \
  -p 5432:5432 -d postgres:16

# Export database URL
export TEST_DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'

# Run all tests
pytest -v

# Run postgres-only tests
pytest -v -m "postgres"
```

#### Coverage Report
```bash
# Generate coverage report
coverage run -m pytest -q -m "not postgres"
coverage report -m
coverage xml  # For CI integration
```

## 📊 Quality Targets

| Metric | Target |
|--------|--------|
| **Ruff Lint** | All checks pass (E, W, F, I, UP rules) |
| **Ruff Format** | Consistent style |
| **MyPy** | No type errors |
| **Tests (non-postgres)** | 100% pass rate |
| **Coverage** | ≥85% (CI floor) |
| **Security (Bandit)** | No high/critical findings |
| **Dependencies** | No known CVEs |

## 🐳 Docker Development

### Build and Run
```bash
# Development build
docker build --target development -t olympus:dev .
docker run -p 8000:8000 olympus:dev

# Production build
docker build --target production -t olympus:prod .
docker run -p 8000:8000 -e DATABASE_URL=postgresql://... olympus:prod
```

### With Docker Compose (if available)
```bash
docker-compose up
```

## 🔧 Pre-Commit Hooks (Optional)

```bash
# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run hooks manually
pre-commit run --all-files
```

## 📦 Build & Distribution

```bash
# Build distribution packages
pip install build
python -m build

# Verify package contents
tar tzf dist/olympus-*.tar.gz | head -20
```

## 🚀 CI/CD Integration

The GitHub Actions workflow automatically runs on push and PR:
- ✅ Ruff linting and formatting checks
- ✅ MyPy type checking
- ✅ Bandit security scanning
- ✅ Pytest with coverage (both SQLite and PostgreSQL)
- ✅ JSON schema validation

**Local CI simulation:**
```bash
# Run the full CI pipeline locally
python -m pip install --upgrade pip
pip install -e ".[dev]"
python tools/validate_schemas.py
ruff check protocol/ storage/ api/ app_testonly/ tests/
ruff format --check protocol/ storage/ api/ app_testonly/ tests/
mypy protocol/ storage/ api/
bandit -r protocol/ storage/ api/ app_testonly/ -f txt
pytest -q -m "not postgres" --cov=protocol --cov=storage --cov=api --cov=app_testonly
```

## 🔐 Security Best Practices

1. **Never commit secrets** - Use environment variables
2. **Review Bandit findings** - Current 2 minor issues are acceptable (dev defaults)
3. **Keep dependencies updated** - Run `pip-audit` regularly
4. **Follow SAST recommendations** - Address CodeQL findings if any

## 📝 Development Workflow

1. Create a feature branch
2. Make minimal, focused changes
3. Run quality checks locally (see above)
4. Ensure tests pass
5. Update documentation if needed
6. Submit PR with descriptive title and body

## 🎯 Quality Gate Summary

**Before committing:**
```bash
# One-liner quality check
ruff check . && ruff format --check . && mypy protocol/ storage/ api/ && pytest -q -m "not postgres"
```

**Before pushing:**
```bash
# Full quality check with coverage
ruff check . && ruff format --check . && mypy protocol/ storage/ api/ && \
pytest -q -m "not postgres" --cov=protocol --cov=storage --cov=api --cov=app_testonly --cov-report=term && \
bandit -r protocol/ storage/ api/ app_testonly/
```

## 📚 Additional Resources

- **Protocol Specs:** `docs/` directory
- **Architecture:** See `README.md` and `docs/`
- **Contributing:** See `CONTRIBUTING.md`

## ❓ FAQ

**Q: Why does `pip install -e .` fail?**  
A: Ensure setuptools >= 77.0.0. This is enforced in `pyproject.toml`.

**Q: Coverage is below 85%?**  
A: Run the full test suite including Postgres-marked tests (`pytest tests/ -v`) for complete coverage.

**Q: What about migrations?**  
A: `migrations/` is excluded from package distribution but can be included if needed for Alembic runtime.

**Q: Can I use Python 3.10 or 3.11?**  
A: Yes! The project supports Python 3.10, 3.11, and 3.12.

---
