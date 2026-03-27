## check: Run full quality gate (lint + type-check + bandit + tests)
.PHONY: check format lint boundary-check vectors check-demo-keys

check: boundary-check check-demo-keys
	python tools/validate_schemas.py
	ruff check protocol/ storage/ api/ scaffolding/ tests/
	ruff format --check protocol/ storage/ api/ scaffolding/ tests/
	mypy protocol/ storage/ api/
	bandit -r protocol/ storage/ api/ scaffolding/ -f txt
	pytest tests/ -v --tb=short -m "not postgres" \
	  --cov=protocol --cov=scaffolding --cov=storage --cov=api \
	  --cov-report=term-missing --cov-report=xml \
	  --cov-fail-under=85
	pytest tests/ -v --tb=short -m "postgres"
	@if [ -n "$(DOCKER_BUILD)" ]; then \
	docker build --target production -t olympus:prod .; \
	fi

## format: Auto-format code with Ruff
format:
	ruff format protocol/ storage/ api/ scaffolding/ tests/
	ruff check --fix protocol/ storage/ api/ scaffolding/ tests/

## lint: Run Ruff + mypy + bandit (no tests)
lint:
	ruff check protocol/ storage/ api/ scaffolding/ tests/
	ruff format --check protocol/ storage/ api/ scaffolding/ tests/
	mypy protocol/ storage/ api/
	bandit -r protocol/ storage/ api/ scaffolding/ -f txt

## boundary-check: Verify protocol module import boundaries are intact
boundary-check:
	python tools/check_import_boundaries.py

## vectors: Verify golden test vectors deterministically
vectors:
	pytest tests/test_golden_values.py tests/test_canonicalizer_vectors.py \
	  -v --tb=short

## check-demo-keys: Reject hardcoded demo API key hashes in source
check-demo-keys:
	@if grep -r --include='*.yml' --include='*.yaml' \
	  -e 'demo-key' \
	  -e '84d53ce2f18ae4856edfe631810f984b8c78bf3c0e136bac89e45642c5c85b37' \
	  -e 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3' \
	  . 2>/dev/null; then \
	  echo "ERROR: Hardcoded demo key detected in source"; exit 1; \
	fi
