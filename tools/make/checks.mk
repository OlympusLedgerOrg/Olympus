## check: Run full quality gate (lint + type-check + bandit + tests)
.PHONY: check format lint boundary-check vectors

check: boundary-check
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
