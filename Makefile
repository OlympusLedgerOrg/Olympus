.PHONY: check

check:
	python tools/validate_schemas.py
	ruff check protocol/ storage/ api/ app/ tests/
	ruff format --check protocol/ storage/ api/ app/ tests/
	mypy protocol/ storage/ api/
	pytest tests/ -v --tb=short -m "not postgres" \
	  --cov=protocol --cov=app \
	  --cov-report=term-missing --cov-report=xml \
	  --cov-fail-under=80
	pytest tests/ -v --tb=short -m "postgres"
	@if [ -n "$(DOCKER_BUILD)" ]; then \
	docker build --target production -t olympus:prod .; \
	fi
