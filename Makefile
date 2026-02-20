.PHONY: check smoke dev

check:
	python tools/validate_schemas.py
	ruff check protocol/ storage/ api/ app/ tests/
	ruff format --check protocol/ storage/ api/ app/ tests/
	mypy protocol/ storage/ api/
	pytest tests/ -v --tb=short -m "not postgres" \
	  --cov=protocol --cov=app \
	  --cov-report=term-missing --cov-report=xml \
	  --cov-fail-under=85
	pytest tests/ -v --tb=short -m "postgres"
	@if [ -n "$(DOCKER_BUILD)" ]; then \
	docker build --target production -t olympus:prod .; \
	fi

smoke:
	bash tools/dev_smoke.sh

dev:
	DATABASE_URL=$${DATABASE_URL:-postgresql://olympus:olympus@localhost:5432/olympus} uvicorn api.app:app --host 127.0.0.1 --port 8000 & \
	UI_API_BASE=http://127.0.0.1:8000 uvicorn ui.app:app --host 127.0.0.1 --port 8080
