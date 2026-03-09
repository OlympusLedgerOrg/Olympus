## smoke: Run PostgreSQL-backed integration smoke test
.PHONY: smoke dev federation-dev federation-down

smoke:
	bash tools/dev_smoke.sh

## dev: Start FastAPI (port 8000) + debug UI (port 8080)
dev:
	@set -e; \
	DATABASE_URL=$${DATABASE_URL:-postgresql://olympus:olympus@localhost:5432/olympus} uvicorn api.app:app --host 127.0.0.1 --port 8000 & \
	api_pid=$$!; \
	trap 'kill $$api_pid' EXIT INT TERM; \
	UI_API_BASE=http://127.0.0.1:8000 OLYMPUS_DEBUG_UI=true uvicorn ui.app:app --host 127.0.0.1 --port 8080

## federation-dev: Start local three-node federation via Docker Compose
federation-dev:
	docker compose -f docker-compose.federation.yml up -d

## federation-down: Stop local federation Docker Compose
federation-down:
	docker compose -f docker-compose.federation.yml down
