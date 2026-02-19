#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

DATABASE_URL="${DATABASE_URL:-postgresql://olympus:olympus@localhost:5432/olympus}"
TEST_DATABASE_URL="${TEST_DATABASE_URL:-${DATABASE_URL}}"
export DATABASE_URL TEST_DATABASE_URL

docker compose up -d db
python -m pip install -r requirements-dev.txt
python -m pip install ruff
python -c "from storage.postgres import StorageLayer; StorageLayer('${DATABASE_URL}').init_schema()"
python -c "import api.app"
pytest tests/ -v --tb=short -m "postgres"
