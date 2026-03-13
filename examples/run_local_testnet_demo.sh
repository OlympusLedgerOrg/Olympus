#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$repo_root/docker-compose.federation.yml"
sample_file="$repo_root/examples/pipeline_golden_example.json"

cleanup() {
  docker compose -f "$compose_file" down -v >/dev/null 2>&1 || true
}

trap cleanup EXIT

echo "[olympus-demo] Starting three-node federation demo..."
docker compose -f "$compose_file" up -d --build

echo "[olympus-demo] Waiting for node1 to report healthy..."
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:8001/health >/dev/null; then
    break
  fi
  sleep 2
done

echo "[olympus-demo] Federation status"
python "$repo_root/tools/olympus.py" federation status --registry "$repo_root/examples/federation_registry.json"

echo "[olympus-demo] Running end-to-end ingest/verify against node1"
python "$repo_root/tools/olympus.py" ingest "$sample_file" \
  --api-url http://127.0.0.1:8001 \
  --api-key demo-key \
  --namespace local-testnet \
  --id pipeline-golden-example \
  --generate-proof \
  --verify \
  --json
