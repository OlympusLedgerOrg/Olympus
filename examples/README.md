# Olympus runnable examples

This directory now includes runnable examples for the main integration paths:

- `python examples/e2e_ingest_demo.py examples/pipeline_golden_example.json --api-url http://127.0.0.1:8000 --api-key demo-key`
  commits a local artifact, retrieves the generated proof bundle, and verifies it
  through the REST API.
- `bash examples/run_local_testnet_demo.sh`
  starts the existing Dockerized three-node federation demo defined in
  `docker-compose.federation.yml`, waits for the nodes to become healthy, and
  runs an end-to-end ingest/verify flow against node 1.
- `node -e "const { OlympusClient } = require('./verifiers/javascript/client'); ..."`
  can be used from web or Node.js applications to drive the same REST workflow.

The scripts intentionally use the existing `Dockerfile`, `docker-compose.federation.yml`,
and `tools/olympus.py` entrypoints so the examples stay close to the production path.
The federation Docker demo provisions a long-lived `demo-key` API credential for
local-only workflows.
