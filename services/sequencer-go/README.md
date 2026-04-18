# Go Sequencer Service

Trillian-shaped log service that orchestrates the CD-HS-ST Rust service for append-only record logging.

## Architecture

This service provides a **Trillian-shaped HTTP/gRPC API** that:

1. Batches and orders record appends
2. Delegates all cryptographic operations to the Rust CD-HS-ST service
3. Persists SMT node deltas and signed roots to Postgres
4. Exposes a simple log API for clients (Python FastAPI, external verifiers)

### Key Principles

- **Go NEVER computes hashes**: All SMT operations delegated to Rust
- **Protobuf-only communication**: No JSON on the Go↔Rust boundary
- **Single global tree**: Not per-shard trees + forest
- **Stateless sequencer**: All state in Postgres or Rust service

## Building

```bash
go build -o sequencer ./cmd/sequencer
```

## Running

```bash
# Start Rust CD-HS-ST service first
cd ../cdhs-smf-rust
cargo run --release

# Then start Go sequencer
cd ../sequencer-go
./sequencer
```

The service will start on `:8080` by default.

## API Endpoints

### POST /v1/queue-leaf

Append a record to the log.

**Request:**
```json
{
  "shard_id": "watauga:2025:budget",
  "record_type": "doc",
  "record_id": "12345",
  "version": "v1",
  "content": "...",
  "content_type": "json"
}
```

**Response:**
```json
{
  "new_root": "abc123...",
  "global_key": "def456...",
  "leaf_value_hash": "789ghi...",
  "tree_size": 42
}
```

### GET /v1/get-latest-root

Get the current root hash and tree size.

**Response:**
```json
{
  "root": "abc123...",
  "tree_size": 42
}
```

### GET /v1/get-inclusion-proof

Generate an inclusion proof for a record.

**Query Parameters:**
- `shard_id`: Shard identifier
- `record_type`: Record type
- `record_id`: Record ID
- `version`: Record version (optional)

**Response:**
```json
{
  "global_key": "abc123...",
  "value_hash": "def456...",
  "siblings": ["...", "..."],
  "root": "789ghi..."
}
```

### GET /v1/get-signed-root-pair

Return the signed roots at two tree sizes for offline comparison.

> **Not** an RFC-6962 / Trillian consistency proof. This endpoint does not
> prove that the older root is a prefix of the newer one — it returns both
> signed roots and lets the caller verify the signatures and compare the
> hashes. The sequencer does not currently produce a real consistency
> proof; the CD-HS-ST is a sparse Merkle tree and the proof shape differs
> from RFC 6962. See the follow-up issue tracked from `CHANGELOG.md`.

**Query Parameters:**
- `old_tree_size`: smaller tree size
- `new_tree_size`: larger tree size (must be ≥ `old_tree_size`)

**Response:**
```json
{
  "old_tree_size": 100,
  "new_tree_size": 200,
  "old_root": "abc123...",
  "old_signature": "def456...",
  "new_root": "789ghi...",
  "new_signature": "jkl012..."
}
```

### GET /v1/get-consistency-proof (deprecated)

Returns HTTP `410 Gone` with a body pointing callers to
`/v1/get-signed-root-pair`. The original name was misleading: it suggested
an RFC-6962 consistency proof but only ever returned a pair of signed
roots. This deprecated alias will be removed in the next release.

## Internal Architecture

### Client Layer (`internal/client`)

Wraps the gRPC client for the Rust CD-HS-ST service. Provides Go-friendly API:

```go
client, err := client.NewCdhsSmfClient()

resp, err := client.Update(ctx, shardID, recordKey, canonicalContent)
// resp.NewRoot, resp.Deltas
```

### Storage Layer (`internal/storage`)

Handles Postgres persistence:

- `cdhs_smf_roots`: Stores (root_hash, tree_size, signature, created_at)
- `cdhs_smf_nodes`: Stores (path, level, hash, created_at)

### API Layer (`internal/api`)

Implements the Trillian-shaped HTTP API. Request flow:

1. Receive `QueueLeaf` request
2. Call Rust service to canonicalize content
3. Call Rust service to update SMT
4. Persist node deltas to Postgres
5. Call Rust service to sign new root
6. Persist signed root to Postgres
7. Return response to client

## Database Schema

```sql
CREATE TABLE cdhs_smf_roots (
    id SERIAL PRIMARY KEY,
    root_hash BYTEA NOT NULL,
    tree_size BIGINT NOT NULL,
    signature BYTEA,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE cdhs_smf_nodes (
    path BYTEA NOT NULL,
    level INTEGER NOT NULL,
    hash BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (path, level)
);
```

## Testing

```bash
go test ./...
```

## Non-Goals (DO NOT IMPLEMENT)

- ❌ Computing Merkle hashes in Go
- ❌ Separate `smt_nodes` and `forest_nodes` tables
- ❌ Per-shard SMTs with forest aggregation
- ❌ JSON wire format for Rust communication
- ❌ Replacing existing Python API (coexistence in Phase 1)

## Phasing

This is **Phase 1** greenfield work. It:
- Does NOT replace existing Python API (`api/` continues to operate)
- Does NOT require migration of existing data
- Does NOT block Phase 0 pre-public work
- CAN coexist with current Python implementation during Phase 1

## Client Usage (Python)

```python
import requests

# Queue a leaf
response = requests.post("http://localhost:8080/v1/queue-leaf", json={
    "shard_id": "watauga:2025:budget",
    "record_type": "doc",
    "record_id": "12345",
    "version": "v1",
    "content": canonical_doc,
    "content_type": "json"
})

new_root = response.json()["new_root"]

# Get inclusion proof
response = requests.get("http://localhost:8080/v1/get-inclusion-proof", params={
    "shard_id": "watauga:2025:budget",
    "record_type": "doc",
    "record_id": "12345",
    "version": "v1"
})

proof = response.json()
```
