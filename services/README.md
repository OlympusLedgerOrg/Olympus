# CD-HS-SMF Architecture Implementation

This directory contains the Phase 1 greenfield implementation of the Constant-Depth Hierarchical Sparse Sharded Merkle Forest (CD-HS-SMF) architecture.

## Overview

The CD-HS-SMF system consists of three layers:

1. **Rust Service** (`cdhs-smf-rust/`): Cryptographic core and SMT operations
2. **Go Sequencer** (`sequencer-go/`): Log service and storage orchestration
3. **Python API** (existing `api/`): High-level API, policy, orchestration

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  Python FastAPI (existing api/)                             │
│  - FOIA endpoints                                           │
│  - Dataset endpoints                                        │
│  - Policy & orchestration                                   │
└────────────────┬────────────────────────────────────────────┘
                 │ HTTP/gRPC
                 ▼
┌─────────────────────────────────────────────────────────────┐
│  Go Sequencer (sequencer-go/)                               │
│  - Trillian-shaped log API                                  │
│  - QueueLeaf, GetLatestRoot, GetInclusionProof              │
│  - Postgres persistence                                     │
└────────────────┬────────────────────────────────────────────┘
                 │ Protobuf over gRPC
                 ▼
┌─────────────────────────────────────────────────────────────┐
│  Rust CD-HS-SMF Service (cdhs-smf-rust/)                    │
│  - BLAKE3 hashing (domain-separated)                        │
│  - Composite key generation                                 │
│  - SMT update/prove operations                              │
│  - Ed25519 signing                                          │
│  - Canonicalization                                         │
└─────────────────────────────────────────────────────────────┘
```

## Key Design Principles

### 1. Single Global Tree

**NOT** separate per-shard trees plus a forest aggregator.

```
❌ OLD (TOCTOU issues):
  Shard Tree 1 → Forest Tree
  Shard Tree 2 → Forest Tree
  Shard Tree 3 → Forest Tree

✅ NEW (CD-HS-SMF):
  Global SMT with composite keys
  key = H(GLOBAL_KEY_PREFIX || shard_id || record_key)
```

### 2. Composite Key Scheme

All records are indexed by a composite key that includes both shard identity and record identity:

```rust
global_key = BLAKE3(
  "OLY:CDHS-SMF:GKEY:V1" ||
  shard_id ||               // e.g., "watauga:2025:budget"
  record_type ||            // e.g., "doc"
  record_id ||              // e.g., "12345"
  version ||                // e.g., "v1"
  sorted(metadata)          // deterministic metadata encoding
)
```

This ensures:
- Logical sharding by keyspace (not physical tree separation)
- No TOCTOU issues from separate tree roots
- Constant-depth proofs (always 256 siblings)

### 3. Clear Responsibility Boundaries

#### Rust Service

- **DOES**: All cryptographic operations
  - BLAKE3 hashing with domain separation
  - Composite key generation
  - SMT update/prove operations
  - Ed25519 signing
  - Canonicalization (JSON, text, etc.)
- **DOES NOT**: Persistence, batching, API serving

#### Go Sequencer

- **DOES**: Log orchestration and persistence
  - Batching and ordering appends
  - Calling Rust service for all crypto ops
  - Persisting SMT node deltas to Postgres
  - Serving Trillian-shaped HTTP/gRPC API
- **DOES NOT**: Computing hashes, implementing SMT logic

#### Python API

- **DOES**: High-level orchestration
  - FOIA/dataset API endpoints
  - Policy logic (retention, redaction rules)
  - Calling Go sequencer for append/proof queries
- **DOES NOT**: SMT logic, canonicalization, hash computation

### 4. Protobuf Wire Format

All communication between Go and Rust uses **protobuf** (NOT JSON):

```protobuf
service CdhsSmfService {
  rpc Update(UpdateRequest) returns (UpdateResponse);
  rpc ProveInclusion(ProveInclusionRequest) returns (ProveInclusionResponse);
  // ...
}
```

This avoids double-serialization when Go serves gRPC externally.

### 5. Domain Separation

All hashing uses BLAKE3 with clear domain separation:

```
GLOBAL_KEY_PREFIX  = "OLY:CDHS-SMF:GKEY:V1"
LEAF_HASH_PREFIX   = "OLY:SMT:LEAF:V1"
NODE_HASH_PREFIX   = "OLY:SMT:NODE:V1"
EMPTY_LEAF_PREFIX  = "OLY:EMPTY-LEAF:V1"
```

Leaf hashing:
```
leaf_hash = BLAKE3("OLY:SMT:LEAF:V1" || key || value_hash)
```

Node hashing:
```
node_hash = BLAKE3("OLY:SMT:NODE:V1" || left || right)
```

## Request Flow Example

### Appending a Record

```
1. Python API receives FOIA document upload
   POST /api/v1/documents

2. Python calls Go sequencer
   POST http://go-sequencer:8080/v1/queue-leaf
   {
     "shard_id": "watauga:2025:budget",
     "record_type": "doc",
     "record_id": "12345",
     "content": raw_doc,
     "content_type": "json"
   }

3. Go sequencer calls Rust service to canonicalize
   gRPC Canonicalize(content_type="json", content=raw_doc)
   → canonical_content

4. Go sequencer calls Rust service to update SMT
   gRPC Update(shard_id, record_key, canonical_content)
   → (new_root, global_key, deltas)

5. Go sequencer persists deltas to Postgres
   INSERT INTO cdhs_smf_nodes (path, level, hash)

6. Go sequencer calls Rust service to sign root
   gRPC SignRoot(root, context)
   → (signature, public_key)

7. Go sequencer persists signed root
   INSERT INTO cdhs_smf_roots (root_hash, signature)

8. Go sequencer returns to Python
   {
     "new_root": "abc123...",
     "global_key": "def456...",
     "tree_size": 42
   }

9. Python API stores document metadata, returns to client
```

### Generating an Inclusion Proof

```
1. Python API receives proof request
   GET /api/v1/proofs/doc/12345

2. Python calls Go sequencer
   GET http://go-sequencer:8080/v1/get-inclusion-proof?
       shard_id=watauga:2025:budget&
       record_type=doc&
       record_id=12345

3. Go sequencer calls Rust service
   gRPC ProveInclusion(shard_id, record_key, root=nil)
   → (global_key, value_hash, siblings[256], root)

4. Go sequencer returns proof to Python
   {
     "global_key": "abc...",
     "value_hash": "def...",
     "siblings": ["...", "..."],
     "root": "ghi..."
   }

5. Python API formats proof, returns to client
```

## Database Schema

The Go sequencer maintains two tables in Postgres:

```sql
-- Signed roots with timestamps
CREATE TABLE cdhs_smf_roots (
    id SERIAL PRIMARY KEY,
    root_hash BYTEA NOT NULL,        -- 32-byte BLAKE3 hash
    tree_size BIGINT NOT NULL,       -- Number of non-empty leaves
    signature BYTEA,                 -- Ed25519 signature (64 bytes)
    created_at TIMESTAMP NOT NULL
);

-- SMT node deltas (sparse storage)
CREATE TABLE cdhs_smf_nodes (
    path BYTEA NOT NULL,             -- 32-byte path
    level INTEGER NOT NULL,          -- 0-255
    hash BYTEA NOT NULL,             -- 32-byte node hash
    created_at TIMESTAMP NOT NULL,
    PRIMARY KEY (path, level)
);
```

**Important**: There are NO separate `smt_nodes` and `forest_nodes` tables. This is a single global tree.

## Poseidon / ZK Separation

The CD-HS-SMF uses **BLAKE3** in the operational layer.

Poseidon hashing is a **separate layer** for ZK witness generation:

```
Rust Service (optional endpoint):
  GeneratePoseidonWitness(canonical_content)
  → (poseidon_root, poseidon_path[256])

Ledger entries can store dual roots:
  {
    "root_b3": "...",         // CD-HS-SMF root (BLAKE3)
    "root_poseidon": "...",   // Redaction circuit root (Poseidon)
  }
```

This keeps ZK concerns logically separate from the operational SMT.

## Phasing

### Phase 0 (Pre-public blockers)

Already completed:
- ✅ Federation module decomposition
- ✅ Copilot instructions updated

Still needed:
- [ ] Groth16 trusted setup ceremony
- [ ] E2E CI integration test against real Postgres

### Phase 1 (Greenfield - this implementation)

- ✅ Protobuf definitions (`proto/cdhs_smf.proto`)
- ✅ Rust CD-HS-SMF service skeleton
- ✅ Go sequencer service skeleton
- [ ] Integration tests (Rust service)
- [ ] Integration tests (Go sequencer)
- [ ] Python client for Go sequencer

### Phase 2 (Post-public migration)

- [ ] Migrate existing Python SMT logic to use Go/Rust services
- [ ] Replace Python canonicalization with Rust service calls
- [ ] Halo2 backend (when circuits are stable)

## Current State

- **Existing Python API** (`api/`) continues to operate using `protocol/ssmf.py`
- **New Rust/Go services** are greenfield implementations that can coexist
- **No backward-compatibility migration** required for legacy data
- **Python reference implementation** (`protocol/ssmf.py`) remains valid

## Non-Goals (Guardrails)

This implementation MUST NOT:

- ❌ Reintroduce the old "two separate SMTs" pattern (per-shard + forest)
- ❌ Move canonicalization back into Python or Go
- ❌ Add new in-process FFI layers (Python↔Rust or Go↔Rust)
- ❌ Use JSON as the wire format between Go and Rust
- ❌ Attempt backward-compatibility migrations for legacy state
- ❌ Create separate `smt_nodes` vs `forest_nodes` tables
- ❌ Implement per-shard SMTs with a forest aggregator

## Building and Running

### Rust Service

```bash
cd services/cdhs-smf-rust
cargo build --release
cargo run --release
```

Service listens on `[::1]:50051`.

### Go Sequencer

```bash
cd services/sequencer-go
go build -o sequencer ./cmd/sequencer
./sequencer
```

Service listens on `:8080`.

### Integration Test

```bash
# Terminal 1: Start Rust service
cd services/cdhs-smf-rust
cargo run --release

# Terminal 2: Start Go sequencer
cd services/sequencer-go
./sequencer

# Terminal 3: Test with curl
curl -X POST http://localhost:8080/v1/queue-leaf \
  -H "Content-Type: application/json" \
  -d '{
    "shard_id": "test:shard",
    "record_type": "doc",
    "record_id": "12345",
    "content": "{\"hello\":\"world\"}",
    "content_type": "json"
  }'
```

## Further Reading

- `/proto/README.md`: Protobuf API documentation
- `/services/cdhs-smf-rust/README.md`: Rust service details
- `/services/sequencer-go/README.md`: Go sequencer details
- `/.github/copilot-instructions.md`: Full architecture guidance
