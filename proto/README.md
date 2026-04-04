# Protocol Buffer Definitions

This directory contains the protobuf definitions for inter-service communication in Olympus.

## CD-HS-ST Service API

The `cdhs_smf.proto` file defines the API for the Constant-Depth Hierarchical Sparse Tree (CD-HS-ST) service.

### Architecture

The CD-HS-ST service is a **Rust standalone binary** that:

- Maintains a single global 256-level Sparse Merkle Tree
- Uses composite keys: `H(GLOBAL_KEY_PREFIX || shard_id || record_key)`
- Exposes a protobuf API over a local Unix domain socket
- Handles all cryptographic operations (BLAKE3 hashing, Ed25519 signing)
- Never trusts clients to compute hashes

### Clients

The primary client is the **Go sequencer service** which:

- Batches and orders record appends
- Calls the Rust service for all SMT operations
- Persists SMT node deltas to Postgres
- Exposes a Trillian-shaped log API (HTTP/gRPC)

### Generating Code

To generate Go code from the proto definitions:

```bash
cd proto
protoc --go_out=../sequencer --go_opt=paths=source_relative \
       --go-grpc_out=../sequencer --go-grpc_opt=paths=source_relative \
       cdhs_smf.proto
```

To generate Rust code (using tonic):

```bash
# Add to build.rs in the Rust service crate
```

### Key Operations

1. **Update**: Insert or update a record in the global SMT
   - Input: shard_id, record_key, canonical_content
   - Output: new_root, global_key, deltas

2. **ProveInclusion**: Generate cryptographic proof that a key exists
   - Input: shard_id, record_key, root (optional)
   - Output: global_key, value_hash, siblings[256], root

3. **ProveNonInclusion**: Generate proof that a key does not exist
   - Input: shard_id, record_key, root (optional)
   - Output: global_key, siblings[256], root

4. **Canonicalize**: Deterministically canonicalize content
   - Input: content_type, content
   - Output: canonical_content, content_hash

5. **SignRoot**: Sign a root hash with Ed25519
   - Input: root, context
   - Output: signature, public_key

### Domain Separation

All hashing uses BLAKE3 with domain separation:

- `GLOBAL_KEY_PREFIX = "OLY:CDHS-SMF:GKEY:V1"`
- Leaf hashes: `BLAKE3("OLY:SMT:LEAF:V1" || key || value_hash)`
- Node hashes: `BLAKE3("OLY:SMT:NODE:V1" || left || right)`
- Empty leaf: `BLAKE3("OLY:EMPTY-LEAF:V1")`

### Non-Goals

This API does NOT:

- Provide batch operations (sequencer batches multiple single updates)
- Store data persistently (that's the sequencer's job)
- Expose separate per-shard trees (single global tree only)
- Support forest-level operations (no hierarchical forest in Phase 1)
