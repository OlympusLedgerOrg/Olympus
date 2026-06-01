# Protocol Buffer Definitions

> **Status: legacy / vestigial.** These `.proto` files date from the
> multi-process design (Rust SMT service ↔ Go sequencer) that was **retired in
> v0.9.0**. In the current Tauri desktop, the SMT runs **in-process** inside the
> Rust binary — there is no separate Go sequencer and no socket/gRPC boundary at
> runtime. The CD-HS-ST contract below is preserved here as a protocol
> specification (operation shapes, domain separation), not as a live service
> API. There is no Go code in the repository.

This directory contains the protobuf definitions that historically described
inter-service communication in Olympus.

## CD-HS-ST Service API

The `cdhs_smf.proto` file defines the API for the Constant-Depth Hierarchical Sparse Tree (CD-HS-ST) service.

### Architecture (model preserved from the spec)

The CD-HS-ST logic — now embedded in the Tauri Rust binary rather than a
standalone service — :

- Maintains a single global 256-level Sparse Merkle Tree
- Uses composite keys: `H(GLOBAL_KEY_PREFIX || shard_id || record_key)`
- Handles all cryptographic operations (BLAKE3 hashing, Ed25519 signing)
- Is the sole authority for hashing (no untrusted client computes hashes)

In v0.9.x this is invoked **in-process** from the Axum handlers in
`src-tauri/src/api/` and the SMT code in `src-tauri/src/smt/`; the
socket/gRPC transport described by these protos is not used at runtime.

### Historical clients

The original design had a **Go sequencer service** as the primary client (batch
+ order appends, persist node deltas to Postgres, expose a Trillian-shaped log
API). That service was retired in v0.9.0; its responsibilities now live inside
the Rust binary.

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
