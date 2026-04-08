# CD-HS-ST Rust Service

Constant-Depth Hierarchical Sparse Tree service implemented in Rust.

## Architecture

This is a **standalone binary** that maintains a single global 256-level Sparse Merkle Tree with composite keys.

### Key Design Principles

1. **Single Global Tree**: NOT per-shard trees + forest aggregator
2. **Composite Keys**: `key = H(GLOBAL_KEY_PREFIX || shard_id || record_key)`
3. **BLAKE3 Hashing**: All cryptographic operations use BLAKE3 with domain separation
4. **Protobuf API**: Exposes gRPC service over local socket (not FFI)
5. **Stateless Service**: Tree state is managed in-memory; persistence handled by Go sequencer

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run --release
```

The service will listen on the Unix domain socket from `CDHS_SMF_SOCKET`,
defaulting to `/run/olympus/cdhs-smf.sock`.

## Testing

```bash
cargo test
```

## API

The service exposes the following gRPC methods:

- `Update(shard_id, record_key, canonical_content) -> (new_root, global_key, deltas)`
- `ProveInclusion(shard_id, record_key, root?) -> (global_key, value_hash, siblings, root)`
- `VerifyInclusion(global_key, value_hash, siblings, root) -> bool`
- `ProveNonInclusion(shard_id, record_key, root?) -> (global_key, siblings, root)`
- `VerifyNonInclusion(global_key, siblings, root) -> bool`
- `Canonicalize(content_type, content) -> (canonical_content, content_hash)`
- `GetRoot() -> (root, tree_size)`
- `SignRoot(root, context) -> (signature, public_key)`

## Module Structure

- `main.rs`: gRPC service implementation and server setup
- `crypto.rs`: BLAKE3 hashing, composite key generation, Ed25519 signing
- `smt.rs`: Sparse Merkle Tree implementation
- `canonicalization.rs`: Content canonicalization (JSON, text)
- `proto.rs`: Generated protobuf code (from build.rs)

## Domain Separation

All hashing uses BLAKE3 with clear domain separation:

```
GLOBAL_KEY_PREFIX = "OLY:CDHS-SMF:GKEY:V1"
LEAF_HASH_PREFIX = "OLY:SMT:LEAF:V1"
NODE_HASH_PREFIX = "OLY:SMT:NODE:V1"
EMPTY_LEAF_PREFIX = "OLY:EMPTY-LEAF:V1"
```

## Composite Key Format

Global keys are computed as:

```
global_key = BLAKE3(
  "OLY:CDHS-SMF:GKEY:V1" ||
  shard_id ||
  record_type ||
  record_id ||
  version ||
  sorted(metadata)
)
```

This ensures:
- Logical sharding by keyspace
- No TOCTOU issues from separate trees
- Constant-depth proofs (always 256 siblings)

## Client Usage

The primary client is the Go sequencer service. Example:

```go
client := NewCdhsSmfClient(conn)

resp, err := client.Update(ctx, &UpdateRequest{
    ShardId: "watauga:2025:budget",
    RecordKey: &RecordKey{
        RecordType: "doc",
        RecordId: "12345",
        Version: "v1",
    },
    CanonicalContent: canonicalBytes,
})

// resp.NewRoot - persist this to DB
// resp.Deltas - persist these SMT nodes to DB
```

## Non-Goals (DO NOT IMPLEMENT)

- ❌ Per-shard SMTs with forest aggregation
- ❌ Separate `smt_nodes` and `forest_nodes` tables
- ❌ FFI/PyO3 bindings (use gRPC instead)
- ❌ JSON wire format (protobuf only)
- ❌ Persistent storage (Go sequencer handles this)
- ❌ Poseidon hashing (separate layer)

## Phasing

This is **Phase 1** work (greenfield implementation). It does NOT:
- Replace existing Python SMT (`protocol/ssmf.py` remains as reference)
- Require migration of existing data
- Block Phase 0 pre-public work
