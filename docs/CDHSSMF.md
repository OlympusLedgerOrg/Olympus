# CDHSSMF: Constant-Depth Hierarchical Sparse Sharded Merkle Forest

## Overview

CDHSSMF is the cryptographic commitment layer for Olympus that **replaces the dual-tree design** (separate per-shard SMTs + forest SMT) with a **single global Sparse Merkle Tree (SMT)** using hierarchical key derivation.

## Design Rationale

### Problem: Dual-Tree Complexity

The original SSMF design had:
- **Shard SMTs**: One 256-level sparse Merkle tree per shard (`shard_id`), keyed by `record_key`
- **Forest SMT**: A second independent 256-level SMT mapping `forest_key = blake3(FOREST_PREFIX || shard_id)` → `shard_root`

Every append required:
- 256-level walk in the shard SMT
- 256-level walk in the forest SMT
- Two sets of node deltas to keep consistent
- Complex concurrency logic to maintain both trees atomically

Bugs involving tree divergence (where shard tree and forest tree became inconsistent) were a symptom of keeping **two separate authenticated structures** consistent under concurrency.

### Solution: Hierarchical Key Derivation

CDHSSMF **collapses the hierarchy into a single SMT** by pushing shard identity into the key space:

```
OLD: shard SMTs:   record_key  -> leaf in shard_i tree
     forest SMT:   shard_id    -> shard_root

NEW: global SMT:   global_key(shard_id, record_key) -> leaf
```

## Implementation

### Global Key Derivation

The `global_key()` function encodes shard identity into the SMT key space:

```python
def global_key(shard_id: str, record_key_bytes: bytes) -> bytes:
    """
    Generate a global SMT key for CDHSSMF.

    Encodes shard identity into the key space via:
    global_key = BLAKE3(KEY_PREFIX || shard_id || "|" || record_key)

    Returns: 32-byte global key
    """
```

### Key Properties

1. **Deterministic**: Same (shard_id, record_key) always produces same global_key
2. **Injective**: Different (shard_id, record_key) pairs produce different global_keys
3. **Cryptographic isolation**: Keys from different shards are cryptographically isolated (no predictable prefix patterns)
4. **Fixed size**: Always returns 32 bytes regardless of input lengths

### Database Schema

The global SMT is stored in two tables:

```sql
-- SMT Leaves: All records from all shards
CREATE TABLE smt_leaves (
    key BYTEA PRIMARY KEY,          -- 32-byte global key
    version INT NOT NULL,
    value_hash BYTEA NOT NULL,      -- 32-byte hash of value
    ts TIMESTAMPTZ NOT NULL
);

-- SMT Nodes: Internal nodes of the global tree
CREATE TABLE smt_nodes (
    level SMALLINT NOT NULL,        -- 0 = root, 255 = leaf level
    index BYTEA NOT NULL,           -- Path to node (packed bits)
    hash BYTEA NOT NULL,            -- 32-byte node hash
    ts TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (level, index)
);
```

**Note**: No `shard_id` column in either table. Shard identity is encoded in the key via `global_key()`.

### Append Operation

Before (dual-tree):
```python
# Load shard tree
shard_tree = load_tree(shard_id)
shard_tree.update(record_key, value_hash)
shard_root = shard_tree.get_root()

# Update forest tree
forest_tree = load_forest()
forest_tree.update(forest_key(shard_id), shard_root)
global_root = forest_tree.get_root()

# Persist both trees
persist(shard_tree)
persist(forest_tree)
```

After (CDHSSMF):
```python
# Load global tree
global_tree = load_tree()

# Generate global key
key = global_key(shard_id, record_key)

# Single tree update
global_tree.update(key, value_hash)
global_root = global_tree.get_root()

# Persist global tree
persist(global_tree)
```

## Benefits

### 1. Simpler Core

- **One SMT implementation**, one root
- No need to keep "shard tree" and "forest tree" synchronized
- Half the hash operations in the hot path (~256 instead of ~512)
- Only one node delta set per append

### 2. Fewer Failure Modes

The entire class of "two trees out of sync" bugs disappears by construction. Transactional correctness is just:
- "Did we apply this one delta for this one SMT path atomically?"

### 3. Better Concurrency

- No need for per-shard *and* global locking
- Only serialize on the global SMT's write path
- Concurrency conflicts are simpler to reason about

### 4. Logical Sharding Preserved

Shards still exist as first-class concepts:
- In API (shard_id parameter)
- In DB indexes (for efficient queries)
- In shard headers (signed commitments)

But cryptographically they're **namespacing** within a single SMT, not separate roots that must be reconciled.

## Migration

See `migrations/011_cdhssmf_global_smt.sql` for the database migration that:
1. Creates new `smt_leaves` and `smt_nodes` tables without `shard_id` columns
2. Migrates existing data (if any)
3. Drops old per-shard tables

## Backwards Compatibility

The following are **deprecated but kept for backwards compatibility**:

- `forest_root()` function in `protocol/hashes.py`
- `FOREST_PREFIX` constant
- `shard_id` parameter in `load_tree_state()` (should pass `None`)

These will be removed in a future protocol version bump.

## Testing

See `tests/test_cdhssmf.py` for comprehensive tests of:
- `global_key()` determinism and collision resistance
- Hierarchical namespace encoding
- Cryptographic isolation between shards

## Performance

Append operation performance:
- **Before**: ~512 BLAKE3 hash operations (256 for shard + 256 for forest)
- **After**: ~256 BLAKE3 hash operations (single global tree)
- **Speedup**: ~2x reduction in hash operations per append

Database operations:
- **Before**: 2 INSERT queries (shard_nodes + forest_nodes)
- **After**: 1 INSERT query (smt_nodes)

## Security Properties

1. **Tamper evidence**: Any change to any leaf in any shard changes the global root
2. **Append-only**: All tables are append-only (INSERT only, no UPDATE/DELETE)
3. **Cryptographic binding**: Global root cryptographically commits to all shards
4. **Proof size**: Fixed 8KB per proof regardless of tree size (256 × 32 bytes)
5. **Shard isolation**: Keys from different shards are cryptographically isolated

## References

- Problem statement: Issue describing dual-tree limitations
- Implementation: `protocol/hashes.py::global_key()`
- Storage layer: `storage/protocol_state.py`
- Tests: `tests/test_cdhssmf.py`
