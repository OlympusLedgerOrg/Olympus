# ADR-0001: Incremental / Paginated Tree Reconstruction

| Field       | Value                                       |
|-------------|---------------------------------------------|
| Status      | Accepted                                    |
| Date        | 2026-03-30                                  |
| Deciders    | Olympus maintainers                         |
| Relates to  | C1, C2, C3, H1 (security review findings)  |

## Context

The current implementation of `_load_tree_state()` (in both
`storage/postgres.py` and `storage/protocol_state.py`) performs a **full
`SELECT * FROM smt_leaves`** on every call, loading every leaf into memory
and replaying the entire Sparse Merkle Tree from scratch.  This is the root
cause of four open findings from the security review:

| ID | Title | Impact |
|----|-------|--------|
| **C1** | `POST /doc/verify` unbounded Merkle rebuild, no auth | Any unauthenticated caller can trigger a full in-memory tree rebuild via the verify endpoint. |
| **C2** | `GET /shards/{shard_id}/proof` full SMT load, no auth | Proof generation loads the entire global SMT to produce a single 256-sibling path. |
| **C3** | `_load_tree_state()` architecturally unbounded | The function has no pagination, streaming, or size limit; memory grows linearly with ledger size. |
| **H1** | `verify_state_replay` O(N²) | State replay recomputes the full tree at every checkpoint, yielding quadratic total work. |

A partial mitigation already exists in `api/services/verification.py` (a
`_MERKLE_LEAF_LIMIT = 50_000` cap on the SELECT), but this is a
band-aid — proof generation silently degrades to "unverified" once the
limit is hit, and the core `_load_tree_state()` path used by the storage
layer has no cap at all.

## Decision

We will replace the full-load-and-replay pattern with **incremental /
paginated tree reconstruction** using the persisted node store
(`smt_nodes`).

### Design

1. **Persisted intermediate nodes** — The `smt_nodes` table already stores
   internal SMT nodes keyed by `(level, index)` with a timestamp.  On every
   `append()` the Rust CD-HS-ST service (or, during Phase 0, the Python
   reference path) writes the delta of changed nodes.  This means the
   **current root and every intermediate hash are already in the database**
   and do not need to be recomputed from leaves.

2. **Proof generation without full load** — To produce an inclusion or
   non-inclusion proof for a single key, the service needs only the
   **256 sibling hashes** along the path from leaf to root.  These can be
   fetched with a single indexed query on `smt_nodes` rather than loading
   all leaves and rebuilding the tree.

3. **Root retrieval from the latest shard header** — The latest committed
   root is stored in the shard header (`root_hash`).  Endpoints that only
   need the current root (e.g. `GetLatestRoot`) should read it directly
   from `shard_headers` instead of recomputing it.

4. **Paginated historical replay** — For audit operations that must verify
   the tree at a historical timestamp (e.g. `verify_state_replay`), the
   replay should:
   - Fetch the stored root from the header at that timestamp.
   - If re-derivation is required, stream leaves in batches (e.g. 10 000)
     and update the in-memory tree incrementally, yielding periodically
     to avoid blocking the event loop.
   - Cache intermediate results across sequential checkpoints to eliminate
     the O(N²) behaviour: each checkpoint replays only the **delta** since
     the previous one.

5. **`_load_tree_state()` deprecation** — The function will be deprecated
   and replaced by purpose-specific helpers:
   - `get_proof_path(global_key) -> list[bytes]` — fetch 256 siblings.
   - `get_current_root() -> bytes` — read from latest header.
   - `replay_tree_incremental(from_ts, to_ts, batch_size)` — streaming
     rebuild for audit.

### Migration

- Phase 0: Add `get_proof_path()` and `get_current_root()` helpers to
  `StorageLayer`; wire them into the `/shards/{shard_id}/proof` and
  `/doc/verify` endpoints so they no longer call `_load_tree_state()`.
- Phase 1: The Rust CD-HS-ST service natively supports `prove_inclusion`
  and `get_root`; Go's sequencer calls these over protobuf, making the
  Python helpers unnecessary.
- Phase 2: Remove `_load_tree_state()` entirely once all callers have
  migrated.

## Consequences

- **C1/C2 resolved**: Proof endpoints fetch O(256) nodes instead of O(N)
  leaves, bounding memory and CPU regardless of ledger size.
- **C3 resolved**: The unbounded full-load function is removed from the
  hot path.
- **H1 resolved**: Replay becomes O(N) total (streaming with delta
  caching) instead of O(N²).
- **Trade-off**: The `smt_nodes` table must be kept consistent with
  `smt_leaves` on every write.  This is already the case for the existing
  `append()` implementation, so no new invariant is introduced.
- **Trade-off**: Historical proof generation for timestamps that predate
  the node-persistence change will still require a leaf replay.  This is
  acceptable because the node store has been populated since the initial
  schema.

## Alternatives Considered

1. **In-memory LRU cache of reconstructed trees** — Reduces repeated work
   but does not bound peak memory; a single cold miss still triggers a
   full rebuild.  Rejected.

2. **Materialized-view root in Postgres** — Keeps the root up to date via
   a trigger.  Solves root retrieval but not proof generation.  Partially
   adopted (root is already in `shard_headers`).

3. **Read-through Merkle cache (Redis / memcached)** — Adds an external
   dependency for a problem that can be solved with the existing
   `smt_nodes` table.  Rejected for Phase 0; may be revisited for
   horizontal scaling in Phase 2+.
