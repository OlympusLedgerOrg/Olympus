# ADR-0022: Lazy deep-node storage (persist-shallow, recompute-deep) for the persistent SMT

- **Status:** Accepted (decisions locked — see "Resolved decisions"); implementation pending
- **Date:** 2026-06-04
- **Supersedes / builds on:** ADR-0005 (structured leaf prefix + shard binding), migration `0043` (packed node bit-paths, PR #1172)
- **Evidence:** PR #1173 `smt_node_depth_histogram` measurement; round-trip + storage benchmarks (PR #1169)

## Context

The persistent SMT (`src-tauri/src/smt/`) materialises **every internal node** of the
256-deep tree into `smt_nodes`. Measurements show this dominates ledger storage:

- ~**185 internal nodes per leaf** (256 levels minus shared prefixes).
- Even after packed bit-paths (migration 0043, ~3.4× smaller keys), `smt_nodes`
  is still ~**27 KiB/leaf** on disk — ≈ **95%** of total ledger bytes, projecting
  to **~27 GB per million leaves**. `smt_leaves` is only ~220 B/leaf.

But **interior nodes are a pure function of the leaves** (`node_hash` folds over
child hashes; absent subtrees collapse to the precomputed empty-subtree hash).
So they need not all be stored. The depth-histogram measurement (PR #1173)
quantifies the win of persisting only the shallow nodes and recomputing the rest:

| leaves | full (packed) | hybrid `K=72` | reduction |
|---:|---:|---:|---:|
| 1 000 | 27.5 KiB/leaf | 606 B/leaf | 46× |
| 5 000 | 27.2 KiB/leaf | 327 B/leaf | 85× |

Crucially the persisted shallow-node set is **near-constant in N** (2.8k → 4.4k
nodes for 5× the leaves) while total nodes grow ~185×N — so the win **grows with
scale**, collapsing storage toward "just the leaves" (~0.3 GB/M).

A structural property of Olympus's sharding makes this especially clean: the
64-bit shard prefix (`SHARD_PREFIX_BITS = 64`) means depths `0..64` hold at most
one path per shard, so the shallow region is tiny regardless of leaf count; all
the per-leaf branching lives at depths `64..256` (within a shard's subtree).

## Decision

Persist only internal nodes with **`depth ≤ K`**; **recompute** any node deeper
than `K` on demand from the leaves beneath it. `K` is chosen to (a) keep every
per-shard subtree root persisted (so a proof never triggers an `O(N)` recompute
of a whole sibling shard) and (b) bound the leaves under any recomputed deep
sibling to a small constant.

### Choice of `K`

- `K` MUST be `≥ SHARD_PREFIX_BITS (64)`: the off-path siblings in the
  shard-prefix region are *other shards' subtree roots*; recomputing one means
  hashing that entire shard (`~N/#shards` leaves). Persisting `depth ≤ 64` keeps
  them as cheap PK probes.
- A within-shard margin `m` then sets the *expected* recompute size. The canopy
  rooted at `K = 64 + m` holds the leaves sharing a `(64+m)`-bit prefix; for a
  shard of `M` uniform-hash leaves that is `≈ M / 2^m` leaves **in expectation**
  — **not** a hard cap (`184 − m` key bits live below the canopy, so depth alone
  bounds nothing). The measurement used **`K = 72`** (`m = 8`), keeping the
  persisted set ~constant (a few thousand nodes total). What makes the *actual*
  canopy tiny is **prefix uniqueness, not the margin**: with uniform BLAKE3
  record keys (`olympus_crypto::record_key`), two leaves don't collide in their
  first 72 bits until ~`2^36` leaves (birthday bound), so below that scale every
  canopy is a **single leaf** and recompute folds one leaf up an empty chain.
- The pathological case — a canopy that grows large via 72-bit prefix collisions
  or non-hashed/adversarial record keys — is handled explicitly by a
  `CANOPY_RECOMPUTE_CAP`: if a canopy scan exceeds the cap, the read path stops
  folding and reads the persisted deep sibling nodes directly, keeping
  prove/update latency bounded for *any* key distribution. (The write path must
  therefore keep persisting deep nodes for over-cap canopies once lazy flushing
  lands — see Implementation plan.)
- `K` is a single named constant (`LAZY_DEPTH = 72`), co-located with
  `CACHE_DEPTH`. It is **not** operator-tunable in this ADR; the **persisted set
  is tied to `K`**, so any change is a migration-class event (see
  *Future reconsideration*).

### Read path (`prove` / `build_working_set`)

For each requested key, resolve the 256 siblings as today, except:
- siblings at `depth ≤ K`: fetched from cache/`smt_nodes` (unchanged);
- siblings at `depth > K`: **recomputed** — range-scan `smt_leaves` for the
  leaves under the sibling's prefix and fold them up to the sibling's depth using
  the canonical `leaf_hash`/`node_hash` and `empty_subtree_hash` for empty gaps.
  The leaf range is a contiguous PK scan: the tree key is `shard_prefix ‖ suffix`
  and `smt_leaves`'s PK is that 32-byte key, so leaves under a `d`-bit prefix are
  the half-open key range `[prefix‖0…, prefix‖1…)`. No new index is required
  (the existing PK B-tree is prefix-ordered); we will confirm with `EXPLAIN`.

`root()` and `shard_subtree_root()` are unaffected (root is `depth 0`; shard
roots are at `depth 64 ≤ K`, still persisted).

### Write path (`update_batch`)

`update_batch` already recomputes the full affected path in memory under the H-4
write lock. The only change: when flushing dirty nodes, **persist only those with
`depth ≤ K`**; discard deeper dirty nodes. Leaves are persisted unchanged. This
*reduces* write amplification (≈185 node upserts/leaf → a near-constant shallow
set) on top of the storage win.

### Correctness

This is physical-only: `path`/depth are addressing, never hashed, and recompute
uses the exact same `leaf_hash`/`node_hash`/`empty_subtree_hash` as the
in-memory reference. Therefore **roots and proofs are byte-identical** and the
offline verifiers are untouched. The in-memory `olympus_crypto::smt::SparseMerkleTree`
remains the oracle for parity tests.

## Consequences / trade-offs

- **Storage:** `smt_nodes` collapses from ~185 nodes/leaf to a near-constant
  shallow set → ~50–100× smaller, improving with scale (~27 GB/M → ~0.3 GB/M).
- **CPU (the cost):** `prove` and the per-batch recompute do extra
  leaf-range-scans + in-memory folding for the deep portion. For uniform-hash
  keys the canopy is a single leaf, so the deep fold is ~`O(184)` hashes; the top
  `K` levels stay cached, so proofs remain ~`O(256)` rather than `O(N)`. The
  worst case (a large canopy) is bounded by `CANOPY_RECOMPUTE_CAP`: past the cap
  the read path reads persisted deep nodes instead of folding, so latency never
  scales with canopy size. Expected: low-ms proofs vs today's ~1 ms; to be
  measured and gated (see Validation).
- **Operational:** changing `K` after deployment requires re-materialising or
  pruning `smt_nodes` to match; documented as a migration-class change.

## Alternatives considered

- **Status quo (persist all nodes):** simplest, but ~27 GB/M — rejected at target scale.
- **Leaf-only (`K = 0`):** ~maximal storage win but `O(N)` recompute of sibling
  shard roots on every proof — rejected (proof latency blows up with N).
- **Smaller node rows only (done):** packed paths (migration 0043) gave ~3.4×;
  orthogonal and already shipped. The remaining bulk is node *count*, not row size.
- **External KV / RocksDB-style node store:** larger architectural change; out of scope.
- **Hash-truncation of node digests:** changes `node_hash` output → breaks
  roots/proofs/verifiers — rejected (not physical-only).

## Risks & mitigations

- **Recompute correctness on the hot path** → extensive parity tests against the
  in-memory reference (root + existence/non-existence proofs, multi-shard,
  random fuzz), plus the existing `smt_pg_backend` integration test extended to
  assert *no* `depth > K` rows exist and proofs still verify byte-for-byte.
- **Proof-latency regression** → measure with `smt_persistent_benchmark`
  (PgBackend) before/after; tune `K`; keep the `CACHE_DEPTH` hot cache. Land
  behind a measured threshold, not blind.
- **Over-cap fallback must stay satisfiable (PR 2/2 invariant)** → the read-path
  fallback for a "hot" canopy (`> CANOPY_RECOMPUTE_CAP` leaves) reads the
  persisted `depth > K` sibling nodes; if those rows are missing the proof
  silently degrades to empty-subtree hashes and produces a **wrong** proof. So
  the write-path flush filter (and the `0044` delete) MUST preserve every
  `depth > K` node for any canopy whose live leaf count exceeds the cap — the
  filter is "persist `depth ≤ K` **OR** in an over-cap canopy", not a blanket
  `depth ≤ K`. PR 2/2 must encode this as a test (build an over-cap canopy, flush,
  assert the deep rows survive and proofs still verify) and, where feasible, a
  startup/debug assertion.
- **Stale deep rows** from a pre-hybrid DB → one-time migration deletes
  `WHERE depth > K` **except** rows belonging to an over-cap canopy (see the
  invariant above). No production data exists today, so a no-op in practice.
- **H-4 locking** → recompute on the read path is pure/read-only (no new locks);
  `update_batch` keeps the existing write lock; the flush change is strictly a
  subset of what it already writes.

## Implementation plan (subsequent PR, gated on this ADR)

1. Add `LAZY_DEPTH` const + a `recompute_subtree_root(prefix, depth)` helper in
   `tree.rs` that range-scans `smt_leaves` and folds (pure, no I/O beyond the
   one scan; runs on the blocking pool like the existing recompute).
2. `build_working_set`: use the backend for `depth ≤ K`, recompute `depth > K`
   from the canopy, capped at `CANOPY_RECOMPUTE_CAP` (fall back to persisted deep
   nodes past the cap). *(Shipped in the read-path PR.)*
3. `update_batch_inner` flush: filter dirty nodes to `depth ≤ K` before
   `put_nodes`, **except** keep persisting `depth > K` nodes for any canopy that
   exceeds `CANOPY_RECOMPUTE_CAP`, so the read-path fallback stays valid.
4. Migration `0044`: delete `WHERE depth > K` **except** rows in an over-cap
   canopy (fail-closed style consistent with 0043).
5. Tests: extend `smt_pg_backend` (root/proof parity + "no deep rows below K
   *outside* over-cap canopies" assertion); add an over-cap-canopy flush test
   that asserts the deep rows survive and proofs still verify (guards the
   fallback invariant in Risks); add a multi-shard fuzz parity test; benchmark
   proof latency delta.
6. Update `ADR-0021` cross-reference and `CLAUDE.md` SMT notes.

## Resolved decisions (locked, 2026-06-04)

1. **`K = 72`.** Clears the 64-bit shard prefix (cross-shard subtree roots stay
   persisted) plus one byte-aligned record byte (canopy = a contiguous 9-byte
   key-prefix range). The canopy is bounded **in practice by prefix uniqueness,
   not by the margin**: uniform BLAKE3 record keys don't collide in 72 bits until
   ~`2^36` leaves, so canopies are effectively singletons at any realistic scale.
   (Correction: the original "8-bit margin ⇒ ≤256 leaves" framing was wrong —
   `184` key bits live below depth 72, so depth alone caps nothing; the expected
   canopy for a shard of `M` leaves is `≈ M/256`, which grows with `M`.) The
   unbounded worst case (prefix collisions / non-hashed keys) is held by
   `CANOPY_RECOMPUTE_CAP`, which falls back to persisted deep nodes — so latency
   is `O(256)` regardless of distribution.
2. **Pinned `const`, no tunability.** `K` (`LAZY_DEPTH`) ships as a hardcoded
   constant; there is no operator switch. See *Future reconsideration* for the
   conditions under which this could change.
3. **Latency gate:** accept up to a **3× regression** on `prove`, **provided the
   absolute time stays strictly under 10 ms/proof** on the `smt_persistent_benchmark`
   PgBackend pass (representative sizes), so proof generation can never stall
   block validation. If either bound is exceeded, the implementation does **not**
   land as-is (tune the single-scan batching / hot cache, or re-evaluate `K`).

### Read-path refinement (to honour the latency gate)

Recompute does **one** `smt_leaves` range-scan per distinct canopy, not one per
deep sibling: fetch the leaves under the path's depth-`K` (72-bit) prefix in a
single contiguous PK scan, then fold *every* `depth > K` sibling from that
in-memory canopy. The scan is capped at `CANOPY_RECOMPUTE_CAP + 1`: under the cap
(the universal case for uniform-hash keys, where the canopy is a single leaf) we
fold; over the cap we abandon the fold and read the persisted deep sibling nodes
instead. This keeps the added DB cost to a single bounded round-trip and the
added CPU to hashing a bounded number of leaves up ≤ 184 levels.

## Future reconsideration

Making `K` (`LAZY_DEPTH`) — or the related `CACHE_DEPTH` — operator-tunable is
**not** part of this decision and must be introduced only via a **superseding
ADR**. Because the set of persisted nodes is defined by `K`, any change to it is
a **migration-class event**: lowering `K` requires *pruning* the now-redundant
`depth > K_new` rows; raising `K` requires *re-materialising* the
`K_old < depth ≤ K_new` band (recompute-and-`put` those nodes) before reads can
rely on them. Neither is supported here; both would be specified by the
superseding ADR.

## Superseded open questions

_(Resolved above; retained for history.)_ `K` value · static-const vs config ·
latency-regression gate.
