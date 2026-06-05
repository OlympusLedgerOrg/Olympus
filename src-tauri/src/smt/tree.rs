//! Persistent, batched Sparse Merkle Tree over a [`NodeBackend`].
//!
//! This is the scaling wrapper around the pure in-memory tree in
//! `olympus-crypto::smt`. It keeps the canonical hashing/path/proof logic in
//! the crypto crate (so roots, proofs and the offline verifiers are byte-for-
//! byte identical) and adds the three things the in-memory tree can't do at
//! scale:
//!
//!  1. **Write-behind cache** — the upper `CACHE_DEPTH` levels stay resident in
//!     memory; everything below lives in `smt_nodes`. Each operation prefetches
//!     exactly the sibling nodes it needs in a couple of bulk queries, computes
//!     in memory, then flushes dirty nodes in batched upserts.
//!  2. **Shard-parallel inserts** — a batch is grouped by 64-bit shard prefix.
//!     Each shard's subtree (depths 64..256) is disjoint from every other
//!     shard's, so they recompute concurrently on the blocking pool; only the
//!     top 64 levels are merged sequentially.
//!  3. **Batched proofs** — siblings for a whole batch of keys are resolved
//!     from one prefetched working set, so keys sharing a prefix share lookups.
//!
//! Correctness is anchored by parity tests at the bottom of this file: for
//! random inputs the persistent tree's root and proofs must equal those of
//! `olympus_crypto::smt::SparseMerkleTree`.

use std::collections::{HashMap, HashSet};

use olympus_crypto::smt::{
    empty_subtree_hash, key_to_path_bits, path_to_key, shard_prefix, sibling_path, ExistenceProof,
    NonExistenceProof, Proof, SHARD_PREFIX_BITS, SMT_DEPTH,
};
use olympus_crypto::{leaf_hash, node_hash};

use super::backend::{LeafRecord, NodeBackend, NodePath};

/// Upper levels kept resident in the write-behind cache. 20 levels cover the
/// whole shard-prefix region with room to spare (≤ 2^20 nodes) and every
/// operation touches them, so caching avoids a DB round-trip on the hot path.
const CACHE_DEPTH: usize = 20;

/// Deepest node depth persisted to `smt_nodes` (ADR-0022). Nodes at
/// `depth ≤ LAZY_DEPTH` are stored; deeper internal nodes are **recomputed** on
/// demand from the leaves of the *canopy* beneath them (the leaves sharing the
/// first `LAZY_DEPTH` key bits). `72` clears the 64-bit shard prefix
/// (`SHARD_PREFIX_BITS`) — so every per-shard subtree root stays persisted —
/// plus one record byte, and is byte-aligned (`72 / 8 = 9`) so a canopy is a
/// contiguous tree-key prefix range that recompute can fold with a single
/// ordered leaf scan.
///
/// What actually bounds a canopy is **prefix uniqueness, not the depth margin**:
/// production record keys are uniform BLAKE3 hashes
/// (`olympus_crypto::record_key`), so by the birthday bound two leaves don't
/// collide in their first 72 bits until ~`2^36` (~68 billion) leaves. Below that
/// scale every 72-bit prefix maps to a single leaf, so canopies are effectively
/// singletons and recompute folds one leaf up an empty chain. (The earlier
/// "8-bit margin ⇒ ≤256 leaves" framing was wrong — 184 key bits live below
/// depth 72, so depth alone caps nothing.) A canopy can only grow large under
/// 72-bit prefix collisions or non-hashed/adversarial record keys; that case is
/// handled by the `CANOPY_RECOMPUTE_CAP` fallback below, which keeps prove/
/// update latency bounded regardless of key distribution.
///
/// Pinned (not operator-tunable); changing it is a migration-class event
/// (ADR-0022).
const LAZY_DEPTH: usize = 72;

/// Byte width of a canopy's tree-key prefix (`LAZY_DEPTH` bits). `LAZY_DEPTH`
/// must be a whole number of bytes so a canopy maps to a contiguous key range.
const LAZY_PREFIX_BYTES: usize = LAZY_DEPTH / 8;

/// Maximum number of leaves a single on-demand canopy recompute will fold.
/// Beyond this the canopy is treated as "hot": instead of recomputing its deep
/// subtree we read the persisted deep sibling nodes directly, so a pathological
/// canopy (72-bit prefix collisions, or non-hashed record keys) can't turn one
/// `prove`/`update_batch` into an unbounded scan + fold. For uniform-hash keys
/// canopies are singletons, so this fallback is essentially never taken; it is a
/// worst-case latency guard, not the common path.
///
/// The fallback relies on deep nodes being present in `smt_nodes`. In this
/// (read-path) increment the write path still persists every node, so they
/// always are. The follow-up lazy-flush change (ADR-0022 PR 2/2) must keep
/// persisting deep nodes for any canopy that exceeds this cap, so the fallback
/// stays valid once shallow-only flushing lands.
const CANOPY_RECOMPUTE_CAP: usize = 1024;

// Compile-time invariants the recompute logic relies on.
const _: () = {
    assert!(
        LAZY_DEPTH.is_multiple_of(8),
        "LAZY_DEPTH must be byte-aligned"
    );
    assert!(
        LAZY_DEPTH >= SHARD_PREFIX_BITS,
        "LAZY_DEPTH must persist all per-shard subtree roots"
    );
    assert!(
        CACHE_DEPTH <= LAZY_DEPTH,
        "the hot cache must be within the persisted region"
    );
    assert!(
        LAZY_DEPTH < SMT_DEPTH,
        "LAZY_DEPTH must leave a deep region to recompute"
    );
};

/// A single leaf insert/update. Build `key` via
/// `olympus_crypto::smt::shard_record_key`.
#[derive(Debug, Clone)]
pub struct LeafUpdate {
    pub key: [u8; 32],
    pub value_hash: [u8; 32],
    /// Shard identifier, bound into the leaf domain prefix (ADR-0005).
    pub shard_id: String,
    pub parser_id: String,
    pub canonical_parser_version: String,
    /// Parser model-artifact hash, bound into the leaf domain (ADR-0004).
    pub model_hash: String,
}

/// The prefetched in-memory slice an operation works against.
struct WorkingSet {
    /// Internal nodes (depths `1..=255`) plus the root (depth 0) that were
    /// found in the cache or backend.
    nodes: HashMap<NodePath, [u8; 32]>,
    /// Existing leaf records relevant to the operation.
    leaves: HashMap<[u8; 32], LeafRecord>,
}

/// Persistent SMT. Holds the backend and the resident hot cache.
pub struct PersistentSmt<B: NodeBackend> {
    backend: B,
    /// Resident copy of every node with depth `<= CACHE_DEPTH`.
    cache: HashMap<NodePath, [u8; 32]>,
}

impl<B: NodeBackend> PersistentSmt<B> {
    /// Open the tree, loading the hot upper levels into memory.
    pub async fn open(backend: B) -> anyhow::Result<Self> {
        let cache = backend.load_hot(CACHE_DEPTH).await?;
        Ok(Self { backend, cache })
    }

    /// Open the tree **without** loading the hot upper-level cache.
    ///
    /// Safe ONLY for write-only callers. [`update_batch`] re-loads the hot
    /// cache from the backend under the write lock before it reads any cached
    /// node (audit H-4 part 2), so a deferred (empty) initial cache is always
    /// overwritten before use — and this saves the eager top-`CACHE_DEPTH`
    /// `load_hot` SELECT that [`open`](Self::open) does on every call (audit
    /// finding 9). Do NOT use this for read/proof paths ([`root`](Self::root),
    /// [`get`](Self::get), [`prove`](Self::prove), [`prove_batch`](Self::prove_batch)
    /// → `build_working_set`): they handle an empty `cache` by falling back to
    /// backend lookups, so they still return **correct** results — but they
    /// miss the hot cache on every call and pay unnecessary backend
    /// round-trips. The `update_batch` safety constraint above (it reloads the
    /// hot cache under the write lock, so a deferred `cache` is fine) is
    /// unchanged.
    pub fn open_deferred(backend: B) -> Self {
        Self {
            backend,
            cache: HashMap::new(),
        }
    }

    /// Current global root.
    pub async fn root(&self) -> anyhow::Result<[u8; 32]> {
        let empty: NodePath = Vec::new();
        if let Some(h) = self.cache.get(&empty) {
            return Ok(*h);
        }
        let got = self.backend.get_nodes(std::slice::from_ref(&empty)).await?;
        Ok(got
            .get(&empty)
            .copied()
            .unwrap_or_else(|| empty_subtree_hash(SMT_DEPTH)))
    }

    /// Per-shard subtree root: the node at depth `SHARD_PREFIX_BITS` along the
    /// shard's prefix (empty-subtree hash when the shard has no records).
    pub async fn shard_subtree_root(&self, shard_id: &str) -> anyhow::Result<[u8; 32]> {
        let bits = bytes_to_bits(&shard_prefix(shard_id));
        if bits.len() <= CACHE_DEPTH {
            if let Some(h) = self.cache.get(&bits) {
                return Ok(*h);
            }
        }
        let got = self.backend.get_nodes(std::slice::from_ref(&bits)).await?;
        Ok(got
            .get(&bits)
            .copied()
            .unwrap_or_else(|| empty_subtree_hash(SMT_DEPTH - SHARD_PREFIX_BITS)))
    }

    /// Value hash stored at `key`, if present.
    pub async fn get(&self, key: &[u8; 32]) -> anyhow::Result<Option<[u8; 32]>> {
        let got = self.backend.get_leaves(std::slice::from_ref(key)).await?;
        Ok(got.get(key).map(|r| r.value_hash))
    }

    /// Insert/update a single leaf. Returns the new global root.
    pub async fn update(
        &mut self,
        key: [u8; 32],
        value_hash: [u8; 32],
        shard_id: &str,
        parser_id: &str,
        canonical_parser_version: &str,
        model_hash: &str,
    ) -> anyhow::Result<[u8; 32]> {
        self.update_batch(&[LeafUpdate {
            key,
            value_hash,
            shard_id: shard_id.to_string(),
            parser_id: parser_id.to_string(),
            canonical_parser_version: canonical_parser_version.to_string(),
            model_hash: model_hash.to_string(),
        }])
        .await
    }

    /// Insert/update a batch of leaves (mutable: an existing key is overwritten
    /// with the new `value_hash`). Returns the new root.
    pub async fn update_batch(&mut self, updates: &[LeafUpdate]) -> anyhow::Result<[u8; 32]> {
        self.update_batch_inner(updates, false).await
    }

    /// Like [`update_batch`](Self::update_batch) but enforces leaf write-once
    /// **atomically under the write lock**: if any updated key already holds a
    /// leaf with a *different* `value_hash`, the whole batch is rejected and
    /// nothing is persisted (an identical re-commit is a no-op and succeeds).
    /// The existence check runs inside the same `build_working_set` read the
    /// recompute uses, so it shares the writer lock — closing the
    /// get-then-update TOCTOU a caller doing `get()` + `update_batch()` would
    /// otherwise leave open.
    pub async fn update_batch_write_once(
        &mut self,
        updates: &[LeafUpdate],
    ) -> anyhow::Result<[u8; 32]> {
        self.update_batch_inner(updates, true).await
    }

    /// Shared implementation. `write_once` toggles the immutable-leaf guard.
    ///
    /// Audit H-4: the read-modify-write sequence below
    /// (`build_working_set` → in-memory recompute → `put_nodes` +
    /// `put_leaves`) is NOT atomic with respect to a concurrent writer
    /// against the same database (e.g. a federation peer or a second
    /// process). Two racing writers can each read a stale working set,
    /// compute disjoint dirty internal-path sets, and then upsert; the
    /// second writer's `put_nodes` silently overwrites overlapping paths
    /// from the first, leaving the tree's invariant
    /// `root == reconstruct(leaves)` broken until a full recompute.
    ///
    /// We close the window by taking a backend-level cross-process write
    /// lock for the duration of the batch. On Postgres this is
    /// `pg_advisory_lock`; on the in-memory backend it's an async
    /// `Mutex`. The lock is released when `_write_lock` drops at the
    /// end of this function (or on panic, via the RAII guard).
    async fn update_batch_inner(
        &mut self,
        updates: &[LeafUpdate],
        write_once: bool,
    ) -> anyhow::Result<[u8; 32]> {
        if updates.is_empty() {
            return self.root().await;
        }

        let _write_lock = self.backend.acquire_write_lock().await?;

        // Audit H-4 part 2: after acquiring the lock, refresh the hot
        // cache from the backend. Without this, a writer that opened
        // earlier carries a stale cache of upper-level internal nodes
        // (depth ≤ `CACHE_DEPTH`) and `build_working_set` would happily
        // serve those stale hashes instead of the post-merge state the
        // previous lock-holder just committed — silently undoing their
        // merge. The lock guarantees serialisation; this refresh
        // guarantees the *post-lock view* of the tree is the durable
        // one. Cost is one bulk SELECT over the hot upper levels per
        // `update_batch`, which is small relative to the recompute work.
        self.cache = self.backend.load_hot(CACHE_DEPTH).await?;

        // Dedup by key; the last update for a key wins (matches sequential apply).
        let mut latest: HashMap<[u8; 32], LeafRecord> = HashMap::new();
        for u in updates {
            // Reject malformed provenance with an error instead of panicking —
            // these come off request / federation paths, so a bad row must not
            // crash the writer. Same checks as the in-memory tree's asserts.
            if u.shard_id.is_empty() {
                return Err(anyhow::anyhow!("shard_id must be non-empty"));
            }
            if !olympus_crypto::smt::shard_id_matches_key(&u.shard_id, &u.key) {
                return Err(anyhow::anyhow!(
                    "shard_id must hash to the key's 64-bit prefix (ADR-0005 authority); \
                     build the key with shard_record_key(shard_id, record_key)"
                ));
            }
            if u.parser_id.is_empty() {
                return Err(anyhow::anyhow!("parser_id must be non-empty"));
            }
            if u.canonical_parser_version.is_empty() {
                return Err(anyhow::anyhow!(
                    "canonical_parser_version must be non-empty"
                ));
            }
            if u.model_hash.is_empty() {
                return Err(anyhow::anyhow!("model_hash must be non-empty"));
            }
            latest.insert(
                u.key,
                LeafRecord {
                    value_hash: u.value_hash,
                    shard_id: u.shard_id.clone(),
                    parser_id: u.parser_id.clone(),
                    canonical_parser_version: u.canonical_parser_version.clone(),
                    model_hash: u.model_hash.clone(),
                },
            );
        }
        let keys: Vec<[u8; 32]> = latest.keys().copied().collect();

        // 1. Prefetch the sibling working set, then overlay the updated leaves.
        let ws = self.build_working_set(&keys).await?;
        let mut nodes = ws.nodes;
        let mut leaves = ws.leaves;

        // Write-once enforcement (immutable parser-provenance leaves). Done
        // here — inside the write lock, against the leaves `build_working_set`
        // just read — so the existence check and the write are atomic. A
        // caller doing `get()` then `update_batch()` would leave a TOCTOU
        // window; folding the check in closes it. An identical re-commit
        // (same value_hash) is allowed to fall through as a no-op overlay.
        if write_once {
            for (k, rec) in &latest {
                if let Some(existing) = leaves.get(k) {
                    if existing.value_hash != rec.value_hash {
                        return Err(anyhow::anyhow!(
                            "write-once violation: a leaf at this key is already committed \
                             with a different value_hash; refusing to overwrite (would \
                             invalidate prior inclusion proofs)"
                        ));
                    }
                }
            }
        }

        for (k, rec) in &latest {
            leaves.insert(*k, rec.clone());
        }
        // Seed every known leaf hash at its depth-256 path so the recompute
        // reads sibling leaves (updated or pre-existing) uniformly.
        for (k, rec) in &leaves {
            nodes.insert(key_to_path_bits(k), leaf_hash_of(k, rec));
        }

        // 2. Group changed keys by their 64-bit shard prefix.
        let mut groups: HashMap<[u8; 8], Vec<NodePath>> = HashMap::new();
        for k in &keys {
            let mut g = [0u8; 8];
            g.copy_from_slice(&k[..8]);
            groups.entry(g).or_default().push(key_to_path_bits(k));
        }

        // 3. Shard-parallel recompute of depths 256→64 (disjoint per shard).
        let mut handles = Vec::with_capacity(groups.len());
        for (g, frontier_paths) in &groups {
            let shard_bits = bytes_to_bits(g);
            let slice: HashMap<NodePath, [u8; 32]> = nodes
                .iter()
                .filter(|(p, _)| {
                    p.len() >= SHARD_PREFIX_BITS && p[..SHARD_PREFIX_BITS] == shard_bits[..]
                })
                .map(|(p, h)| (p.clone(), *h))
                .collect();
            let frontier: HashSet<NodePath> = frontier_paths.iter().cloned().collect();
            handles.push(tokio::task::spawn_blocking(move || {
                compute_subtree(slice, frontier, SMT_DEPTH, SHARD_PREFIX_BITS)
            }));
        }
        let mut dirty: Vec<(NodePath, [u8; 32])> = Vec::new();
        for h in handles {
            dirty.extend(h.await?);
        }

        // 4. Merge: fold the changed shard roots up through the top 64 levels.
        for (p, h) in &dirty {
            nodes.insert(p.clone(), *h);
        }
        let merge_frontier: HashSet<NodePath> = groups.keys().map(|g| bytes_to_bits(g)).collect();
        let merged = recompute_up(&mut nodes, merge_frontier, SHARD_PREFIX_BITS, 0);
        for p in merged {
            dirty.push((p.clone(), nodes[&p]));
        }

        // 5. Persist dirty internal nodes + leaves; refresh the hot cache.
        for (p, h) in &dirty {
            if p.len() <= CACHE_DEPTH {
                self.cache.insert(p.clone(), *h);
            }
        }
        self.backend.put_nodes(&dirty).await?;
        let leaf_rows: Vec<([u8; 32], LeafRecord)> = latest.into_iter().collect();
        self.backend.put_leaves(&leaf_rows).await?;

        Ok(nodes
            .get(&Vec::<u8>::new())
            .copied()
            .unwrap_or_else(|| empty_subtree_hash(SMT_DEPTH)))
    }

    /// Existence/non-existence proof for a single key.
    pub async fn prove(&self, key: &[u8; 32]) -> anyhow::Result<Proof> {
        Ok(self
            .prove_batch(std::slice::from_ref(key))
            .await?
            .pop()
            .expect("prove_batch returns one proof per key"))
    }

    /// Proofs for a batch of keys from one prefetched working set. Keys sharing
    /// a prefix share sibling lookups.
    pub async fn prove_batch(&self, keys: &[[u8; 32]]) -> anyhow::Result<Vec<Proof>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let ws = self.build_working_set(keys).await?;
        let root_hash = self.root().await?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let path = key_to_path_bits(key);
            let mut siblings = Vec::with_capacity(SMT_DEPTH);
            for level in 0..SMT_DEPTH {
                let bit_pos = SMT_DEPTH - 1 - level;
                let sib = sibling_path(&path[..=bit_pos]);
                siblings.push(resolve_sibling(&ws, &sib, level));
            }
            let proof = match ws.leaves.get(key) {
                Some(rec) => Proof::Existence(ExistenceProof {
                    key: *key,
                    value_hash: rec.value_hash,
                    shard_id: rec.shard_id.clone(),
                    parser_id: rec.parser_id.clone(),
                    canonical_parser_version: rec.canonical_parser_version.clone(),
                    model_hash: rec.model_hash.clone(),
                    siblings,
                    root_hash,
                }),
                None => Proof::NonExistence(NonExistenceProof {
                    key: *key,
                    siblings,
                    root_hash,
                }),
            };
            out.push(proof);
        }
        Ok(out)
    }

    /// Prefetch the union of sibling nodes (and relevant leaves) for `keys`.
    /// Cache hits for the hot upper levels are taken from the resident cache;
    /// deeper siblings are bulk-loaded from the backend in one query.
    async fn build_working_set(&self, keys: &[[u8; 32]]) -> anyhow::Result<WorkingSet> {
        let mut nodes: HashMap<NodePath, [u8; 32]> = HashMap::new();
        let mut want_nodes: HashSet<NodePath> = HashSet::new();
        let mut want_leaves: HashSet<[u8; 32]> = HashSet::new();

        // Keys grouped by canopy (their shared `LAZY_PREFIX_BYTES` prefix), so
        // each canopy is scanned once and its over-cap fallback covers every key
        // beneath it.
        let mut keys_by_canopy: HashMap<[u8; LAZY_PREFIX_BYTES], Vec<[u8; 32]>> = HashMap::new();

        for key in keys {
            let path = key_to_path_bits(key);
            for level in 0..SMT_DEPTH {
                let bit_pos = SMT_DEPTH - 1 - level;
                let sib = sibling_path(&path[..=bit_pos]);
                if sib.len() == SMT_DEPTH {
                    want_leaves.insert(path_to_key(&sib));
                } else if sib.len() <= CACHE_DEPTH {
                    if let Some(h) = self.cache.get(&sib) {
                        nodes.insert(sib, *h);
                    }
                } else if sib.len() <= LAZY_DEPTH {
                    want_nodes.insert(sib);
                }
                // Siblings deeper than LAZY_DEPTH are not fetched here; they are
                // recomputed from the canopy of leaves below (see ADR-0022), or
                // — for an over-cap canopy — fetched in the fallback below.
            }
            want_leaves.insert(*key);

            let mut prefix = [0u8; LAZY_PREFIX_BYTES];
            prefix.copy_from_slice(&key[..LAZY_PREFIX_BYTES]);
            keys_by_canopy.entry(prefix).or_default().push(*key);
        }

        let node_query: Vec<NodePath> = want_nodes.into_iter().collect();
        for (p, h) in self.backend.get_nodes(&node_query).await? {
            nodes.insert(p, h);
        }
        let leaf_query: Vec<[u8; 32]> = want_leaves.into_iter().collect();
        let mut leaves = self.backend.get_leaves(&leaf_query).await?;

        // Materialise the deep region (`depth > LAZY_DEPTH`) one canopy at a time.
        // `LAZY_DEPTH` is byte-aligned, so a canopy is exactly the leaves sharing
        // the first `LAZY_PREFIX_BYTES` of the tree key — a contiguous key range.
        // For uniform-hash keys a canopy is a single leaf; we scan it (capped at
        // `CANOPY_RECOMPUTE_CAP + 1`) and fold it up to `LAZY_DEPTH`, which
        // materialises every deep internal node along (and adjacent to) each
        // path. Absent deep siblings stay absent and resolve to the empty-subtree
        // hash, identical to the full tree.
        for (prefix, canopy_keys) in &keys_by_canopy {
            let mut lo = [0u8; 32];
            lo[..LAZY_PREFIX_BYTES].copy_from_slice(prefix);
            let mut hi = [0xFFu8; 32];
            hi[..LAZY_PREFIX_BYTES].copy_from_slice(prefix);
            let canopy = self
                .backend
                .get_leaves_in_range(lo, hi, CANOPY_RECOMPUTE_CAP + 1)
                .await?;

            if canopy.len() > CANOPY_RECOMPUTE_CAP {
                // "Hot" canopy (72-bit prefix collisions or non-hashed keys):
                // recomputing would be an unbounded fold, so read the persisted
                // deep sibling nodes directly instead — bounding latency to the
                // proof-path size. (Deep nodes are still persisted in this
                // read-path increment; ADR-0022 PR 2/2 keeps persisting them for
                // over-cap canopies so this fallback stays valid.)
                let mut deep_sibs: HashSet<NodePath> = HashSet::new();
                for key in canopy_keys {
                    let path = key_to_path_bits(key);
                    for level in 0..SMT_DEPTH {
                        let bit_pos = SMT_DEPTH - 1 - level;
                        let sib = sibling_path(&path[..=bit_pos]);
                        if sib.len() > LAZY_DEPTH && sib.len() < SMT_DEPTH {
                            deep_sibs.insert(sib);
                        }
                    }
                }
                let deep_query: Vec<NodePath> = deep_sibs.into_iter().collect();
                for (p, h) in self.backend.get_nodes(&deep_query).await? {
                    nodes.insert(p, h);
                }
                continue;
            }

            let mut frontier: HashSet<NodePath> = HashSet::with_capacity(canopy.len());
            for (k, rec) in &canopy {
                let leaf_path = key_to_path_bits(k);
                nodes.insert(leaf_path.clone(), leaf_hash_of(k, rec));
                frontier.insert(leaf_path);
                // Canopy leaves are also leaf-level siblings; make them resolvable.
                leaves.entry(*k).or_insert_with(|| rec.clone());
            }
            recompute_up(&mut nodes, frontier, SMT_DEPTH, LAZY_DEPTH);
        }

        Ok(WorkingSet { nodes, leaves })
    }
}

/// Read-only introspection for the in-memory backend, used by benchmarks and
/// tests. Deliberately scoped to `PersistentSmt<MemBackend>` and limited to
/// count accessors so callers can size the tree without a handle to the raw
/// `NodeBackend` — whose `put_nodes` / `put_leaves` take `&self` and would
/// bypass the `acquire_write_lock` + hot-cache refresh that `update_batch`
/// guarantees (audit H-4).
impl PersistentSmt<super::backend::MemBackend> {
    /// Number of materialised internal nodes currently held by the backend.
    pub fn mem_node_count(&self) -> usize {
        self.backend.node_count()
    }

    /// Number of leaf records currently held by the backend.
    pub fn mem_leaf_count(&self) -> usize {
        self.backend.leaf_count()
    }
}

// ── pure helpers (no I/O — safe to run on the blocking pool) ────────────────

fn leaf_hash_of(key: &[u8; 32], rec: &LeafRecord) -> [u8; 32] {
    leaf_hash(
        rec.shard_id.as_bytes(),
        key,
        &rec.value_hash,
        rec.parser_id.as_bytes(),
        rec.canonical_parser_version.as_bytes(),
        rec.model_hash.as_bytes(),
    )
}

/// Expand bytes into a bit-path (one byte per bit, MSB first).
fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8u8 {
            bits.push((byte >> (7 - i)) & 1);
        }
    }
    bits
}

/// Resolve the hash at `sibling_path` against a working set, mirroring the
/// reference tree's `resolve_sibling`: stored internal node first, then a
/// leaf sibling hashed on demand, else the empty-subtree hash at `level`.
fn resolve_sibling(ws: &WorkingSet, sibling_path: &[u8], level: usize) -> [u8; 32] {
    if let Some(h) = ws.nodes.get(sibling_path) {
        return *h;
    }
    if sibling_path.len() == SMT_DEPTH {
        let key = path_to_key(sibling_path);
        if let Some(rec) = ws.leaves.get(&key) {
            return leaf_hash_of(&key, rec);
        }
    }
    empty_subtree_hash(level)
}

/// Recompute every ancestor of the paths in `frontier`, from `start_depth`
/// (the depth of the frontier nodes — already correct in `nodes`) up to and
/// including `stop_depth`, writing results into `nodes`. Returns the set of
/// node paths written (depths `stop_depth..start_depth`).
///
/// Each parent reads its two children from `nodes`; an absent child is the
/// empty-subtree hash for its depth — identical to the in-memory tree.
fn recompute_up(
    nodes: &mut HashMap<NodePath, [u8; 32]>,
    frontier: HashSet<NodePath>,
    start_depth: usize,
    stop_depth: usize,
) -> HashSet<NodePath> {
    let mut written: HashSet<NodePath> = HashSet::new();
    let mut frontier = frontier;
    for child_depth in (stop_depth + 1..=start_depth).rev() {
        let empty_child = empty_subtree_hash(SMT_DEPTH - child_depth);
        let mut next: HashSet<NodePath> = HashSet::new();
        for child in &frontier {
            let parent = child[..child_depth - 1].to_vec();
            if next.contains(&parent) {
                continue;
            }
            let mut left = parent.clone();
            left.push(0);
            let mut right = parent.clone();
            right.push(1);
            let l = nodes.get(&left).copied().unwrap_or(empty_child);
            let r = nodes.get(&right).copied().unwrap_or(empty_child);
            let h = node_hash(&l, &r);
            nodes.insert(parent.clone(), h);
            written.insert(parent.clone());
            next.insert(parent);
        }
        frontier = next;
    }
    written
}

/// Recompute one shard's subtree (`start_depth`→`stop_depth`) on a slice of the
/// working set and return its dirty `(path, hash)` nodes. Runs on the blocking
/// pool, so it owns its inputs.
fn compute_subtree(
    mut slice: HashMap<NodePath, [u8; 32]>,
    frontier: HashSet<NodePath>,
    start_depth: usize,
    stop_depth: usize,
) -> Vec<(NodePath, [u8; 32])> {
    let written = recompute_up(&mut slice, frontier, start_depth, stop_depth);
    written
        .into_iter()
        .map(|p| (p.clone(), slice[&p]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::backend::MemBackend;
    use olympus_crypto::smt::{shard_record_key, verify_proof, SparseMerkleTree};

    /// Tiny deterministic LCG so tests are reproducible without a `rand` dep.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn rk(&mut self) -> [u8; 32] {
            let mut k = [0u8; 32];
            for b in &mut k {
                *b = (self.next() >> 33) as u8;
            }
            k
        }
    }

    /// Build a `LeafUpdate` whose key is `shard_record_key(shard, rec)`, so the
    /// `shard_id` is consistent with the key prefix (ADR-0005 authority).
    fn upd(shard: &str, rec: [u8; 32], v: u8) -> LeafUpdate {
        LeafUpdate {
            key: shard_record_key(shard, &rec),
            value_hash: [v; 32],
            shard_id: shard.to_string(),
            parser_id: "docling@2.3.1".into(),
            canonical_parser_version: "v1".into(),
            model_hash: "blake3:docling@2.3.1".into(),
        }
    }

    /// Build a reference in-memory tree from the same updates (last-wins).
    fn reference(updates: &[LeafUpdate]) -> SparseMerkleTree {
        let mut t = SparseMerkleTree::new();
        for u in updates {
            t.update(
                u.key,
                u.value_hash,
                &u.shard_id,
                &u.parser_id,
                &u.canonical_parser_version,
                &u.model_hash,
            );
        }
        t
    }

    #[tokio::test]
    async fn empty_tree_root_matches_reference() {
        let smt = PersistentSmt::open(MemBackend::new()).await.unwrap();
        assert_eq!(smt.root().await.unwrap(), reference(&[]).root());
    }

    #[tokio::test]
    async fn single_insert_matches_reference() {
        let mut smt = PersistentSmt::open(MemBackend::new()).await.unwrap();
        let updates = vec![upd("shard-a", [1u8; 32], 0xAA)];
        let root = smt.update_batch(&updates).await.unwrap();
        assert_eq!(root, reference(&updates).root());
    }

    #[tokio::test]
    async fn multi_shard_batch_matches_reference_and_proofs_verify() {
        let mut smt = PersistentSmt::open(MemBackend::new()).await.unwrap();
        let mut rng = Lcg(0x1234_5678);
        let shards = ["alpha", "beta", "gamma", "delta"];
        let mut updates = Vec::new();
        for i in 0..200u32 {
            let shard = shards[(i as usize) % shards.len()];
            updates.push(upd(shard, rng.rk(), (i % 251) as u8));
        }

        let root = smt.update_batch(&updates).await.unwrap();
        let reference_root = reference(&updates).root();
        assert_eq!(root, reference_root, "batched root must match reference");

        // Every inserted key proves existence and verifies against the root.
        let keys: Vec<[u8; 32]> = updates.iter().map(|u| u.key).collect();
        let proofs = smt.prove_batch(&keys).await.unwrap();
        assert_eq!(proofs.len(), keys.len());
        for p in &proofs {
            assert!(matches!(p, Proof::Existence(_)));
            assert!(verify_proof(p, Some(&root)));
        }

        // Batched proofs equal the reference tree's per-key proofs byte-for-byte.
        let reference_tree = reference(&updates);
        for (key, got) in keys.iter().zip(&proofs) {
            assert_eq!(
                *got,
                reference_tree.prove(key),
                "proof mismatch vs reference"
            );
        }
    }

    #[tokio::test]
    async fn incremental_batches_match_one_shot() {
        // Splitting the same updates across several persisted batches must land
        // on the same root as applying them all at once — proves the prefetch /
        // flush / cache cycle reads back its own writes correctly.
        let mut rng = Lcg(0xDEAD_BEEF);
        let mut all = Vec::new();
        for i in 0..120u32 {
            let shard = if i % 2 == 0 { "s0" } else { "s1" };
            all.push(upd(shard, rng.rk(), (i % 250) as u8));
        }

        let mut smt = PersistentSmt::open(MemBackend::new()).await.unwrap();
        for chunk in all.chunks(17) {
            smt.update_batch(chunk).await.unwrap();
        }
        assert_eq!(smt.root().await.unwrap(), reference(&all).root());
    }

    #[tokio::test]
    async fn nonexistence_proof_matches_reference() {
        let mut smt = PersistentSmt::open(MemBackend::new()).await.unwrap();
        let updates = vec![upd("shard-a", [1u8; 32], 0xAA)];
        let root = smt.update_batch(&updates).await.unwrap();

        let absent = shard_record_key("shard-a", &[9u8; 32]);
        let proof = smt.prove(&absent).await.unwrap();
        assert!(matches!(proof, Proof::NonExistence(_)));
        assert!(verify_proof(&proof, Some(&root)));
        assert_eq!(proof, reference(&updates).prove(&absent));
    }

    /// Force many leaves into a *single* `LAZY_DEPTH` canopy so the deep
    /// recompute (ADR-0022) folds a real multi-leaf subtree at `depth >
    /// LAZY_DEPTH`, not just empty siblings. `LAZY_DEPTH` is 72 bits = 9 key
    /// bytes; the key is `shard_prefix(8) ‖ record(24)`, so leaves sharing a
    /// shard *and* `record[0]` share the 72-bit prefix and branch only below it.
    #[tokio::test]
    async fn deep_recompute_multi_leaf_canopy_matches_reference() {
        let canopy_key = |i: u8| {
            let mut rec = [0u8; 32];
            rec[0] = 0xAB; // shared 9th key byte → same canopy
            rec[1] = i; // differ at depth > LAZY_DEPTH
            rec[7] = i.wrapping_mul(31);
            rec
        };
        let mut updates: Vec<LeafUpdate> = (0..12u8)
            .map(|i| upd("canopy-shard", canopy_key(i), i))
            .collect();
        // A second canopy (different record[0]) + another shard, so the proof
        // path also crosses persisted shard-prefix siblings, not only this canopy.
        updates.push(upd("canopy-shard", [0x07; 32], 99));
        updates.push(upd("other-shard", [2u8; 32], 0xCD));

        let mut smt = PersistentSmt::open(MemBackend::new()).await.unwrap();
        let root = smt.update_batch(&updates).await.unwrap();
        let reference = reference(&updates);
        assert_eq!(
            root,
            reference.root(),
            "multi-leaf canopy root must match reference"
        );

        // Existence proof for a key deep inside the busy canopy.
        let key = updates[5].key;
        let proof = smt.prove(&key).await.unwrap();
        assert!(matches!(proof, Proof::Existence(_)));
        assert!(verify_proof(&proof, Some(&root)));
        assert_eq!(
            proof,
            reference.prove(&key),
            "existence proof must match reference"
        );

        // Non-existence for a key in the same canopy (absent deep bits).
        let absent = shard_record_key("canopy-shard", &canopy_key(200));
        let nproof = smt.prove(&absent).await.unwrap();
        assert!(matches!(nproof, Proof::NonExistence(_)));
        assert!(verify_proof(&nproof, Some(&root)));
        assert_eq!(
            nproof,
            reference.prove(&absent),
            "non-existence proof must match reference"
        );
    }

    /// Drive a single canopy past `CANOPY_RECOMPUTE_CAP` so `build_working_set`
    /// takes the over-cap fallback (read persisted deep nodes instead of folding
    /// the canopy). Proofs must still match the reference exactly — the fallback
    /// is a latency guard, not a behaviour change. Keys here share a fixed 9-byte
    /// prefix (same shard + `record[0]`), the pathological shape uniform-hash
    /// keys never produce.
    #[tokio::test]
    async fn over_cap_canopy_falls_back_and_matches_reference() {
        // Spread the counter across record bytes that all sit below LAZY_DEPTH
        // (byte index ≥ 1 of the record == key byte ≥ 9), keeping record[0] fixed
        // so every key lands in the one canopy.
        let hot_key = |i: u32| {
            let mut rec = [0u8; 32];
            rec[0] = 0x5C; // shared 9th key byte → one canopy for all i
            rec[1..5].copy_from_slice(&i.to_be_bytes());
            rec
        };
        let n = (CANOPY_RECOMPUTE_CAP as u32) + 50; // strictly over the cap
        let mut updates: Vec<LeafUpdate> = (0..n)
            .map(|i| upd("hot-shard", hot_key(i), i as u8))
            .collect();
        // A leaf in a different shard so the proof path also crosses a normal
        // (single-leaf) canopy and persisted shard-prefix siblings.
        updates.push(upd("cool-shard", [0x11; 32], 0x22));

        let mut smt = PersistentSmt::open(MemBackend::new()).await.unwrap();
        let root = smt.update_batch(&updates).await.unwrap();
        let reference = reference(&updates);
        assert_eq!(
            root,
            reference.root(),
            "over-cap canopy root must match reference"
        );

        // Existence proof for a key inside the over-cap canopy → fallback path.
        let key = updates[(n / 2) as usize].key;
        let proof = smt.prove(&key).await.unwrap();
        assert!(matches!(proof, Proof::Existence(_)));
        assert!(verify_proof(&proof, Some(&root)));
        assert_eq!(
            proof,
            reference.prove(&key),
            "over-cap existence proof must match reference"
        );

        // Non-existence inside the same over-cap canopy.
        let absent = shard_record_key("hot-shard", &hot_key(n + 12345));
        let nproof = smt.prove(&absent).await.unwrap();
        assert!(matches!(nproof, Proof::NonExistence(_)));
        assert!(verify_proof(&nproof, Some(&root)));
        assert_eq!(
            nproof,
            reference.prove(&absent),
            "over-cap non-existence proof must match reference"
        );

        // The cool-shard leaf (a normal canopy) still verifies in the same batch.
        let cool = updates.last().unwrap().key;
        let cproof = smt.prove(&cool).await.unwrap();
        assert!(verify_proof(&cproof, Some(&root)));
        assert_eq!(
            cproof,
            reference.prove(&cool),
            "normal-canopy proof must match reference"
        );
    }

    #[tokio::test]
    async fn shard_subtree_root_matches_reference() {
        let mut smt = PersistentSmt::open(MemBackend::new()).await.unwrap();
        let updates = vec![
            upd("shard-a", [1u8; 32], 0xAA),
            upd("shard-b", [2u8; 32], 0xBB),
        ];
        smt.update_batch(&updates).await.unwrap();
        let reference_tree = reference(&updates);
        for shard in ["shard-a", "shard-b", "empty-shard"] {
            assert_eq!(
                smt.shard_subtree_root(shard).await.unwrap(),
                reference_tree.shard_subtree_root(shard),
                "shard subtree root mismatch for {shard}"
            );
        }
    }

    #[tokio::test]
    async fn updating_existing_key_matches_reference() {
        let mut smt = PersistentSmt::open(MemBackend::new()).await.unwrap();
        let k = shard_record_key("s", &[7u8; 32]);
        smt.update_batch(&[upd("s", [7u8; 32], 0x11)])
            .await
            .unwrap();
        let root = smt
            .update_batch(&[upd("s", [7u8; 32], 0x22)])
            .await
            .unwrap();

        let reference_root =
            reference(&[upd("s", [7u8; 32], 0x11), upd("s", [7u8; 32], 0x22)]).root();
        assert_eq!(root, reference_root);
        assert_eq!(smt.get(&k).await.unwrap(), Some([0x22u8; 32]));
    }

    #[tokio::test]
    async fn write_once_rejects_conflicting_value() {
        let mut smt = PersistentSmt::open(MemBackend::new()).await.unwrap();
        let k = shard_record_key("s", &[7u8; 32]);

        // First write-once commit succeeds.
        smt.update_batch_write_once(&[upd("s", [7u8; 32], 0x11)])
            .await
            .unwrap();
        let root_after_first = smt.root().await.unwrap();

        // An identical re-commit is a harmless no-op and still succeeds.
        smt.update_batch_write_once(&[upd("s", [7u8; 32], 0x11)])
            .await
            .unwrap();
        assert_eq!(smt.root().await.unwrap(), root_after_first);

        // A different value at the same key is rejected, and nothing is
        // persisted — the original leaf and root are untouched.
        let err = smt
            .update_batch_write_once(&[upd("s", [7u8; 32], 0x22)])
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("write-once"),
            "expected a write-once violation, got: {err}"
        );
        assert_eq!(smt.get(&k).await.unwrap(), Some([0x11u8; 32]));
        assert_eq!(smt.root().await.unwrap(), root_after_first);

        // Plain `update_batch` (mutable) still overwrites — write-once is
        // opt-in, not a global policy change.
        smt.update_batch(&[upd("s", [7u8; 32], 0x22)])
            .await
            .unwrap();
        assert_eq!(smt.get(&k).await.unwrap(), Some([0x22u8; 32]));
    }

    // ── H-4: concurrent-writer regression ──────────────────────────────────
    //
    // Drives two `update_batch` calls in parallel against a *shared*
    // backend (mirroring the federation gossip + ingest race). With the
    // H-4 fix in place, the backend's `acquire_write_lock` serialises
    // them and the final root equals the reference tree built from the
    // union of both update sets. Without the fix, one writer's leaves
    // are silently dropped from the root and the assertion fires.
    //
    // We construct one `PersistentSmt` per task but share the SAME
    // `Arc<MemBackend>` between them — same model as two desktop
    // processes pointing at the same Postgres.
    #[tokio::test]
    async fn concurrent_update_batches_dont_lose_leaves() {
        use std::sync::Arc;

        /// `PersistentSmt::open` takes `B: NodeBackend` by value; wrap
        /// MemBackend in an Arc-backed adapter that satisfies the trait
        /// while delegating to a shared instance. This is test-only —
        /// production uses one `PersistentSmt` per `PgBackend`.
        struct SharedMem(Arc<MemBackend>);
        impl NodeBackend for SharedMem {
            async fn get_nodes(
                &self,
                paths: &[NodePath],
            ) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
                self.0.get_nodes(paths).await
            }
            async fn get_leaves(
                &self,
                keys: &[[u8; 32]],
            ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
                self.0.get_leaves(keys).await
            }
            async fn get_leaves_in_range(
                &self,
                lo: [u8; 32],
                hi: [u8; 32],
                limit: usize,
            ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
                self.0.get_leaves_in_range(lo, hi, limit).await
            }
            async fn put_nodes(&self, nodes: &[(NodePath, [u8; 32])]) -> anyhow::Result<()> {
                self.0.put_nodes(nodes).await
            }
            async fn put_leaves(&self, leaves: &[([u8; 32], LeafRecord)]) -> anyhow::Result<()> {
                self.0.put_leaves(leaves).await
            }
            async fn load_hot(
                &self,
                max_depth: usize,
            ) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
                self.0.load_hot(max_depth).await
            }
            async fn acquire_write_lock(
                &self,
            ) -> anyhow::Result<crate::smt::backend::WriteLockGuard> {
                self.0.acquire_write_lock().await
            }
        }

        let shared = Arc::new(MemBackend::new());

        // Two writers, disjoint shards so the leaf sets don't conflict —
        // the race is purely on the internal-node merge at the top.
        let mut writer_a = PersistentSmt::open(SharedMem(shared.clone()))
            .await
            .unwrap();
        let mut writer_b = PersistentSmt::open(SharedMem(shared.clone()))
            .await
            .unwrap();

        let mut rng_a = Lcg(0xA1_A1A1A1);
        let mut rng_b = Lcg(0xB2_B2B2B2);
        let updates_a: Vec<LeafUpdate> =
            (0..40).map(|i| upd("alpha", rng_a.rk(), i as u8)).collect();
        let updates_b: Vec<LeafUpdate> =
            (0..40).map(|i| upd("beta", rng_b.rk(), i as u8)).collect();

        // Fire concurrently. The H-4 lock should fully serialise these,
        // so one observes the other's committed leaves on the second
        // pass.
        let ua = updates_a.clone();
        let ub = updates_b.clone();
        let (ra, rb) = tokio::join!(
            async move { writer_a.update_batch(&ua).await },
            async move { writer_b.update_batch(&ub).await },
        );
        ra.expect("writer A update_batch");
        rb.expect("writer B update_batch");

        // Reopen against the shared backend so we read the post-merge
        // root from durable state, not from either writer's hot cache.
        let final_smt = PersistentSmt::open(SharedMem(shared.clone()))
            .await
            .expect("reopen final view");
        let final_root = final_smt.root().await.expect("final root");

        // The reference root is computed by applying BOTH batches to a
        // fresh in-memory tree, in either order — last-wins on a key is
        // irrelevant here because the two batches touch disjoint keys.
        let mut all = updates_a.clone();
        all.extend(updates_b.clone());
        let reference_root = reference(&all).root();

        assert_eq!(
            final_root, reference_root,
            "audit H-4: concurrent update_batch calls lost some leaves — \
             the backend writer lock is not serialising correctly"
        );

        // Every leaf from BOTH writers must be readable from the shared
        // backend. If H-4 regressed, the second writer's `put_nodes`
        // would silently strand the first writer's leaves under stale
        // internal paths and they wouldn't reconstruct under the root.
        for u in &all {
            let got = final_smt.get(&u.key).await.expect("get");
            assert_eq!(
                got,
                Some(u.value_hash),
                "leaf {:?} missing after concurrent update_batch — H-4 regression",
                u.key
            );
        }
    }
}
