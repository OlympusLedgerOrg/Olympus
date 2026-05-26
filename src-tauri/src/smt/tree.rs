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

/// A single leaf insert/update. Build `key` via
/// `olympus_crypto::smt::shard_record_key`.
#[derive(Debug, Clone)]
pub struct LeafUpdate {
    pub key: [u8; 32],
    pub value_hash: [u8; 32],
    pub parser_id: String,
    pub canonical_parser_version: String,
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
        parser_id: &str,
        canonical_parser_version: &str,
    ) -> anyhow::Result<[u8; 32]> {
        self.update_batch(&[LeafUpdate {
            key,
            value_hash,
            parser_id: parser_id.to_string(),
            canonical_parser_version: canonical_parser_version.to_string(),
        }])
        .await
    }

    /// Insert/update a batch of leaves, processing each 64-bit shard's subtree
    /// concurrently and merging the top 64 levels once. Returns the new root.
    pub async fn update_batch(&mut self, updates: &[LeafUpdate]) -> anyhow::Result<[u8; 32]> {
        if updates.is_empty() {
            return self.root().await;
        }

        // Dedup by key; the last update for a key wins (matches sequential apply).
        let mut latest: HashMap<[u8; 32], LeafRecord> = HashMap::new();
        for u in updates {
            assert!(!u.parser_id.is_empty(), "parser_id must be non-empty");
            assert!(
                !u.canonical_parser_version.is_empty(),
                "canonical_parser_version must be non-empty"
            );
            latest.insert(
                u.key,
                LeafRecord {
                    value_hash: u.value_hash,
                    parser_id: u.parser_id.clone(),
                    canonical_parser_version: u.canonical_parser_version.clone(),
                },
            );
        }
        let keys: Vec<[u8; 32]> = latest.keys().copied().collect();

        // 1. Prefetch the sibling working set, then overlay the updated leaves.
        let ws = self.build_working_set(&keys).await?;
        let mut nodes = ws.nodes;
        let mut leaves = ws.leaves;
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
        let merge_frontier: HashSet<NodePath> =
            groups.keys().map(|g| bytes_to_bits(g)).collect();
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
                    parser_id: rec.parser_id.clone(),
                    canonical_parser_version: rec.canonical_parser_version.clone(),
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
                } else {
                    want_nodes.insert(sib);
                }
            }
            want_leaves.insert(*key);
        }

        let node_query: Vec<NodePath> = want_nodes.into_iter().collect();
        for (p, h) in self.backend.get_nodes(&node_query).await? {
            nodes.insert(p, h);
        }
        let leaf_query: Vec<[u8; 32]> = want_leaves.into_iter().collect();
        let leaves = self.backend.get_leaves(&leaf_query).await?;
        Ok(WorkingSet { nodes, leaves })
    }
}

// ── pure helpers (no I/O — safe to run on the blocking pool) ────────────────

fn leaf_hash_of(key: &[u8; 32], rec: &LeafRecord) -> [u8; 32] {
    leaf_hash(
        key,
        &rec.value_hash,
        rec.parser_id.as_bytes(),
        rec.canonical_parser_version.as_bytes(),
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
    written.into_iter().map(|p| (p.clone(), slice[&p])).collect()
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
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
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

    fn upd(key: [u8; 32], v: u8) -> LeafUpdate {
        LeafUpdate {
            key,
            value_hash: [v; 32],
            parser_id: "docling@2.3.1".into(),
            canonical_parser_version: "v1".into(),
        }
    }

    /// Build a reference in-memory tree from the same updates (last-wins).
    fn reference(updates: &[LeafUpdate]) -> SparseMerkleTree {
        let mut t = SparseMerkleTree::new();
        for u in updates {
            t.update(u.key, u.value_hash, &u.parser_id, &u.canonical_parser_version);
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
        let k = shard_record_key("shard-a", &[1u8; 32]);
        let updates = vec![upd(k, 0xAA)];
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
            let key = shard_record_key(shard, &rng.rk());
            updates.push(upd(key, (i % 251) as u8));
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
            assert_eq!(*got, reference_tree.prove(key), "proof mismatch vs reference");
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
            let key = shard_record_key(if i % 2 == 0 { "s0" } else { "s1" }, &rng.rk());
            all.push(upd(key, (i % 250) as u8));
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
        let present = shard_record_key("shard-a", &[1u8; 32]);
        let updates = vec![upd(present, 0xAA)];
        let root = smt.update_batch(&updates).await.unwrap();

        let absent = shard_record_key("shard-a", &[9u8; 32]);
        let proof = smt.prove(&absent).await.unwrap();
        assert!(matches!(proof, Proof::NonExistence(_)));
        assert!(verify_proof(&proof, Some(&root)));
        assert_eq!(proof, reference(&updates).prove(&absent));
    }

    #[tokio::test]
    async fn shard_subtree_root_matches_reference() {
        let mut smt = PersistentSmt::open(MemBackend::new()).await.unwrap();
        let updates = vec![
            upd(shard_record_key("shard-a", &[1u8; 32]), 0xAA),
            upd(shard_record_key("shard-b", &[2u8; 32]), 0xBB),
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
        smt.update_batch(&[upd(k, 0x11)]).await.unwrap();
        let root = smt.update_batch(&[upd(k, 0x22)]).await.unwrap();

        let reference_root = reference(&[upd(k, 0x11), upd(k, 0x22)]).root();
        assert_eq!(root, reference_root);
        assert_eq!(smt.get(&k).await.unwrap(), Some([0x22u8; 32]));
    }
}
