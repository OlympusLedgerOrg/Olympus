//! Sparse Merkle Tree implementation for CD-HS-ST
//!
//! This module implements a 256-height sparse Merkle tree with:
//! - Precomputed empty hashes for efficient sparse operations
//! - In-memory storage (persistence is handled by the Go sequencer)
//! - Inclusion and non-inclusion proofs

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::crypto;
use tokio::sync::RwLock;

static EMPTY_HASHES: LazyLock<[[u8; 32]; 257]> = LazyLock::new(|| {
    let mut empty = [[0u8; 32]; 257];
    empty[0] = crypto::empty_leaf();
    for index in 1..empty.len() {
        empty[index] = crypto::hash_node(&empty[index - 1], &empty[index - 1]);
    }
    empty
});

/// A 256-level sparse Merkle tree
pub struct SparseMerkleTree {
    /// Internal state (nodes and leaves)
    state: RwLock<TreeState>,
}

struct TreeState {
    /// Mapping from (level, path_bits[0..=level]) to hash
    nodes: HashMap<(u8, Vec<u8>), [u8; 32]>,
    /// Mapping from key to (value_hash, parser_id, canonical_parser_version).
    /// The parser fields are bound into the leaf hash per ADR-0003.
    leaves: HashMap<[u8; 32], ([u8; 32], String, String)>,
    /// Current root
    root: [u8; 32],
    /// Number of non-empty leaves
    size: u64,
}

/// Node delta for persistence.
///
/// `path` is the **packed path prefix** at the given level (not the full
/// 32-byte leaf key).  This matches the encoding used by the PyO3 extension
/// in `src/smt.rs::incremental_update_raw()` and `storage/postgres.py`.
pub struct NodeDelta {
    pub path: Vec<u8>,
    pub level: u32,
    pub hash: [u8; 32],
}

/// Inclusion proof
pub struct InclusionProof {
    pub value_hash: [u8; 32],
    /// Parser identity bound into the leaf hash (ADR-0003).
    pub parser_id: String,
    /// Operator-controlled canonical parser version bound into the leaf hash
    /// (ADR-0003).
    pub canonical_parser_version: String,
    pub siblings: Vec<[u8; 32]>,
}

/// Non-inclusion proof
pub struct NonInclusionProof {
    pub siblings: Vec<[u8; 32]>,
}

/// A fully-computed SMT update that has not yet been applied to live state.
///
/// Produced by `SparseMerkleTree::compute_update`; consumed by
/// `SparseMerkleTree::apply_prepared`. This is the per-transaction payload
/// that the prepared-transaction LRU in `main.rs` holds between
/// `PrepareUpdate` and `CommitPreparedUpdate` so storage failure between
/// those two RPCs cannot leave the live SMT ahead of durable state.
pub struct PreparedUpdate {
    /// Root the SMT held when this update was computed. `apply_prepared`
    /// refuses to commit if the live root has moved on (another commit
    /// raced us).
    pub prior_root: [u8; 32],
    /// Root the SMT will hold after `apply_prepared` succeeds.
    pub new_root: [u8; 32],
    /// Tree size after commit (matches `Update`'s `tree_size`).
    pub new_tree_size: u64,
    /// Whether this commit will create a brand-new leaf (vs. overwrite an
    /// existing one). Needed so `apply_prepared` updates `size` correctly.
    pub is_new_leaf: bool,
    /// Leaf key.
    pub key: [u8; 32],
    /// Leaf value hash.
    pub value_hash: [u8; 32],
    /// Parser identity (ADR-0003).
    pub parser_id: String,
    /// Canonical parser version (ADR-0003).
    pub canonical_parser_version: String,
    /// Per-level deltas. `nodes_to_write[level]` is the (level, packed-path,
    /// hash) triple that must be inserted into `state.nodes` on commit.
    pub nodes_to_write: Vec<((u8, Vec<u8>), [u8; 32])>,
    /// Wire-format deltas to return to the sequencer for persistence.
    pub deltas: Vec<NodeDelta>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        let empty_hashes = empty_hashes();
        let root = empty_hashes[256]; // Root of empty tree

        Self {
            state: RwLock::new(TreeState {
                nodes: HashMap::new(),
                leaves: HashMap::new(),
                root,
                size: 0,
            }),
        }
    }

    /// Update a leaf and return new root and deltas.
    ///
    /// `parser_id` and `canonical_parser_version` are bound into the leaf
    /// hash domain per ADR-0003. Both MUST be non-empty.
    ///
    /// This is the single-phase API kept for backwards compatibility and
    /// for callers without an external durability requirement (tests). New
    /// production code paths SHOULD use `compute_update` + `apply_prepared`
    /// (exposed over gRPC as `PrepareUpdate` / `CommitPreparedUpdate`) so
    /// that durable state and live state cannot diverge on storage failure.
    pub async fn update(
        &self,
        key: &[u8; 32],
        value_hash: &[u8; 32],
        parser_id: &str,
        canonical_parser_version: &str,
    ) -> Result<([u8; 32], Vec<NodeDelta>), String> {
        // Hold the write lock across compute+apply so this single-phase
        // call remains atomic from a concurrent reader's perspective. Inner
        // helpers take a `&mut TreeState` so they don't try to re-lock.
        let mut state = self.state.write().await;
        let prepared = Self::compute_update_locked(
            &state,
            key,
            value_hash,
            parser_id,
            canonical_parser_version,
        )?;
        // Drain `deltas` into the return value before applying, since
        // `apply_prepared_locked` consumes the rest of the prepared payload.
        let new_root = prepared.new_root;
        let deltas = {
            // Move out by reconstructing without the deltas field clone.
            let PreparedUpdate {
                prior_root,
                new_root: _,
                new_tree_size,
                is_new_leaf,
                key,
                value_hash,
                parser_id,
                canonical_parser_version,
                nodes_to_write,
                deltas,
            } = prepared;
            let to_apply = PreparedUpdate {
                prior_root,
                new_root,
                new_tree_size,
                is_new_leaf,
                key,
                value_hash,
                parser_id,
                canonical_parser_version,
                nodes_to_write,
                deltas: Vec::new(),
            };
            Self::apply_prepared_locked(&mut state, to_apply)?;
            deltas
        };
        Ok((new_root, deltas))
    }

    /// Phase 1 of two-phase commit: compute the new root + deltas for an
    /// update WITHOUT mutating the live SMT.
    ///
    /// The returned `PreparedUpdate` captures everything needed for
    /// `apply_prepared` to commit the update atomically later, plus the
    /// `prior_root` that `apply_prepared` uses to detect a stale prepare.
    pub async fn compute_update(
        &self,
        key: &[u8; 32],
        value_hash: &[u8; 32],
        parser_id: &str,
        canonical_parser_version: &str,
    ) -> Result<PreparedUpdate, String> {
        let state = self.state.read().await;
        Self::compute_update_locked(&state, key, value_hash, parser_id, canonical_parser_version)
    }

    /// Phase 2 of two-phase commit: atomically apply a prepared update.
    ///
    /// Fails with `"stale prepared transaction"` if the live root has
    /// advanced since `compute_update` produced this `PreparedUpdate`.
    /// On stale rejection, the live SMT is left untouched and the caller
    /// should re-prepare against the current root.
    pub async fn apply_prepared(&self, prepared: PreparedUpdate) -> Result<[u8; 32], String> {
        let mut state = self.state.write().await;
        Self::apply_prepared_locked(&mut state, prepared)
    }

    fn compute_update_locked(
        state: &TreeState,
        key: &[u8; 32],
        value_hash: &[u8; 32],
        parser_id: &str,
        canonical_parser_version: &str,
    ) -> Result<PreparedUpdate, String> {
        if parser_id.is_empty() {
            return Err("parser_id must be a non-empty string".to_string());
        }
        if canonical_parser_version.is_empty() {
            return Err("canonical_parser_version must be a non-empty string".to_string());
        }

        let prior_root = state.root;
        let is_new_leaf = !state.leaves.contains_key(key);

        // Convert key to path bits.
        let path_bits = key_to_path_bits(key);

        // Compute leaf hash.
        let leaf_hash = crypto::hash_leaf(
            key,
            value_hash,
            parser_id.as_bytes(),
            canonical_parser_version.as_bytes(),
        );

        let empty_hashes = empty_hashes();
        let mut current_hash = leaf_hash;
        let mut nodes_to_write: Vec<((u8, Vec<u8>), [u8; 32])> = Vec::with_capacity(256);
        let mut deltas: Vec<NodeDelta> = Vec::with_capacity(256);

        for level in (0..256).rev() {
            let bit = path_bits[level];

            // Stage the node we'd insert at (level, path_prefix). We do not
            // touch state.nodes here — only buffer the writes for the
            // commit phase.
            let node_path = path_bits[0..=level].to_vec();
            nodes_to_write.push(((level as u8, node_path.clone()), current_hash));

            let sibling_path = sibling_path_bits(&path_bits, level);

            // Read the sibling from the LIVE state (we haven't applied any
            // of our own writes yet, so this is consistent).
            //
            // IMPORTANT: a concurrent prepare against an *overlapping* key
            // may have already buffered a write at this same `(level,
            // sibling_path)` in its own PreparedUpdate. That doesn't show
            // up here — which is exactly why `apply_prepared_locked`
            // refuses to commit if `state.root` has moved since prepare.
            let sibling_hash = state
                .nodes
                .get(&(level as u8, sibling_path))
                .copied()
                .unwrap_or(empty_hashes[255 - level]);

            let (left, right) = if bit == 0 {
                (current_hash, sibling_hash)
            } else {
                (sibling_hash, current_hash)
            };

            let parent_hash = crypto::hash_node(&left, &right);

            let packed_path = if level == 0 {
                Vec::new()
            } else {
                pack_path_bits(&path_bits[..level])
            };

            deltas.push(NodeDelta {
                path: packed_path,
                level: level as u32,
                hash: current_hash,
            });

            current_hash = parent_hash;
        }

        let new_root = current_hash;
        let new_tree_size = if is_new_leaf {
            state.size + 1
        } else {
            state.size
        };

        Ok(PreparedUpdate {
            prior_root,
            new_root,
            new_tree_size,
            is_new_leaf,
            key: *key,
            value_hash: *value_hash,
            parser_id: parser_id.to_string(),
            canonical_parser_version: canonical_parser_version.to_string(),
            nodes_to_write,
            deltas,
        })
    }

    fn apply_prepared_locked(
        state: &mut TreeState,
        prepared: PreparedUpdate,
    ) -> Result<[u8; 32], String> {
        // Stale-prepare detection: refuse to apply if some other commit
        // moved the root since `compute_update` ran. The Go sequencer is
        // expected to Abort and re-prepare in that case.
        if state.root != prepared.prior_root {
            return Err("stale prepared transaction: root advanced since prepare".to_string());
        }

        // Insert the leaf (with its parser provenance, ADR-0003).
        state.leaves.insert(
            prepared.key,
            (
                prepared.value_hash,
                prepared.parser_id,
                prepared.canonical_parser_version,
            ),
        );

        if prepared.is_new_leaf {
            state.size += 1;
        }

        // Apply the staged node writes.
        for (k, v) in prepared.nodes_to_write {
            state.nodes.insert(k, v);
        }

        state.root = prepared.new_root;
        Ok(prepared.new_root)
    }

    /// Get current root
    pub async fn root(&self) -> [u8; 32] {
        self.state.read().await.root
    }

    /// Get tree size (number of non-empty leaves)
    pub async fn size(&self) -> u64 {
        self.state.read().await.size
    }

    /// Replay a sequence of `(key, value_hash, parser_id, canonical_parser_version)`
    /// leaf insertions in order.
    ///
    /// Iterates through the provided tuples and calls `self.update()` for
    /// each, using the same path as live inserts so the resulting root is
    /// identical. Returns the final root hash after all leaves have been
    /// applied.
    pub async fn replay(
        &self,
        leaves: Vec<([u8; 32], [u8; 32], String, String)>,
    ) -> Result<[u8; 32], String> {
        for (key, value_hash, parser_id, canonical_parser_version) in leaves {
            self.update(&key, &value_hash, &parser_id, &canonical_parser_version)
                .await?;
        }
        Ok(self.root().await)
    }

    /// Generate inclusion proof
    pub async fn prove_inclusion(
        &self,
        key: &[u8; 32],
        root: &[u8; 32],
    ) -> Result<InclusionProof, String> {
        let state = self.state.read().await;

        // Check if key exists
        let (value_hash, parser_id, canonical_parser_version) = state
            .leaves
            .get(key)
            .ok_or_else(|| "Key not found".to_string())?;

        // Check root matches
        if &state.root != root {
            return Err("Root mismatch".to_string());
        }

        let path_bits = key_to_path_bits(key);
        let empty_hashes = empty_hashes();
        let mut siblings = vec![[0u8; 32]; 256];

        for level in (0..256).rev() {
            let sibling_path = sibling_path_bits(&path_bits, level);

            let sibling_hash = state
                .nodes
                .get(&(level as u8, sibling_path))
                .copied()
                .unwrap_or(empty_hashes[255 - level]);

            siblings[level] = sibling_hash;
        }

        Ok(InclusionProof {
            value_hash: *value_hash,
            parser_id: parser_id.clone(),
            canonical_parser_version: canonical_parser_version.clone(),
            siblings,
        })
    }

    /// Generate non-inclusion proof
    pub async fn prove_non_inclusion(
        &self,
        key: &[u8; 32],
        root: &[u8; 32],
    ) -> Result<NonInclusionProof, String> {
        let state = self.state.read().await;

        // Check if key doesn't exist
        if state.leaves.contains_key(key) {
            return Err("Key exists".to_string());
        }

        // Check root matches
        if &state.root != root {
            return Err("Root mismatch".to_string());
        }

        let path_bits = key_to_path_bits(key);
        let empty_hashes = empty_hashes();
        let mut siblings = vec![[0u8; 32]; 256];

        for level in (0..256).rev() {
            let sibling_path = sibling_path_bits(&path_bits, level);

            let sibling_hash = state
                .nodes
                .get(&(level as u8, sibling_path))
                .copied()
                .unwrap_or(empty_hashes[255 - level]);

            siblings[level] = sibling_hash;
        }

        Ok(NonInclusionProof { siblings })
    }
}

/// Verify an inclusion proof.
///
/// `parser_id` and `canonical_parser_version` are bound into the leaf hash
/// per ADR-0003. Both MUST be non-empty; passing an empty string returns
/// `false` immediately.
pub fn verify_inclusion(
    key: &[u8; 32],
    value_hash: &[u8; 32],
    parser_id: &str,
    canonical_parser_version: &str,
    siblings: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if siblings.len() != 256 {
        return false;
    }
    if parser_id.is_empty() || canonical_parser_version.is_empty() {
        return false;
    }

    let path_bits = key_to_path_bits(key);
    let mut current_hash = crypto::hash_leaf(
        key,
        value_hash,
        parser_id.as_bytes(),
        canonical_parser_version.as_bytes(),
    );

    for level in (0..256).rev() {
        let bit = path_bits[level];
        let sibling = siblings[level];

        let (left, right) = if bit == 0 {
            (current_hash, sibling)
        } else {
            (sibling, current_hash)
        };

        current_hash = crypto::hash_node(&left, &right);
    }

    &current_hash == root
}

/// Verify a non-inclusion proof
pub fn verify_non_inclusion(key: &[u8; 32], siblings: &[[u8; 32]], root: &[u8; 32]) -> bool {
    if siblings.len() != 256 {
        return false;
    }

    let path_bits = key_to_path_bits(key);
    let empty_leaf = crypto::empty_leaf();
    let mut current_hash = empty_leaf;

    for level in (0..256).rev() {
        let bit = path_bits[level];
        let sibling = siblings[level];

        let (left, right) = if bit == 0 {
            (current_hash, sibling)
        } else {
            (sibling, current_hash)
        };

        current_hash = crypto::hash_node(&left, &right);
    }

    &current_hash == root
}

/// Convert 32-byte key to 256-bit path (list of 0s and 1s)
fn key_to_path_bits(key: &[u8; 32]) -> Vec<u8> {
    let mut path = Vec::with_capacity(256);
    for byte in key {
        for i in 0..8 {
            // Extract bit (MSB first)
            let bit = (byte >> (7 - i)) & 1;
            path.push(bit);
        }
    }
    path
}

/// Get sibling path bits at a given level.
///
/// Precondition: `level` must be less than `path_bits.len()` (always holds
/// for the 256-level tree where `path_bits` has exactly 256 elements and
/// `level` ranges over 0..=255).
fn sibling_path_bits(path_bits: &[u8], level: usize) -> Vec<u8> {
    let mut sibling = path_bits[0..=level].to_vec();
    sibling[level] = 1 - sibling[level];
    sibling
}

/// Precompute empty hashes for sparse tree
/// empty_hashes[i] = hash of empty subtree at height i
fn empty_hashes() -> &'static [[u8; 32]; 257] {
    &EMPTY_HASHES
}

/// Pack a slice of path bits (0s and 1s) into bytes, MSB first.
///
/// Matches `pack_path_bits` in `src/smt.rs` (PyO3) and
/// `StorageLayer._encode_path()` in `storage/postgres.py`.
/// An empty slice returns an empty Vec. A 256-element slice returns 32 bytes.
fn pack_path_bits(bits: &[u8]) -> Vec<u8> {
    if bits.is_empty() {
        return Vec::new();
    }
    let num_bytes = bits.len().div_ceil(8);
    let mut result = vec![0u8; num_bytes];
    for (i, &bit) in bits.iter().enumerate() {
        if bit != 0 {
            result[i >> 3] |= 1 << (7 - (i & 7));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_empty_tree() {
        let tree = SparseMerkleTree::new();
        assert_eq!(tree.size().await, 0);

        let root = tree.root().await;
        assert_eq!(root.len(), 32);

        let mut recomputed = [[0u8; 32]; 257];
        recomputed[0] = crypto::empty_leaf();
        for i in 1..recomputed.len() {
            recomputed[i] = crypto::hash_node(&recomputed[i - 1], &recomputed[i - 1]);
        }
        assert_eq!(root, recomputed[256]);
        assert_eq!(root, empty_hashes()[256]);
    }

    #[tokio::test]
    async fn test_update() {
        let tree = SparseMerkleTree::new();
        let key = [1u8; 32];
        let value_hash = [2u8; 32];

        let result = tree.update(&key, &value_hash, "docling@2.3.1", "v1").await;
        assert!(result.is_ok());

        let (new_root, deltas) = result.unwrap();
        assert_eq!(new_root.len(), 32);
        assert!(!deltas.is_empty());
        assert_eq!(tree.size().await, 1);
    }

    #[tokio::test]
    async fn test_single_key_inclusion_proof() {
        let tree = SparseMerkleTree::new();
        let key = [1u8; 32];
        let value_hash = [2u8; 32];

        tree.update(&key, &value_hash, "docling@2.3.1", "v1").await.unwrap();
        let root = tree.root().await;

        let proof = tree.prove_inclusion(&key, &root).await.unwrap();
        assert_eq!(proof.siblings.len(), 256);
        assert!(verify_inclusion(&key, &value_hash, "docling@2.3.1", "v1", &proof.siblings, &root));
    }

    #[tokio::test]
    async fn test_two_key_inclusion_proofs() {
        let tree = SparseMerkleTree::new();

        // Two keys that differ at bit 0 (MSB)
        let key_a = [0u8; 32];
        let mut key_b = [0u8; 32];
        key_b[0] = 0x80; // bit 0 = 1

        let val_a = [0xAAu8; 32];
        let val_b = [0xBBu8; 32];

        tree.update(&key_a, &val_a, "docling@2.3.1", "v1").await.unwrap();
        tree.update(&key_b, &val_b, "docling@2.3.1", "v1").await.unwrap();
        let root = tree.root().await;

        // Both proofs must verify
        let proof_a = tree.prove_inclusion(&key_a, &root).await.unwrap();
        assert!(verify_inclusion(&key_a, &val_a, "docling@2.3.1", "v1", &proof_a.siblings, &root));

        let proof_b = tree.prove_inclusion(&key_b, &root).await.unwrap();
        assert!(verify_inclusion(&key_b, &val_b, "docling@2.3.1", "v1", &proof_b.siblings, &root));

        // Siblings should include actual node hashes, not all empty
        let empty_hashes = empty_hashes();
        let has_non_empty = proof_a
            .siblings
            .iter()
            .enumerate()
            .any(|(i, s)| *s != empty_hashes[255 - i]);
        assert!(
            has_non_empty,
            "Two-key proof must have at least one non-empty sibling"
        );
    }

    #[tokio::test]
    async fn test_three_key_inclusion_proofs() {
        let tree = SparseMerkleTree::new();

        // Three keys: A and C share bit 0 but differ at bit 1
        let key_a = [0u8; 32]; // bits: 0, 0, ...
        let mut key_b = [0u8; 32];
        key_b[0] = 0x80; // bits: 1, 0, ...
        let mut key_c = [0u8; 32];
        key_c[0] = 0x40; // bits: 0, 1, ...

        let val = [0xFFu8; 32];

        tree.update(&key_a, &val, "docling@2.3.1", "v1").await.unwrap();
        tree.update(&key_b, &val, "docling@2.3.1", "v1").await.unwrap();
        tree.update(&key_c, &val, "docling@2.3.1", "v1").await.unwrap();
        let root = tree.root().await;

        for key in [key_a, key_b, key_c] {
            let proof = tree.prove_inclusion(&key, &root).await.unwrap();
            assert!(
                verify_inclusion(&key, &val, "docling@2.3.1", "v1", &proof.siblings, &root),
                "Inclusion proof failed for key {:?}",
                &key[..4]
            );
        }
    }

    #[tokio::test]
    async fn test_many_keys_inclusion_proofs() {
        let tree = SparseMerkleTree::new();
        let mut keys = Vec::new();
        let mut vals = Vec::new();

        for i in 0u8..10 {
            let mut key = [0u8; 32];
            key[0] = i;
            let mut val = [0u8; 32];
            val[0] = i + 100;
            tree.update(&key, &val, "docling@2.3.1", "v1").await.unwrap();
            keys.push(key);
            vals.push(val);
        }

        let root = tree.root().await;
        for (key, val) in keys.iter().zip(vals.iter()) {
            let proof = tree.prove_inclusion(key, &root).await.unwrap();
            assert!(
                verify_inclusion(key, val, "docling@2.3.1", "v1", &proof.siblings, &root),
                "Proof failed for key starting with {:02x}",
                key[0]
            );
        }
    }

    #[tokio::test]
    async fn test_non_inclusion_proof() {
        let tree = SparseMerkleTree::new();
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let value_hash = [3u8; 32];

        tree.update(&key1, &value_hash, "docling@2.3.1", "v1").await.unwrap();
        let root = tree.root().await;

        let proof = tree.prove_non_inclusion(&key2, &root).await.unwrap();
        assert_eq!(proof.siblings.len(), 256);
        assert!(verify_non_inclusion(&key2, &proof.siblings, &root));
    }

    #[tokio::test]
    async fn test_non_inclusion_with_multiple_keys() {
        let tree = SparseMerkleTree::new();
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let absent = [3u8; 32];
        let val = [0xAAu8; 32];

        tree.update(&key1, &val, "docling@2.3.1", "v1").await.unwrap();
        tree.update(&key2, &val, "docling@2.3.1", "v1").await.unwrap();
        let root = tree.root().await;

        let proof = tree.prove_non_inclusion(&absent, &root).await.unwrap();
        assert!(verify_non_inclusion(&absent, &proof.siblings, &root));
    }

    #[tokio::test]
    async fn test_insert_order_independence() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let val_a = [0xAu8; 32];
        let val_b = [0xBu8; 32];

        let tree1 = SparseMerkleTree::new();
        tree1.update(&key_a, &val_a, "docling@2.3.1", "v1").await.unwrap();
        tree1.update(&key_b, &val_b, "docling@2.3.1", "v1").await.unwrap();

        let tree2 = SparseMerkleTree::new();
        tree2.update(&key_b, &val_b, "docling@2.3.1", "v1").await.unwrap();
        tree2.update(&key_a, &val_a, "docling@2.3.1", "v1").await.unwrap();

        assert_eq!(
            tree1.root().await,
            tree2.root().await,
            "Root must be independent of insertion order"
        );
    }

    #[tokio::test]
    async fn test_update_existing_key() {
        let tree = SparseMerkleTree::new();
        let key = [1u8; 32];
        let val1 = [2u8; 32];
        let val2 = [3u8; 32];

        tree.update(&key, &val1, "docling@2.3.1", "v1").await.unwrap();
        let root1 = tree.root().await;

        tree.update(&key, &val2, "docling@2.3.1", "v1").await.unwrap();
        let root2 = tree.root().await;

        assert_ne!(root1, root2, "Root must change when value changes");
        assert_eq!(tree.size().await, 1, "Size should not increase on update");

        let proof = tree.prove_inclusion(&key, &root2).await.unwrap();
        assert!(verify_inclusion(&key, &val2, "docling@2.3.1", "v1", &proof.siblings, &root2));
    }

    #[test]
    fn test_key_to_path_bits() {
        let key = [0b10101010u8; 32];
        let bits = key_to_path_bits(&key);

        assert_eq!(bits.len(), 256);
        // First byte should give: 1,0,1,0,1,0,1,0
        assert_eq!(bits[0], 1);
        assert_eq!(bits[1], 0);
        assert_eq!(bits[2], 1);
        assert_eq!(bits[3], 0);
    }

    #[test]
    fn test_sibling_path_bits_length_and_flip() {
        let path = vec![0u8, 1, 0, 1, 1, 0, 0, 1]; // 8 bits for simplicity

        // At level 0: path[0..=0] with bit 0 flipped
        let sib0 = sibling_path_bits(&path, 0);
        assert_eq!(sib0.len(), 1);
        assert_eq!(sib0[0], 1); // flipped from 0

        // At level 3: path[0..=3] with bit 3 flipped
        let sib3 = sibling_path_bits(&path, 3);
        assert_eq!(sib3.len(), 4);
        assert_eq!(sib3, vec![0, 1, 0, 0]); // last bit flipped from 1 to 0

        // At level 7: path[0..=7] with bit 7 flipped
        let sib7 = sibling_path_bits(&path, 7);
        assert_eq!(sib7.len(), 8);
        assert_eq!(sib7, vec![0, 1, 0, 1, 1, 0, 0, 0]); // last bit flipped from 1 to 0
    }

    // ------------------------------------------------------------------
    // H-2 two-phase commit tests: compute_update + apply_prepared
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_compute_update_does_not_mutate_state() {
        // Sacred Law: a prepared-but-uncommitted update MUST NOT appear
        // in any signed root. Verify by computing an update, then
        // observing that root() / size() are unchanged.
        let tree = SparseMerkleTree::new();
        let prior_root = tree.root().await;
        let prior_size = tree.size().await;

        let prepared = tree
            .compute_update(&[1u8; 32], &[2u8; 32], "docling@2.3.1", "v1")
            .await
            .expect("compute_update must succeed on empty tree");

        assert_eq!(prepared.prior_root, prior_root, "prior_root snapshot");
        assert_ne!(prepared.new_root, prior_root, "new_root must differ");
        assert!(prepared.is_new_leaf);
        assert_eq!(prepared.deltas.len(), 256);

        // Critically: live state must be untouched.
        assert_eq!(tree.root().await, prior_root, "live root must not advance");
        assert_eq!(tree.size().await, prior_size, "live size must not advance");
    }

    #[tokio::test]
    async fn test_apply_prepared_advances_state_to_predicted_root() {
        let tree = SparseMerkleTree::new();
        let prepared = tree
            .compute_update(&[7u8; 32], &[8u8; 32], "docling@2.3.1", "v1")
            .await
            .unwrap();
        let predicted = prepared.new_root;

        let applied = tree.apply_prepared(prepared).await.unwrap();
        assert_eq!(applied, predicted);
        assert_eq!(tree.root().await, predicted);
        assert_eq!(tree.size().await, 1);
    }

    #[tokio::test]
    async fn test_apply_prepared_rejects_stale_prepare() {
        // Atomic-swap requirement: if another commit raced us, the
        // prepared transaction's prior_root no longer matches the live
        // root and apply_prepared MUST refuse to commit.
        let tree = SparseMerkleTree::new();

        // Two prepares against the empty tree.
        let p1 = tree
            .compute_update(&[1u8; 32], &[2u8; 32], "docling@2.3.1", "v1")
            .await
            .unwrap();
        let p2 = tree
            .compute_update(&[3u8; 32], &[4u8; 32], "docling@2.3.1", "v1")
            .await
            .unwrap();
        assert_eq!(p1.prior_root, p2.prior_root, "both saw same prior root");

        // First prepare commits — advances live root.
        tree.apply_prepared(p1).await.unwrap();

        // Second prepare is now stale.
        let err = tree.apply_prepared(p2).await.expect_err("stale prepare must fail");
        assert!(
            err.contains("stale prepared transaction"),
            "error must identify staleness, got: {}",
            err
        );

        // Live state must still reflect the FIRST commit only.
        assert_eq!(tree.size().await, 1);
    }

    #[tokio::test]
    async fn test_compute_apply_equivalent_to_update() {
        // Property: compute_update + apply_prepared must produce the
        // exact same root + delta set as a single-phase update().
        let tree_a = SparseMerkleTree::new();
        let tree_b = SparseMerkleTree::new();
        let key = [42u8; 32];
        let value = [99u8; 32];

        let (root_a, deltas_a) = tree_a.update(&key, &value, "p@1", "v1").await.unwrap();
        let prepared = tree_b
            .compute_update(&key, &value, "p@1", "v1")
            .await
            .unwrap();
        let predicted_root = prepared.new_root;
        let deltas_b: Vec<NodeDelta> = prepared
            .deltas
            .iter()
            .map(|d| NodeDelta {
                path: d.path.clone(),
                level: d.level,
                hash: d.hash,
            })
            .collect();
        let root_b = tree_b.apply_prepared(prepared).await.unwrap();

        assert_eq!(root_a, root_b);
        assert_eq!(predicted_root, root_b);
        assert_eq!(deltas_a.len(), deltas_b.len());
        for (a, b) in deltas_a.iter().zip(deltas_b.iter()) {
            assert_eq!(a.level, b.level);
            assert_eq!(a.path, b.path);
            assert_eq!(a.hash, b.hash);
        }
    }

    #[tokio::test]
    async fn test_compute_update_rejects_empty_provenance() {
        let tree = SparseMerkleTree::new();
        assert!(tree
            .compute_update(&[1u8; 32], &[2u8; 32], "", "v1")
            .await
            .is_err());
        assert!(tree
            .compute_update(&[1u8; 32], &[2u8; 32], "p@1", "")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_two_phase_random_sequence_matches_replay() {
        // Property test: a random sequence of prepare/commit/abort
        // operations on tree A must leave A's root equal to a
        // single-phase replay of just the COMMITTED leaves on tree B.
        // This is the core "no lost updates / no phantom updates"
        // property that the H-2 protocol must enforce.
        use std::collections::HashMap;

        // Deterministic xorshift PRNG so failures reproduce.
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
            fn key(&mut self) -> [u8; 32] {
                let mut k = [0u8; 32];
                // Use only 4 distinct keys so prepares overlap heavily.
                let id = (self.next() % 4) as u8;
                k[31] = id;
                k
            }
            fn val(&mut self) -> [u8; 32] {
                let mut v = [0u8; 32];
                let id = (self.next() % 256) as u8;
                v[0] = id;
                v
            }
        }

        let tree_live = SparseMerkleTree::new();
        // Track committed leaves in insertion order so we can replay.
        let mut committed: Vec<([u8; 32], [u8; 32])> = Vec::new();
        // Last-write-wins map for final-state comparison.
        let mut latest: HashMap<[u8; 32], [u8; 32]> = HashMap::new();

        let mut rng = Rng(0xDEAD_BEEF_1234_5678);
        // 1000 random ops as required by the spec property test.
        for _ in 0..1000 {
            let op = rng.next() % 3;
            let key = rng.key();
            let val = rng.val();
            let prepared = tree_live
                .compute_update(&key, &val, "p@1", "v1")
                .await
                .expect("compute must succeed");
            match op {
                0 => {
                    // Commit
                    if tree_live.apply_prepared(prepared).await.is_ok() {
                        committed.push((key, val));
                        latest.insert(key, val);
                    }
                    // If the prepare is stale (root advanced between
                    // compute and apply — only possible under concurrency,
                    // which this single-thread test avoids), fall through.
                }
                1 => {
                    // Abort: drop the prepared transaction without
                    // applying. Nothing to do here — the local
                    // `prepared` binding goes out of scope.
                    drop(prepared);
                }
                _ => {
                    // Compute-then-discard variant: same as abort but
                    // exercises a different code path.
                    drop(prepared);
                }
            }
        }

        // Replay committed leaves into a fresh tree.
        let tree_replay = SparseMerkleTree::new();
        for (k, v) in committed.iter() {
            tree_replay.update(k, v, "p@1", "v1").await.unwrap();
        }

        assert_eq!(
            tree_live.root().await,
            tree_replay.root().await,
            "live root after random prepare/commit/abort sequence must equal replay-of-commits"
        );

        // Sanity check: tree_live.size() == number of distinct keys
        // that ever got a commit (the SMT counts unique keys).
        assert_eq!(tree_live.size().await as usize, latest.len());
    }
}

