//! Sparse Merkle Tree implementation for CD-HS-ST
//!
//! This module implements a 256-height sparse Merkle tree with:
//! - Precomputed empty hashes for efficient sparse operations
//! - In-memory storage (persistence is handled by the Go sequencer)
//! - Inclusion and non-inclusion proofs

use std::collections::HashMap;
use std::sync::RwLock;

use crate::crypto;

/// A 256-level sparse Merkle tree
pub struct SparseMerkleTree {
    /// Internal state (nodes and leaves)
    state: RwLock<TreeState>,
}

struct TreeState {
    /// Mapping from (level, path_bits[0..=level]) to hash
    nodes: HashMap<(u8, Vec<u8>), [u8; 32]>,
    /// Mapping from key to value_hash
    leaves: HashMap<[u8; 32], [u8; 32]>,
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
    pub siblings: Vec<[u8; 32]>,
}

/// Non-inclusion proof
pub struct NonInclusionProof {
    pub siblings: Vec<[u8; 32]>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        let empty_hashes = precompute_empty_hashes();
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

    /// Update a leaf and return new root and deltas
    pub fn update(&self, key: &[u8; 32], value_hash: &[u8; 32]) -> Result<([u8; 32], Vec<NodeDelta>), String> {
        let mut state = self.state.write().map_err(|e| format!("Lock error: {}", e))?;
        let mut deltas = Vec::new();

        // Check if this is a new leaf
        let is_new = !state.leaves.contains_key(key);
        if is_new {
            state.size += 1;
        }

        // Store leaf
        state.leaves.insert(*key, *value_hash);

        // Convert key to path bits
        let path_bits = key_to_path_bits(key);

        // Compute leaf hash
        let leaf_hash = crypto::hash_leaf(key, value_hash);

        // Update from leaf (level 255) to root (above level 0)
        let mut current_hash = leaf_hash;
        let empty_hashes = precompute_empty_hashes();

        for level in (0..256).rev() {
            let bit = path_bits[level];

            // Store node before computing parent
            let node_path = path_bits[0..=level].to_vec();
            state.nodes.insert((level as u8, node_path.clone()), current_hash);

            let sibling_path = sibling_path_bits(&path_bits, level);

            // Get sibling hash (from nodes or use empty hash).
            // In this service, level 255 = leaf, level 0 = near root.
            // The sibling at level L is an empty subtree of height (255-L):
            //   - At level 255 (leaf): sibling height 0 → empty_hashes[0] (empty leaf)
            //   - At level 0 (root):   sibling height 255 → empty_hashes[255]
            let sibling_hash = state.nodes
                .get(&(level as u8, sibling_path.clone()))
                .copied()
                .unwrap_or(empty_hashes[255 - level]);

            // Compute parent hash
            let (left, right) = if bit == 0 {
                (current_hash, sibling_hash)
            } else {
                (sibling_hash, current_hash)
            };

            let parent_hash = crypto::hash_node(&left, &right);

            // Record delta with packed path prefix at this level
            // (matches src/smt.rs::incremental_update_raw encoding).
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

        // Update root
        state.root = current_hash;

        Ok((current_hash, deltas))
    }

    /// Get current root
    pub fn root(&self) -> [u8; 32] {
        self.state.read().unwrap().root
    }

    /// Get tree size (number of non-empty leaves)
    pub fn size(&self) -> u64 {
        self.state.read().unwrap().size
    }

    /// Generate inclusion proof
    pub fn prove_inclusion(&self, key: &[u8; 32], root: &[u8; 32]) -> Result<InclusionProof, String> {
        let state = self.state.read().map_err(|e| format!("Lock error: {}", e))?;

        // Check if key exists
        let value_hash = state.leaves.get(key)
            .ok_or_else(|| "Key not found".to_string())?;

        // Check root matches
        if &state.root != root {
            return Err("Root mismatch".to_string());
        }

        let path_bits = key_to_path_bits(key);
        let empty_hashes = precompute_empty_hashes();
        let mut siblings = vec![[0u8; 32]; 256];

        for level in (0..256).rev() {
            let sibling_path = sibling_path_bits(&path_bits, level);

            let sibling_hash = state.nodes
                .get(&(level as u8, sibling_path))
                .copied()
                .unwrap_or(empty_hashes[255 - level]);

            siblings[level] = sibling_hash;
        }

        Ok(InclusionProof {
            value_hash: *value_hash,
            siblings,
        })
    }

    /// Generate non-inclusion proof
    pub fn prove_non_inclusion(&self, key: &[u8; 32], root: &[u8; 32]) -> Result<NonInclusionProof, String> {
        let state = self.state.read().map_err(|e| format!("Lock error: {}", e))?;

        // Check if key doesn't exist
        if state.leaves.contains_key(key) {
            return Err("Key exists".to_string());
        }

        // Check root matches
        if &state.root != root {
            return Err("Root mismatch".to_string());
        }

        let path_bits = key_to_path_bits(key);
        let empty_hashes = precompute_empty_hashes();
        let mut siblings = vec![[0u8; 32]; 256];

        for level in (0..256).rev() {
            let sibling_path = sibling_path_bits(&path_bits, level);

            let sibling_hash = state.nodes
                .get(&(level as u8, sibling_path))
                .copied()
                .unwrap_or(empty_hashes[255 - level]);

            siblings[level] = sibling_hash;
        }

        Ok(NonInclusionProof { siblings })
    }
}

/// Verify an inclusion proof
pub fn verify_inclusion(
    key: &[u8; 32],
    value_hash: &[u8; 32],
    siblings: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if siblings.len() != 256 {
        return false;
    }

    let path_bits = key_to_path_bits(key);
    let mut current_hash = crypto::hash_leaf(key, value_hash);

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
pub fn verify_non_inclusion(
    key: &[u8; 32],
    siblings: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
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
fn precompute_empty_hashes() -> Vec<[u8; 32]> {
    let mut empty = vec![crypto::empty_leaf()];
    for _ in 0..256 {
        let last = empty.last().unwrap();
        empty.push(crypto::hash_node(last, last));
    }
    empty
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

    #[test]
    fn test_empty_tree() {
        let tree = SparseMerkleTree::new();
        assert_eq!(tree.size(), 0);

        let root = tree.root();
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_update() {
        let tree = SparseMerkleTree::new();
        let key = [1u8; 32];
        let value_hash = [2u8; 32];

        let result = tree.update(&key, &value_hash);
        assert!(result.is_ok());

        let (new_root, deltas) = result.unwrap();
        assert_eq!(new_root.len(), 32);
        assert!(!deltas.is_empty());
        assert_eq!(tree.size(), 1);
    }

    #[test]
    fn test_single_key_inclusion_proof() {
        let tree = SparseMerkleTree::new();
        let key = [1u8; 32];
        let value_hash = [2u8; 32];

        tree.update(&key, &value_hash).unwrap();
        let root = tree.root();

        let proof = tree.prove_inclusion(&key, &root).unwrap();
        assert_eq!(proof.siblings.len(), 256);
        assert!(verify_inclusion(&key, &value_hash, &proof.siblings, &root));
    }

    #[test]
    fn test_two_key_inclusion_proofs() {
        let tree = SparseMerkleTree::new();

        // Two keys that differ at bit 0 (MSB)
        let key_a = [0u8; 32];
        let mut key_b = [0u8; 32];
        key_b[0] = 0x80; // bit 0 = 1

        let val_a = [0xAAu8; 32];
        let val_b = [0xBBu8; 32];

        tree.update(&key_a, &val_a).unwrap();
        tree.update(&key_b, &val_b).unwrap();
        let root = tree.root();

        // Both proofs must verify
        let proof_a = tree.prove_inclusion(&key_a, &root).unwrap();
        assert!(verify_inclusion(&key_a, &val_a, &proof_a.siblings, &root));

        let proof_b = tree.prove_inclusion(&key_b, &root).unwrap();
        assert!(verify_inclusion(&key_b, &val_b, &proof_b.siblings, &root));

        // Siblings should include actual node hashes, not all empty
        let empty_hashes = precompute_empty_hashes();
        let has_non_empty = proof_a.siblings.iter().enumerate().any(|(i, s)| *s != empty_hashes[255 - i]);
        assert!(has_non_empty, "Two-key proof must have at least one non-empty sibling");
    }

    #[test]
    fn test_three_key_inclusion_proofs() {
        let tree = SparseMerkleTree::new();

        // Three keys: A and C share bit 0 but differ at bit 1
        let key_a = [0u8; 32];        // bits: 0, 0, ...
        let mut key_b = [0u8; 32];
        key_b[0] = 0x80;               // bits: 1, 0, ...
        let mut key_c = [0u8; 32];
        key_c[0] = 0x40;               // bits: 0, 1, ...

        let val = [0xFFu8; 32];

        tree.update(&key_a, &val).unwrap();
        tree.update(&key_b, &val).unwrap();
        tree.update(&key_c, &val).unwrap();
        let root = tree.root();

        for key in [key_a, key_b, key_c] {
            let proof = tree.prove_inclusion(&key, &root).unwrap();
            assert!(
                verify_inclusion(&key, &val, &proof.siblings, &root),
                "Inclusion proof failed for key {:?}",
                &key[..4]
            );
        }
    }

    #[test]
    fn test_many_keys_inclusion_proofs() {
        let tree = SparseMerkleTree::new();
        let mut keys = Vec::new();
        let mut vals = Vec::new();

        for i in 0u8..10 {
            let mut key = [0u8; 32];
            key[0] = i;
            let mut val = [0u8; 32];
            val[0] = i + 100;
            tree.update(&key, &val).unwrap();
            keys.push(key);
            vals.push(val);
        }

        let root = tree.root();
        for (key, val) in keys.iter().zip(vals.iter()) {
            let proof = tree.prove_inclusion(key, &root).unwrap();
            assert!(
                verify_inclusion(key, val, &proof.siblings, &root),
                "Proof failed for key starting with {:02x}",
                key[0]
            );
        }
    }

    #[test]
    fn test_non_inclusion_proof() {
        let tree = SparseMerkleTree::new();
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let value_hash = [3u8; 32];

        tree.update(&key1, &value_hash).unwrap();
        let root = tree.root();

        let proof = tree.prove_non_inclusion(&key2, &root).unwrap();
        assert_eq!(proof.siblings.len(), 256);
        assert!(verify_non_inclusion(&key2, &proof.siblings, &root));
    }

    #[test]
    fn test_non_inclusion_with_multiple_keys() {
        let tree = SparseMerkleTree::new();
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let absent = [3u8; 32];
        let val = [0xAAu8; 32];

        tree.update(&key1, &val).unwrap();
        tree.update(&key2, &val).unwrap();
        let root = tree.root();

        let proof = tree.prove_non_inclusion(&absent, &root).unwrap();
        assert!(verify_non_inclusion(&absent, &proof.siblings, &root));
    }

    #[test]
    fn test_insert_order_independence() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let val_a = [0xAu8; 32];
        let val_b = [0xBu8; 32];

        let tree1 = SparseMerkleTree::new();
        tree1.update(&key_a, &val_a).unwrap();
        tree1.update(&key_b, &val_b).unwrap();

        let tree2 = SparseMerkleTree::new();
        tree2.update(&key_b, &val_b).unwrap();
        tree2.update(&key_a, &val_a).unwrap();

        assert_eq!(tree1.root(), tree2.root(), "Root must be independent of insertion order");
    }

    #[test]
    fn test_update_existing_key() {
        let tree = SparseMerkleTree::new();
        let key = [1u8; 32];
        let val1 = [2u8; 32];
        let val2 = [3u8; 32];

        tree.update(&key, &val1).unwrap();
        let root1 = tree.root();

        tree.update(&key, &val2).unwrap();
        let root2 = tree.root();

        assert_ne!(root1, root2, "Root must change when value changes");
        assert_eq!(tree.size(), 1, "Size should not increase on update");

        let proof = tree.prove_inclusion(&key, &root2).unwrap();
        assert!(verify_inclusion(&key, &val2, &proof.siblings, &root2));
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
}
