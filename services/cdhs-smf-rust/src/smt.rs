//! Sparse Merkle Tree implementation for CD-HS-SMF
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
    /// Mapping from (level, path_bits[0..level]) to hash
    nodes: HashMap<(u8, Vec<u8>), [u8; 32]>,
    /// Mapping from key to value_hash
    leaves: HashMap<[u8; 32], [u8; 32]>,
    /// Current root
    root: [u8; 32],
    /// Number of non-empty leaves
    size: u64,
}

/// Node delta for persistence
pub struct NodeDelta {
    pub path: [u8; 32],
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

        // Update from bottom to top
        let mut current_hash = leaf_hash;
        let empty_hashes = precompute_empty_hashes();

        for level in 0..256 {
            let bit = path_bits[level];
            let sibling_path = sibling_path_bits(&path_bits, level);

            // Get sibling hash (from nodes or use empty hash)
            let sibling_hash = state.nodes
                .get(&(level as u8, sibling_path.clone()))
                .copied()
                .unwrap_or(empty_hashes[level]);

            // Compute parent hash
            let (left, right) = if bit == 0 {
                (current_hash, sibling_hash)
            } else {
                (sibling_hash, current_hash)
            };

            let parent_hash = crypto::hash_node(&left, &right);

            // Store node
            let node_path = path_bits[0..=level].to_vec();
            state.nodes.insert((level as u8, node_path.clone()), current_hash);

            // Record delta
            deltas.push(NodeDelta {
                path: *key, // Simplified - in production, encode path properly
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
        let mut siblings = Vec::with_capacity(256);

        for level in 0..256 {
            let sibling_path = sibling_path_bits(&path_bits, level);

            let sibling_hash = state.nodes
                .get(&(level as u8, sibling_path))
                .copied()
                .unwrap_or(empty_hashes[level]);

            siblings.push(sibling_hash);
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
        let mut siblings = Vec::with_capacity(256);

        for level in 0..256 {
            let sibling_path = sibling_path_bits(&path_bits, level);

            let sibling_hash = state.nodes
                .get(&(level as u8, sibling_path))
                .copied()
                .unwrap_or(empty_hashes[level]);

            siblings.push(sibling_hash);
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

    for level in 0..256 {
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

    for level in 0..256 {
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

/// Get sibling path bits at a given level
fn sibling_path_bits(path_bits: &[u8], level: usize) -> Vec<u8> {
    let mut sibling = path_bits[0..level].to_vec();
    // Flip the bit at this level
    if level > 0 {
        let last_bit = path_bits[level - 1];
        sibling[level - 1] = 1 - last_bit;
    }
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
    fn test_proof_generation() {
        let tree = SparseMerkleTree::new();
        let key = [1u8; 32];
        let value_hash = [2u8; 32];

        tree.update(&key, &value_hash).unwrap();
        let root = tree.root();

        // Inclusion proof for existing key
        let proof = tree.prove_inclusion(&key, &root);
        assert!(proof.is_ok());

        let inc_proof = proof.unwrap();
        assert_eq!(inc_proof.siblings.len(), 256);

        // Verify the proof
        let valid = verify_inclusion(&key, &value_hash, &inc_proof.siblings, &root);
        assert!(valid);
    }

    #[test]
    fn test_non_inclusion_proof() {
        let tree = SparseMerkleTree::new();
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let value_hash = [3u8; 32];

        tree.update(&key1, &value_hash).unwrap();
        let root = tree.root();

        // Non-inclusion proof for non-existing key
        let proof = tree.prove_non_inclusion(&key2, &root);
        assert!(proof.is_ok());

        let non_inc_proof = proof.unwrap();
        assert_eq!(non_inc_proof.siblings.len(), 256);

        // Verify the proof
        let valid = verify_non_inclusion(&key2, &non_inc_proof.siblings, &root);
        assert!(valid);
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
}
