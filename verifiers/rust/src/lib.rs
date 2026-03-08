//! Olympus Verifier for Rust
//!
//! High-performance implementation for verifying Olympus commitments.

use blake3;
use hex;

/// Constants for domain separation
const LEAF_PREFIX: &[u8] = b"LEAF";
const NODE_PREFIX: &[u8] = b"NODE";
const HASH_SEPARATOR: &[u8] = b"|";

/// Compute BLAKE3 hash of data
pub fn compute_blake3(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Verify a BLAKE3 hash
pub fn verify_blake3_hash(data: &[u8], expected_hash: &str) -> bool {
    let actual_hash = compute_blake3(data);
    let actual_hex = hex::encode(actual_hash);
    actual_hex == expected_hash.to_lowercase()
}

/// Compute the domain-separated hash of a Merkle leaf
pub fn merkle_leaf_hash(leaf_data: &[u8]) -> [u8; 32] {
    let mut combined = Vec::with_capacity(
        LEAF_PREFIX.len() + HASH_SEPARATOR.len() + leaf_data.len()
    );
    combined.extend_from_slice(LEAF_PREFIX);
    combined.extend_from_slice(HASH_SEPARATOR);
    combined.extend_from_slice(leaf_data);
    compute_blake3(&combined)
}

/// Compute the hash of a Merkle parent node
pub fn merkle_parent_hash(left_hash: &[u8; 32], right_hash: &[u8; 32]) -> [u8; 32] {
    let mut combined = Vec::with_capacity(
        NODE_PREFIX.len() +
        HASH_SEPARATOR.len() +
        32 +
        HASH_SEPARATOR.len() +
        32
    );
    combined.extend_from_slice(NODE_PREFIX);
    combined.extend_from_slice(HASH_SEPARATOR);
    combined.extend_from_slice(left_hash);
    combined.extend_from_slice(HASH_SEPARATOR);
    combined.extend_from_slice(right_hash);
    compute_blake3(&combined)
}

/// Compute Merkle tree root from leaves
pub fn compute_merkle_root(leaves: &[Vec<u8>]) -> Result<String, &'static str> {
    if leaves.is_empty() {
        return Err("Cannot compute Merkle root of empty tree");
    }

    // Hash all leaves with domain separation
    let mut level: Vec<[u8; 32]> = leaves
        .iter()
        .map(|leaf| merkle_leaf_hash(leaf))
        .collect();

    // Build tree bottom-up
    while level.len() > 1 {
        let mut next_level = Vec::with_capacity((level.len() + 1) / 2);

        for i in (0..level.len()).step_by(2) {
            let left = &level[i];
            let right = if i + 1 < level.len() {
                &level[i + 1]
            } else {
                &level[i] // Duplicate last leaf if odd
            };
            next_level.push(merkle_parent_hash(left, right));
        }

        level = next_level;
    }

    Ok(hex::encode(level[0]))
}

/// Merkle sibling in a proof
#[derive(Debug, Clone)]
pub struct MerkleSibling {
    pub hash: String,
    pub position: String,
}

/// Merkle inclusion proof
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf_hash: [u8; 32],
    pub siblings: Vec<MerkleSibling>,
    pub root_hash: String,
}

/// Verify a Merkle inclusion proof
pub fn verify_merkle_proof(proof: &MerkleProof) -> Result<bool, String> {
    let mut current_hash = proof.leaf_hash;

    for sibling in &proof.siblings {
        let sibling_bytes = hex::decode(&sibling.hash)
            .map_err(|e| format!("Failed to decode sibling hash: {}", e))?;

        if sibling_bytes.len() != 32 {
            return Err("Sibling hash must be 32 bytes".to_string());
        }

        let sibling_array: [u8; 32] = sibling_bytes.try_into().unwrap();

        current_hash = match sibling.position.as_str() {
            "left" => merkle_parent_hash(&sibling_array, &current_hash),
            "right" => merkle_parent_hash(&current_hash, &sibling_array),
            _ => return Err(format!("Invalid sibling position: {}", sibling.position)),
        };
    }

    let actual_root = hex::encode(current_hash);
    Ok(actual_root == proof.root_hash.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_verification() {
        let data = b"Hello, Olympus!";
        let hash = compute_blake3(data);
        let hex_hash = hex::encode(hash);

        assert!(verify_blake3_hash(data, &hex_hash));
        assert!(!verify_blake3_hash(data, "invalid"));
    }

    #[test]
    fn test_merkle_root_computation() {
        let leaves = vec![
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
        ];

        let root = compute_merkle_root(&leaves).unwrap();
        assert_eq!(root.len(), 64); // 32 bytes = 64 hex chars

        // Computing same root twice should give same result
        let root2 = compute_merkle_root(&leaves).unwrap();
        assert_eq!(root, root2);
    }

    #[test]
    fn test_merkle_proof_verification() {
        let leaves = vec![
            b"alpha".to_vec(),
            b"beta".to_vec(),
        ];

        let root = compute_merkle_root(&leaves).unwrap();

        // Create a simple proof for the first leaf
        let leaf_hash = merkle_leaf_hash(&leaves[0]);
        let leaf1_hash = merkle_leaf_hash(&leaves[1]);

        let proof = MerkleProof {
            leaf_hash,
            siblings: vec![
                MerkleSibling {
                    hash: hex::encode(leaf1_hash),
                    position: "right".to_string(),
                },
            ],
            root_hash: root,
        };

        let valid = verify_merkle_proof(&proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_empty_tree() {
        let leaves: Vec<Vec<u8>> = vec![];
        let result = compute_merkle_root(&leaves);
        assert!(result.is_err());
    }
}
