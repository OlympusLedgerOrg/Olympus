//! Binary Merkle tree using domain-prefixed BLAKE3 + Poseidon over BN254.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};

use crate::zk::poseidon;

fn leaf_hash(content_hash: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"OLY:LEAF:V1|");
    h.update(content_hash.as_bytes());
    h.finalize().to_hex().to_string()
}

fn node_hash(left: &str, right: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"OLY:NODE:V1|");
    h.update(left.as_bytes());
    h.update(b"|");
    h.update(right.as_bytes());
    h.finalize().to_hex().to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_hash: String,
    pub leaf_index: usize,
    pub siblings: Vec<MerkleProofStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub hash: String,
    pub position: String, // "left" or "right"
}

pub struct MerkleResult {
    pub root: String,
    pub proof: MerkleProof,
}

/// Build a binary Merkle tree over sorted content hashes and return root + proof for `target_hash`.
pub fn build_tree(content_hashes: &[String], target_hash: &str) -> Option<MerkleResult> {
    if content_hashes.is_empty() {
        return None;
    }

    let mut leaves: Vec<String> = content_hashes.iter().map(|h| leaf_hash(h)).collect();
    let target_leaf = leaf_hash(target_hash);
    let target_idx = leaves.iter().position(|l| *l == target_leaf)?;

    // Pad to next power of 2 by duplicating last leaf
    let n = leaves.len().next_power_of_two();
    while leaves.len() < n {
        leaves.push(leaves.last().unwrap().clone());
    }

    let mut siblings = Vec::new();
    let mut idx = target_idx;
    let mut level = leaves;

    while level.len() > 1 {
        let sibling_idx = idx ^ 1;
        let position = if sibling_idx < idx { "left" } else { "right" };
        siblings.push(MerkleProofStep {
            hash: level[sibling_idx].clone(),
            position: position.to_string(),
        });

        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        idx /= 2;
        level = next;
    }

    Some(MerkleResult {
        root: level[0].clone(),
        proof: MerkleProof {
            leaf_hash: target_leaf,
            leaf_index: target_idx,
            siblings,
        },
    })
}

/// Verify a Merkle proof against a root.
pub fn verify_proof(content_hash: &str, root: &str, proof: &MerkleProof) -> bool {
    let expected_leaf = leaf_hash(content_hash);
    if proof.leaf_hash != expected_leaf {
        return false;
    }

    let mut current = proof.leaf_hash.clone();
    for step in &proof.siblings {
        current = if step.position == "left" {
            node_hash(&step.hash, &current)
        } else {
            node_hash(&current, &step.hash)
        };
    }

    current == root
}

// ── Poseidon Merkle tree (BN254, circomlib-compatible) ────────────────────────

fn hex_to_fr(hex: &str) -> Fr {
    let mut bytes = [0u8; 32];
    let decoded = hex::decode(hex).unwrap_or_default();
    // Right-align into 32 bytes (big-endian)
    let start = 32usize.saturating_sub(decoded.len());
    bytes[start..start + decoded.len()].copy_from_slice(&decoded);
    Fr::from_be_bytes_mod_order(&bytes)
}

fn fr_to_hex(f: Fr) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    hex::encode(bytes)
}

/// Domain 2 leaf: DomainPoseidon(2, 0, content_hash_as_Fr)
fn poseidon_leaf(content_hash: &str) -> Result<Fr, poseidon::PoseidonError> {
    let val = hex_to_fr(content_hash);
    poseidon::domain_node(2, Fr::from(0u64), val)
}

/// Domain 1 node: DomainPoseidon(1, left, right)
fn poseidon_node(left: Fr, right: Fr) -> Result<Fr, poseidon::PoseidonError> {
    poseidon::domain_node(1, left, right)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoseidonProof {
    pub leaf_hash: String,
    pub leaf_index: usize,
    pub path_elements: Vec<String>,
    pub path_indices: Vec<u8>,
}

pub struct PoseidonResult {
    pub root: String,
    pub proof: PoseidonProof,
}

/// Build a Poseidon Merkle tree and return root + proof for `target_hash`.
pub fn build_poseidon_tree(content_hashes: &[String], target_hash: &str) -> Option<PoseidonResult> {
    if content_hashes.is_empty() {
        return None;
    }

    let mut leaves: Vec<Fr> = content_hashes
        .iter()
        .filter_map(|h| poseidon_leaf(h).ok())
        .collect();
    let target_leaf = poseidon_leaf(target_hash).ok()?;
    let target_idx = leaves.iter().position(|l| *l == target_leaf)?;

    let n = leaves.len().next_power_of_two();
    while leaves.len() < n {
        leaves.push(*leaves.last().unwrap());
    }

    let mut path_elements = Vec::new();
    let mut path_indices = Vec::new();
    let mut idx = target_idx;
    let mut level = leaves;

    while level.len() > 1 {
        let sib = idx ^ 1;
        path_elements.push(fr_to_hex(level[sib]));
        path_indices.push(if idx % 2 == 0 { 0 } else { 1 });

        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(poseidon_node(pair[0], pair[1]).unwrap_or(Fr::from(0u64)));
        }
        idx /= 2;
        level = next;
    }

    Some(PoseidonResult {
        root: fr_to_hex(level[0]),
        proof: PoseidonProof {
            leaf_hash: fr_to_hex(target_leaf),
            leaf_index: target_idx,
            path_elements,
            path_indices,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_tree() {
        let hashes = vec!["abc123".repeat(10) + &"0".repeat(4)];
        let r = build_tree(&hashes, &hashes[0]).unwrap();
        assert!(verify_proof(&hashes[0], &r.root, &r.proof));
    }

    #[test]
    fn multi_leaf_tree() {
        let hashes: Vec<String> = (0..5)
            .map(|i| format!("{:064x}", i))
            .collect();
        for h in &hashes {
            let r = build_tree(&hashes, h).unwrap();
            assert!(verify_proof(h, &r.root, &r.proof));
        }
    }

    #[test]
    fn wrong_hash_fails() {
        let hashes = vec![format!("{:064x}", 1), format!("{:064x}", 2)];
        let r = build_tree(&hashes, &hashes[0]).unwrap();
        assert!(!verify_proof(&format!("{:064x}", 99), &r.root, &r.proof));
    }

    #[test]
    fn poseidon_single_leaf() {
        let hashes = vec![format!("{:064x}", 42)];
        let r = build_poseidon_tree(&hashes, &hashes[0]).unwrap();
        assert_eq!(r.proof.leaf_index, 0);
        assert!(!r.root.is_empty());
        assert_ne!(r.root, "0".repeat(64));
    }

    #[test]
    fn poseidon_multi_leaf() {
        let hashes: Vec<String> = (1..=4).map(|i| format!("{:064x}", i)).collect();
        for h in &hashes {
            let r = build_poseidon_tree(&hashes, h);
            assert!(r.is_some());
        }
        // All should have the same root
        let roots: Vec<String> = hashes.iter()
            .map(|h| build_poseidon_tree(&hashes, h).unwrap().root)
            .collect();
        assert!(roots.windows(2).all(|w| w[0] == w[1]));
    }
}
