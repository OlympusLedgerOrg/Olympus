//! Binary Merkle tree using domain-prefixed BLAKE3 + Poseidon over BN254.
//!
//! Tree shape follows RFC 6962 (Certificate Transparency) style: pairs are
//! hashed `(left, right)`, and a lone trailing node at an odd level is
//! **promoted** to the next level unchanged — never duplicated. This matches
//! the reference verifier in `verifiers/rust` (`compute_merkle_root`) so the
//! host and the offline verifier agree for any leaf count, and it removes the
//! "phantom index" class of forgeries that duplicate-padding allowed (a leaf
//! could otherwise prove membership at the duplicated positions).
//!
//! `verify_proof` derives the walk direction and the promotion points from
//! `leaf_index` + `tree_size` rather than trusting prover-supplied position
//! strings, so the claimed leaf index is bound to the proof.

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
    /// Total number of (real) leaves in the tree. Required to reconstruct the
    /// CT-style walk — where promotions happen depends on the per-level sizes,
    /// which depend on the leaf count. `serde(default)` keeps deserialization of
    /// any legacy proof rows safe (a missing/zero value simply fails to verify).
    #[serde(default)]
    pub tree_size: usize,
    pub siblings: Vec<MerkleProofStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub hash: String,
    pub position: String, // "left" or "right" — side the SIBLING sits on
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

    let leaves: Vec<String> = content_hashes.iter().map(|h| leaf_hash(h)).collect();
    let target_leaf = leaf_hash(target_hash);
    let target_idx = leaves.iter().position(|l| *l == target_leaf)?;
    let tree_size = leaves.len();

    let mut siblings = Vec::new();
    let mut idx = target_idx;
    let mut level = leaves;

    while level.len() > 1 {
        // CT-style: a lone trailing node at an odd-length level has no sibling
        // and is promoted unchanged — emit no proof step for it.
        let is_lone = idx == level.len() - 1 && level.len() % 2 == 1;
        if !is_lone {
            let sibling_idx = idx ^ 1; // even↔+1, odd↔-1; always valid when not lone
            let position = if idx % 2 == 0 { "right" } else { "left" };
            siblings.push(MerkleProofStep {
                hash: level[sibling_idx].clone(),
                position: position.to_string(),
            });
        }

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for i in (0..level.len()).step_by(2) {
            if i + 1 < level.len() {
                next.push(node_hash(&level[i], &level[i + 1]));
            } else {
                next.push(level[i].clone()); // promote lone node
            }
        }
        idx /= 2;
        level = next;
    }

    Some(MerkleResult {
        root: level[0].clone(),
        proof: MerkleProof {
            leaf_hash: target_leaf,
            leaf_index: target_idx,
            tree_size,
            siblings,
        },
    })
}

/// Verify a Merkle proof against a root.
///
/// The walk is driven by `leaf_index` + `tree_size` (not by the prover-supplied
/// `position` fields), which binds the claimed index: a proof whose `leaf_index`
/// doesn't match its sibling path produces a different root and fails. The
/// supplied positions are additionally cross-checked against the index-derived
/// direction, and every sibling step must be consumed exactly.
pub fn verify_proof(content_hash: &str, root: &str, proof: &MerkleProof) -> bool {
    let expected_leaf = leaf_hash(content_hash);
    if proof.leaf_hash != expected_leaf {
        return false;
    }
    // A single-leaf tree has size 1 and no siblings; reject an out-of-range index.
    if proof.tree_size == 0 || proof.leaf_index >= proof.tree_size {
        return false;
    }

    let mut idx = proof.leaf_index;
    let mut level_size = proof.tree_size;
    let mut current = proof.leaf_hash.clone();
    let mut steps = proof.siblings.iter();

    while level_size > 1 {
        let is_lone = idx == level_size - 1 && level_size % 2 == 1;
        if !is_lone {
            let step = match steps.next() {
                Some(s) => s,
                None => return false, // fewer steps than the structure requires
            };
            let sibling_is_left = idx % 2 == 1;
            let position_ok = if sibling_is_left {
                step.position == "left"
            } else {
                step.position == "right"
            };
            if !position_ok {
                return false;
            }
            current = if sibling_is_left {
                node_hash(&step.hash, &current)
            } else {
                node_hash(&current, &step.hash)
            };
        }
        idx /= 2;
        level_size = level_size.div_ceil(2);
    }

    // All supplied steps must have been consumed by the structural walk.
    if steps.next().is_some() {
        return false;
    }

    current == root
}

// ── Poseidon Merkle tree (BN254, circomlib-compatible) ────────────────────────

/// Decode a hex string into a BN254 field element.
///
/// Returns an error on invalid hex or input longer than 32 bytes, rather than
/// silently mapping bad input to `Fr::from(0)` (which corrupts tree leaves) or
/// panicking on an out-of-bounds slice (a DoS surface for over-long input).
fn hex_to_fr(hex: &str) -> Result<Fr, poseidon::PoseidonError> {
    let decoded = hex::decode(hex)
        .map_err(|e| poseidon::PoseidonError::Internal(format!("invalid hex: {e}")))?;
    if decoded.len() > 32 {
        return Err(poseidon::PoseidonError::Internal(format!(
            "hex input too long: {} bytes (max 32)",
            decoded.len()
        )));
    }
    let mut bytes = [0u8; 32];
    let start = 32 - decoded.len(); // right-align big-endian
    bytes[start..].copy_from_slice(&decoded);
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

fn fr_to_hex(f: Fr) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    hex::encode(bytes)
}

/// Domain 2 leaf: DomainPoseidon(2, 0, content_hash_as_Fr)
fn poseidon_leaf(content_hash: &str) -> Result<Fr, poseidon::PoseidonError> {
    let val = hex_to_fr(content_hash)?;
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
///
/// Returns `None` if the input is empty, the target isn't present, or any leaf
/// or node hash fails — never a tree built on silently-dropped leaves or
/// zero-filled nodes.
pub fn build_poseidon_tree(content_hashes: &[String], target_hash: &str) -> Option<PoseidonResult> {
    if content_hashes.is_empty() {
        return None;
    }

    // Propagate hash errors as `None` (no tree) rather than silently dropping
    // un-parseable leaves, which would shift every subsequent index.
    let mut leaves: Vec<Fr> = Vec::with_capacity(content_hashes.len());
    for h in content_hashes {
        leaves.push(poseidon_leaf(h).ok()?);
    }
    let target_leaf = poseidon_leaf(target_hash).ok()?;
    let target_idx = leaves.iter().position(|l| *l == target_leaf)?;

    let mut path_elements = Vec::new();
    let mut path_indices = Vec::new();
    let mut idx = target_idx;
    let mut level = leaves;

    while level.len() > 1 {
        let is_lone = idx == level.len() - 1 && level.len() % 2 == 1;
        if !is_lone {
            let sib = idx ^ 1;
            path_elements.push(fr_to_hex(level[sib]));
            path_indices.push(if idx % 2 == 0 { 0 } else { 1 });
        }

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for i in (0..level.len()).step_by(2) {
            if i + 1 < level.len() {
                next.push(poseidon_node(level[i], level[i + 1]).ok()?);
            } else {
                next.push(level[i]); // promote lone node
            }
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
        // Exercise several non-power-of-2 sizes through the CT-style walk.
        for n in 1..=9usize {
            let hashes: Vec<String> = (0..n).map(|i| format!("{:064x}", i)).collect();
            for h in &hashes {
                let r = build_tree(&hashes, h).unwrap();
                assert!(
                    verify_proof(h, &r.root, &r.proof),
                    "verify failed for leaf {h} in tree of size {n}"
                );
            }
        }
    }

    #[test]
    fn wrong_hash_fails() {
        let hashes = vec![format!("{:064x}", 1), format!("{:064x}", 2)];
        let r = build_tree(&hashes, &hashes[0]).unwrap();
        assert!(!verify_proof(&format!("{:064x}", 99), &r.root, &r.proof));
    }

    #[test]
    fn phantom_index_rejected() {
        // 5-leaf tree: old duplicate-padding allowed proving the last leaf at
        // phantom indices 5,6,7. CT-style + index binding rejects any index
        // outside [0, tree_size).
        let hashes: Vec<String> = (0..5).map(|i| format!("{:064x}", i)).collect();
        let r = build_tree(&hashes, &hashes[4]).unwrap();
        assert!(verify_proof(&hashes[4], &r.root, &r.proof));
        for phantom in [5usize, 6, 7, 8, usize::MAX] {
            let mut p = r.proof.clone();
            p.leaf_index = phantom;
            assert!(
                !verify_proof(&hashes[4], &r.root, &p),
                "phantom index {phantom} must not verify"
            );
        }
    }

    #[test]
    fn index_mismatch_rejected() {
        // A valid proof with a tampered (in-range) leaf_index must fail: the
        // walk is driven by the index, so a wrong index yields a wrong root.
        let hashes: Vec<String> = (0..5).map(|i| format!("{:064x}", i)).collect();
        let r = build_tree(&hashes, &hashes[2]).unwrap();
        for wrong in [0usize, 1, 3, 4] {
            let mut p = r.proof.clone();
            p.leaf_index = wrong;
            assert!(
                !verify_proof(&hashes[2], &r.root, &p),
                "index {wrong} (real is 2) must not verify"
            );
        }
    }

    #[test]
    fn ct_style_matches_reference_promotion() {
        // For a 3-leaf tree [a,b,c]: root = node(node(a,b), c) — c is promoted
        // at the first level, then paired at the second. Verify by reconstruction.
        let hashes: Vec<String> = (0..3).map(|i| format!("{:064x}", i)).collect();
        let r = build_tree(&hashes, &hashes[0]).unwrap();
        let la = leaf_hash(&hashes[0]);
        let lb = leaf_hash(&hashes[1]);
        let lc = leaf_hash(&hashes[2]);
        let expected = node_hash(&node_hash(&la, &lb), &lc);
        assert_eq!(r.root, expected);
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
        let roots: Vec<String> = hashes
            .iter()
            .map(|h| build_poseidon_tree(&hashes, h).unwrap().root)
            .collect();
        assert!(roots.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn poseidon_rejects_bad_hex() {
        // Non-hex and over-length (33-byte) inputs must yield None, not a
        // zero-leaf tree (old hex_to_fr mapped these to Fr(0)) or a panic.
        let non_hex = "zz".repeat(32); // 64 chars, not hex
        assert!(build_poseidon_tree(std::slice::from_ref(&non_hex), &non_hex).is_none());
        let overlong = "a".repeat(66); // 33 bytes
        assert!(build_poseidon_tree(std::slice::from_ref(&overlong), &overlong).is_none());
    }
}
