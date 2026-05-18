//! Domain-separated Poseidon hashing over BN254, matching circomlib semantics.
//!
//! Circomlib DomainPoseidonNode(domain, left, right):
//!   inner = Poseidon([domain, left])      -- 2-input
//!   outer = Poseidon([inner, right])      -- 2-input
//!
//! Domain tags used in Olympus circuits:
//!   1 = Merkle node (document_existence, non_existence, unified)
//!   2 = Merkle leaf
//!   3 = redaction commitment chain
//!
//! `light_poseidon` implements the BN254 Poseidon with the same MDS matrix and
//! round constants as circomlib, so hashes produced here are byte-for-byte
//! identical to snarkjs witness values.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PoseidonError {
    #[error("Poseidon error: {0}")]
    Internal(String),
}

// light_poseidon works on [u8; 32] big-endian field elements.

fn fr_to_bytes(f: Fr) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let b = f.into_bigint().to_bytes_be();
    buf.copy_from_slice(&b);
    buf
}

fn bytes_to_fr(b: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(b)
}

/// 2-input Poseidon: H(a, b) — matches `Poseidon(2)` in circomlib.
pub fn hash2(a: Fr, b: Fr) -> Result<Fr, PoseidonError> {
    let mut h = Poseidon::<Fr>::new_circom(2)
        .map_err(|e| PoseidonError::Internal(e.to_string()))?;
    let result = h.hash(&[a, b])
        .map_err(|e| PoseidonError::Internal(e.to_string()))?;
    Ok(result)
}

/// N-input Poseidon: H(inputs[0], ..., inputs[n-1]).
pub fn hash_n(inputs: &[Fr]) -> Result<Fr, PoseidonError> {
    let n = inputs.len();
    let mut h = Poseidon::<Fr>::new_circom(n)
        .map_err(|e| PoseidonError::Internal(format!("new_circom({n}): {e}")))?;
    let result = h.hash(inputs)
        .map_err(|e| PoseidonError::Internal(e.to_string()))?;
    Ok(result)
}

/// `DomainPoseidonNode(domain, left, right)` as used in merkleProof.circom.
///
/// = Poseidon([Poseidon([domain, left]), right])
pub fn domain_node(domain: u64, left: Fr, right: Fr) -> Result<Fr, PoseidonError> {
    let d = Fr::from(domain);
    let inner = hash2(d, left)?;
    hash2(inner, right)
}

/// Compute a Merkle node hash given two children, routing left/right by
/// `path_index` (0 = current is left child, 1 = current is right child).
pub fn merkle_node(
    current: Fr,
    sibling: Fr,
    path_index: u8,
    domain: u64,
) -> Result<Fr, PoseidonError> {
    let (left, right) = if path_index == 0 {
        (current, sibling)
    } else {
        (sibling, current)
    };
    domain_node(domain, left, right)
}

/// Walk a Merkle path and return the computed root.
///
/// `leaf`          — starting leaf value
/// `path_elements` — sibling hashes, leaf→root order
/// `path_indices`  — 0 = leaf is left child at this level, 1 = right
/// `node_domain`   — domain tag for internal nodes (typically 1)
pub fn compute_merkle_root(
    leaf: Fr,
    path_elements: &[Fr],
    path_indices: &[u8],
    node_domain: u64,
) -> Result<Fr, PoseidonError> {
    assert_eq!(
        path_elements.len(),
        path_indices.len(),
        "path_elements and path_indices must have the same length"
    );
    let mut current = leaf;
    for (&sibling, &idx) in path_elements.iter().zip(path_indices.iter()) {
        current = merkle_node(current, sibling, idx, node_domain)?;
    }
    Ok(current)
}

/// Redaction commitment chain (domain 3):
///   acc = revealedCount
///   for each revealed leaf: acc = DomainPoseidon(3, acc, leaf_value)
///   redacted leaves contribute 0.
pub fn redaction_commitment(
    revealed_count: u64,
    leaves: &[Fr],
    reveal_mask: &[bool],
) -> Result<Fr, PoseidonError> {
    assert_eq!(leaves.len(), reveal_mask.len());
    let mut acc = Fr::from(revealed_count);
    for (&leaf, &revealed) in leaves.iter().zip(reveal_mask.iter()) {
        let val = if revealed { leaf } else { Fr::from(0u64) };
        acc = domain_node(3, acc, val)?;
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn hash2_is_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let h1 = hash2(a, b).unwrap();
        let h2 = hash2(a, b).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn domain_node_differs_by_domain() {
        let l = Fr::from(42u64);
        let r = Fr::from(99u64);
        let h1 = domain_node(1, l, r).unwrap();
        let h2 = domain_node(2, l, r).unwrap();
        assert_ne!(h1, h2, "different domains must produce different hashes");
    }

    #[test]
    fn empty_redaction_commitment() {
        // empty tree: just revealed_count = 0, no leaves
        let result = redaction_commitment(0, &[], &[]).unwrap();
        assert_eq!(result, Fr::from(0u64));
    }
}
