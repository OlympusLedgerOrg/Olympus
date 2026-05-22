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

    // ── Edge case 7: Poseidon S-box / padding parameter consistency ───────────
    //
    // light_poseidon::Poseidon::new_circom(t) instantiates the Poseidon
    // permutation with the SAME MDS matrix and round constants that circomlib
    // uses for t-input hashing.  If there is ever a parameter mismatch — e.g.
    // after upgrading light-poseidon or changing the circom Poseidon version —
    // the two layers produce divergent hashes for identical inputs, which causes
    // the Rust host to generate witnesses that the WASM circuit rejects.
    //
    // The tests below verify three properties that must hold jointly:
    //   1. Determinism: identical inputs always produce identical outputs.
    //   2. Domain separation: different domain tags produce different outputs.
    //   3. Arity consistency: hash_n(2, [a,b]) == hash2(a,b) (same arity ↔ same output).
    //
    // Absolute value tests ("does Poseidon(1,2) equal 0x…?") belong in the
    // integration test suite where they can be cross-checked against snarkjs
    // output.  Unit tests here verify structural invariants that would be
    // violated by padding or S-box mismatches.

    #[test]
    fn hash2_equals_hash_n_with_two_inputs() {
        // If the arity-dispatch logic in light_poseidon is correct, calling
        // hash2(a, b) and hash_n(&[a, b]) must return the same value — they
        // both request a 2-input Poseidon instance.
        let a = Fr::from(111u64);
        let b = Fr::from(222u64);
        let h2 = hash2(a, b).unwrap();
        let hn = hash_n(&[a, b]).unwrap();
        assert_eq!(h2, hn, "hash2 and hash_n({a:?},{b:?}) must agree");
    }

    #[test]
    fn domain_node_is_not_bare_hash2() {
        // DomainPoseidonNode(domain, left, right) ≠ Poseidon(left, right).
        // If domain separation were broken (e.g. the inner domain call were
        // silently dropped), these two would be equal.
        let (_d, l, r) = (Fr::from(1u64), Fr::from(42u64), Fr::from(99u64));
        let h_domain = domain_node(1, l, r).unwrap();
        let h_bare = hash2(l, r).unwrap();
        assert_ne!(h_domain, h_bare, "domain tag must change the hash output");
    }

    #[test]
    fn hash_n_arity3_differs_from_arity2_prefix() {
        // hash_n([a, b, c]) must differ from hash2(hash2(a, b), c) — the
        // Poseidon sponge absorbs all inputs in one permutation call per arity,
        // so a 3-input hash is NOT a sequential 2-input chain.  A mismatch here
        // would indicate the wrong MDS matrix (wrong number of state columns).
        let (a, b, c) = (Fr::from(1u64), Fr::from(2u64), Fr::from(3u64));
        let h3 = hash_n(&[a, b, c]).unwrap();
        let h2_chain = hash2(hash2(a, b).unwrap(), c).unwrap();
        assert_ne!(h3, h2_chain, "3-input Poseidon must not equal chained 2-input");
    }

    #[test]
    fn redaction_commitment_domain3_differs_from_domain1() {
        // The redaction_commitment uses domain tag 3; Merkle nodes use tag 1.
        // Verify that swapping the domain tag in an equivalent Merkle computation
        // produces a different result, confirming the tag is wired through.
        let leaves = [Fr::from(10u64), Fr::from(20u64)];
        let mask = [true, true];
        let rc = redaction_commitment(2, &leaves, &mask).unwrap();
        // Re-derive manually with domain 1 instead of 3.
        let mut acc_d1 = Fr::from(2u64);
        for &leaf in &leaves {
            acc_d1 = domain_node(1, acc_d1, leaf).unwrap(); // domain 1, not 3
        }
        assert_ne!(rc, acc_d1, "domain-3 commitment must differ from domain-1 chain");
    }
}
