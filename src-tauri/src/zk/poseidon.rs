//! Domain-separated Poseidon hashing over BN254, matching circomlib semantics.
//!
//! Circomlib DomainPoseidonNode(domain, left, right):
//!   inner = Poseidon([domain, left])      -- 2-input
//!   outer = Poseidon([inner, right])      -- 2-input
//!
//! Domain tags used in Olympus circuits (audit F-1 — canonical table lives in
//! `olympus_crypto::poseidon`; keep this in sync):
//!   1 = Merkle internal node (document_existence, non_existence, unified)
//!   1 = leaf-wrap  — shares tag 1 with NODE today; see the note in
//!       `olympus_crypto::poseidon` for why this is currently safe and why the
//!       NODE=2 split is deferred to the pre-v1.0 ceremony
//!   3 = redaction / disclosure commitment chain
//!   4 = reveal-mask commitment chain
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

/// Canonical internal-node domain tag (audit L-4 NODE=2 split). Re-exported
/// from `olympus_crypto::poseidon` — the single source of truth — so every
/// prover/witness/fold caller threads the SAME value the circuit hardcodes in
/// `merkleProof.circom`'s `DomainPoseidonNode`. Distinct from the leaf-wrap tag
/// (LEAF=1) so a leaf hash can never be reinterpreted as an internal node.
pub const NODE_DOMAIN: u64 = olympus_crypto::poseidon::DOMAIN_NODE;

/// 2-input Poseidon: H(a, b) — matches `Poseidon(2)` in circomlib.
pub fn hash2(a: Fr, b: Fr) -> Result<Fr, PoseidonError> {
    let mut h =
        Poseidon::<Fr>::new_circom(2).map_err(|e| PoseidonError::Internal(e.to_string()))?;
    let result = h
        .hash(&[a, b])
        .map_err(|e| PoseidonError::Internal(e.to_string()))?;
    Ok(result)
}

/// N-input Poseidon: H(inputs[0], ..., inputs[n-1]).
pub fn hash_n(inputs: &[Fr]) -> Result<Fr, PoseidonError> {
    let n = inputs.len();
    let mut h = Poseidon::<Fr>::new_circom(n)
        .map_err(|e| PoseidonError::Internal(format!("new_circom({n}): {e}")))?;
    let result = h
        .hash(inputs)
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

/// Compute the empty-tree root for a fully-empty Poseidon Merkle tree of
/// the given depth, using `node_domain` for internal nodes and `leaf` as
/// the empty-leaf sentinel.
///
/// Audit H-2: the document_existence and unified circuits' `leafIndex <
/// treeSize` bounds check is gated on `treeSize > 0`. The circuit docstring
/// requires off-chain verifiers to reject `treeSize == 0` unless `root`
/// equals this value; the resolver lives in [`empty_doc_existence_root`]
/// and is wired into `/zk/verify`.
pub fn empty_tree_root(depth: usize, leaf: Fr, node_domain: u64) -> Result<Fr, PoseidonError> {
    let mut acc = leaf;
    for _ in 0..depth {
        acc = domain_node(node_domain, acc, acc)?;
    }
    Ok(acc)
}

/// Cached empty-tree root for the document_existence circuit (depth=20,
/// empty-leaf sentinel = 0, node domain = 1). Matches the circuit's
/// `MerkleTreeInclusionProof(20)` invariant when no leaves have ever been
/// inserted.
pub fn empty_doc_existence_root() -> Result<Fr, PoseidonError> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Fr> = OnceLock::new();
    if let Some(v) = CACHE.get() {
        return Ok(*v);
    }
    let v = empty_tree_root(20, Fr::from(0u64), NODE_DOMAIN)?;
    let _ = CACHE.set(v);
    Ok(v)
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
    // Audit follow-up: was `assert_eq!` — downgrade to a typed error so a
    // malformed bundle on the verifier path returns a clean rejection
    // instead of crashing the process. `debug_assert_eq!` keeps the
    // invariant pinned in dev/CI for internal callers.
    debug_assert_eq!(path_elements.len(), path_indices.len());
    if path_elements.len() != path_indices.len() {
        return Err(PoseidonError::Internal(format!(
            "path_elements ({}) and path_indices ({}) must have the same length",
            path_elements.len(),
            path_indices.len(),
        )));
    }
    let mut current = leaf;
    for (&sibling, &idx) in path_elements.iter().zip(path_indices.iter()) {
        current = merkle_node(current, sibling, idx, node_domain)?;
    }
    Ok(current)
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
        assert_ne!(
            h3, h2_chain,
            "3-input Poseidon must not equal chained 2-input"
        );
    }

    // ── L-16: snarkjs / circomlibjs known-vector anchors ──────────────────
    //
    // The structural invariants above catch most parameter drift, but the
    // light-poseidon → circomlibjs equality is locked in olympus-crypto's
    // dev-tests only. Duplicate the canonical vectors here so the src-tauri
    // ZK layer fails CI directly on any constants drift, without having to
    // run the olympus-crypto suite.
    //
    // Vectors reproduced from circomlibjs @ 0.1.7:
    //   poseidon([1,2])         = 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
    //   poseidon([1,2,3])       = 6542985608222806190361240322586112750744169038454362455181422643027100751666
    //   poseidon([1,2,3,4])     = 18821383157269793795438455681495246036402687001665670618754263018637548127333

    fn fr_from_dec(s: &str) -> Fr {
        let bu: num_bigint::BigUint = s.parse().expect("decimal");
        Fr::from_le_bytes_mod_order(&bu.to_bytes_le())
    }

    #[test]
    fn hash2_matches_circomlibjs_reference_vector() {
        let bytes = hex::decode("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a")
            .expect("hex");
        let expected = Fr::from_be_bytes_mod_order(&bytes);
        assert_eq!(
            hash2(Fr::from(1u64), Fr::from(2u64)).unwrap(),
            expected,
            "hash2(1,2) != circomlibjs poseidon([1,2])"
        );
    }

    #[test]
    fn hash_n_arity3_matches_circomlibjs_reference_vector() {
        let expected = fr_from_dec(
            "6542985608222806190361240322586112750744169038454362455181422643027100751666",
        );
        assert_eq!(
            hash_n(&[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]).unwrap(),
            expected,
        );
    }

    #[test]
    fn hash_n_arity4_matches_circomlibjs_reference_vector() {
        let expected = fr_from_dec(
            "18821383157269793795438455681495246036402687001665670618754263018637548127333",
        );
        assert_eq!(
            hash_n(&[
                Fr::from(1u64),
                Fr::from(2u64),
                Fr::from(3u64),
                Fr::from(4u64)
            ])
            .unwrap(),
            expected,
        );
    }

    #[test]
    fn empty_doc_existence_root_is_deterministic() {
        // Audit H-2 helper: the depth-20 empty-tree root must be stable
        // across builds. Any drift in the empty-tree derivation would mean
        // pre-existing snapshots stored under the old root suddenly fail
        // verification.
        let a = empty_doc_existence_root().unwrap();
        let b = empty_doc_existence_root().unwrap();
        assert_eq!(a, b);
        // Sanity: depth-0 reduces to the empty-leaf sentinel (0).
        assert_eq!(
            empty_tree_root(0, Fr::from(0u64), NODE_DOMAIN).unwrap(),
            Fr::from(0u64)
        );
        // Depth-1 must equal domain_node(NODE_DOMAIN, 0, 0).
        assert_eq!(
            empty_tree_root(1, Fr::from(0u64), NODE_DOMAIN).unwrap(),
            domain_node(NODE_DOMAIN, Fr::from(0u64), Fr::from(0u64)).unwrap(),
        );
    }
}
