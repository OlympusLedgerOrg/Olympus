//! Witness for the `document_existence` circuit.
//!
//! Public inputs  (3): root, leafIndex, treeSize
//! Private inputs    : leaf, pathElements[20], pathIndices[20]
//!
//! Verification-only path: we don't need to re-derive the witness from an SMT;
//! we just validate the public signals against a locally computed Merkle root
//! using the provided path, then hand the proof + signals to ark-groth16.
//!
//! # Edge case 8 — front-running / witness replay
//!
//! The `document_existence` circuit does **not** bind a per-call nonce or
//! requester identity to its public signals.  A valid proof tuple `(A, B, C)`
//! for public signals `[root, leafIndex, treeSize]` is replayable: an
//! eavesdropper who intercepts the proof can wrap it in a new Protobuf
//! envelope addressed to themselves and submit it before the original request
//! resolves.
//!
//! Replay protection **must** be enforced at the application layer:
//!   * Record a hash of `(root ‖ leafIndex ‖ treeSize ‖ proof_bytes)` in the
//!     database and reject duplicate submissions.
//!   * Or bind the caller's Ed25519 public key to the outer request envelope
//!     and verify the signature before accepting the proof.
//!
//! The `redaction_validity` circuit already mitigates replay via the
//! `nullifier = Poseidon(originalRoot, redactedCommitment, recipientId)`
//! output signal.  Extending this pattern to existence circuits requires a
//! circuit recompilation with a new trusted-setup contribution.
//!
//! # Edge case 3 — treeSize = 0 corner case
//!
//! When `treeSize = 0` the in-circuit bounds check (`leafIndex < treeSize`) is
//! disabled because there are no leaves to index.  Off-chain verifiers **must**
//! reject proofs where `treeSize = 0` but the supplied `root` is not the
//! canonical empty-tree root — the circuit cannot enforce this because the
//! empty-tree root is not a circuit parameter.  See
//! `proofs/circuits/document_existence.circom` lines 72–82 for the comment.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use num_bigint::BigInt;
use thiserror::Error;

use crate::zk::poseidon::{compute_merkle_root, PoseidonError};

/// Convert an `Fr` to a `num_bigint::BigInt` (always non-negative — field
/// elements live in [0, r)). ark-circom's witness-input API takes `BigInt`,
/// not `Fr`, so this conversion is required when handing the witness off to
/// the WASM witness generator.
fn fr_to_bigint(f: &Fr) -> BigInt {
    let bytes_be = f.into_bigint().to_bytes_be();
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes_be)
}

pub const DEPTH: usize = 20;

#[derive(Debug, Error)]
pub enum ExistenceError {
    #[error("pathElements length must be {DEPTH}, got {0}")]
    WrongDepth(usize),
    #[error("pathIndices length must be {DEPTH}, got {0}")]
    WrongIndices(usize),
    #[error("pathIndices must be 0 or 1, got {0} at position {1}")]
    InvalidIndex(u8, usize),
    #[error("leaf_index must be < tree_size when tree_size > 0")]
    IndexOutOfBounds,
    #[error("Computed Merkle root does not match claimed root")]
    RootMismatch,
    #[error("Poseidon error: {0}")]
    Poseidon(#[from] PoseidonError),
}

/// All data needed to verify a document-existence proof locally.
pub struct ExistenceWitness {
    /// Public signals (order matches snarkjs output: root, leafIndex, treeSize).
    pub root: Fr,
    pub leaf_index: u64,
    pub tree_size: u64,
    /// Private inputs.
    pub leaf: Fr,
    pub path_elements: Vec<Fr>, // len == DEPTH
    pub path_indices: Vec<u8>,  // len == DEPTH, values in {0, 1}
}

impl ExistenceWitness {
    pub fn new(
        root: Fr,
        leaf_index: u64,
        tree_size: u64,
        leaf: Fr,
        path_elements: Vec<Fr>,
        path_indices: Vec<u8>,
    ) -> Result<Self, ExistenceError> {
        if path_elements.len() != DEPTH {
            return Err(ExistenceError::WrongDepth(path_elements.len()));
        }
        if path_indices.len() != DEPTH {
            return Err(ExistenceError::WrongIndices(path_indices.len()));
        }
        for (i, &idx) in path_indices.iter().enumerate() {
            if idx > 1 {
                return Err(ExistenceError::InvalidIndex(idx, i));
            }
        }
        if tree_size > 0 && leaf_index >= tree_size {
            return Err(ExistenceError::IndexOutOfBounds);
        }
        Ok(Self {
            root,
            leaf_index,
            tree_size,
            leaf,
            path_elements,
            path_indices,
        })
    }

    /// Re-derive the Merkle root from the private inputs and check it matches.
    /// Call this before submitting to the Groth16 verifier for a fast pre-check.
    pub fn verify_merkle_root(&self) -> Result<(), ExistenceError> {
        let computed = compute_merkle_root(
            self.leaf,
            &self.path_elements,
            &self.path_indices,
            1, // node domain
        )?;
        if computed != self.root {
            return Err(ExistenceError::RootMismatch);
        }
        Ok(())
    }

    /// Return public signals in the order expected by the circuit's `IC` vector:
    /// [root, leafIndex, treeSize]
    pub fn public_signals(&self) -> Vec<Fr> {
        vec![
            self.root,
            Fr::from(self.leaf_index),
            Fr::from(self.tree_size),
        ]
    }

    /// Inputs in the shape ark-circom's `CircomBuilder::push_input` accepts:
    /// `(name, Vec<BigInt>)` pairs. Names must match the circom signal
    /// declarations in `proofs/circuits/document_existence.circom`.
    ///
    /// Scalar inputs (`root`, `leafIndex`, `treeSize`, `leaf`) are passed as
    /// a one-element vec; array inputs as a vec of length `DEPTH`.
    pub fn circom_inputs(&self) -> Vec<(String, Vec<BigInt>)> {
        let path_elements: Vec<BigInt> = self.path_elements.iter().map(fr_to_bigint).collect();
        let path_indices: Vec<BigInt> = self
            .path_indices
            .iter()
            .map(|&b| BigInt::from(b as u64))
            .collect();
        vec![
            ("root".into(), vec![fr_to_bigint(&self.root)]),
            ("leafIndex".into(), vec![BigInt::from(self.leaf_index)]),
            ("treeSize".into(), vec![BigInt::from(self.tree_size)]),
            ("leaf".into(), vec![fr_to_bigint(&self.leaf)]),
            ("pathElements".into(), path_elements),
            ("pathIndices".into(), path_indices),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a length-DEPTH sibling path of all zeros — every test that doesn't
    // care about path content can use this and supply its own indices.
    fn zero_path() -> Vec<Fr> {
        vec![Fr::zero(); DEPTH]
    }

    fn zero_indices() -> Vec<u8> {
        vec![0u8; DEPTH]
    }

    // For the "valid Merkle path" tests we compute the root from a known leaf
    // and path so verify_merkle_root() returns Ok.
    fn root_for(leaf: Fr, path: &[Fr], indices: &[u8]) -> Fr {
        compute_merkle_root(leaf, path, indices, 1).expect("compute_merkle_root")
    }

    #[test]
    fn new_rejects_wrong_path_elements_depth() {
        let r = ExistenceWitness::new(
            Fr::zero(),
            0,
            1,
            Fr::zero(),
            vec![Fr::zero(); DEPTH - 1],
            zero_indices(),
        );
        assert!(matches!(r, Err(ExistenceError::WrongDepth(n)) if n == DEPTH - 1));
    }

    #[test]
    fn new_rejects_wrong_path_indices_depth() {
        let r = ExistenceWitness::new(
            Fr::zero(),
            0,
            1,
            Fr::zero(),
            zero_path(),
            vec![0u8; DEPTH - 1],
        );
        assert!(matches!(r, Err(ExistenceError::WrongIndices(n)) if n == DEPTH - 1));
    }

    #[test]
    fn new_rejects_non_binary_path_index() {
        let mut idx = zero_indices();
        idx[3] = 2;
        let r = ExistenceWitness::new(Fr::zero(), 0, 1, Fr::zero(), zero_path(), idx);
        assert!(matches!(r, Err(ExistenceError::InvalidIndex(2, 3))));
    }

    #[test]
    fn new_rejects_index_out_of_bounds_when_tree_nonempty() {
        let r = ExistenceWitness::new(Fr::zero(), 5, 5, Fr::zero(), zero_path(), zero_indices());
        assert!(matches!(r, Err(ExistenceError::IndexOutOfBounds)));
    }

    #[test]
    fn new_allows_tree_size_zero() {
        // Per the file-level comment, treeSize = 0 disables the in-circuit
        // bounds check — the off-chain witness must still construct, and the
        // caller is responsible for rejecting empty-tree roots.
        let r = ExistenceWitness::new(Fr::zero(), 0, 0, Fr::zero(), zero_path(), zero_indices());
        assert!(r.is_ok());
    }

    #[test]
    fn verify_merkle_root_succeeds_when_root_matches_path() {
        let leaf = Fr::from(7u64);
        let path = zero_path();
        let indices = zero_indices();
        let root = root_for(leaf, &path, &indices);
        let w = ExistenceWitness::new(root, 0, 1, leaf, path, indices).unwrap();
        assert!(w.verify_merkle_root().is_ok());
    }

    #[test]
    fn verify_merkle_root_fails_on_mismatch() {
        let w = ExistenceWitness::new(
            Fr::from(0xdeadbeefu64), // wrong root
            0,
            1,
            Fr::from(7u64),
            zero_path(),
            zero_indices(),
        )
        .unwrap();
        assert!(matches!(
            w.verify_merkle_root(),
            Err(ExistenceError::RootMismatch)
        ));
    }

    #[test]
    fn public_signals_order_is_root_leaf_index_tree_size() {
        let w = ExistenceWitness::new(
            Fr::from(42u64),
            3,
            10,
            Fr::from(7u64),
            zero_path(),
            zero_indices(),
        )
        .unwrap();
        let s = w.public_signals();
        assert_eq!(s.len(), 3);
        assert_eq!(s[0], Fr::from(42u64));
        assert_eq!(s[1], Fr::from(3u64));
        assert_eq!(s[2], Fr::from(10u64));
    }

    #[test]
    fn circom_inputs_have_expected_names_and_shapes() {
        let w = ExistenceWitness::new(
            Fr::from(42u64),
            3,
            10,
            Fr::from(7u64),
            zero_path(),
            zero_indices(),
        )
        .unwrap();
        let inputs = w.circom_inputs();
        let names: Vec<&str> = inputs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "root",
                "leafIndex",
                "treeSize",
                "leaf",
                "pathElements",
                "pathIndices"
            ]
        );
        // Scalars have one element; arrays have DEPTH.
        let by_name: std::collections::HashMap<&str, usize> =
            inputs.iter().map(|(n, v)| (n.as_str(), v.len())).collect();
        assert_eq!(by_name["root"], 1);
        assert_eq!(by_name["leafIndex"], 1);
        assert_eq!(by_name["treeSize"], 1);
        assert_eq!(by_name["leaf"], 1);
        assert_eq!(by_name["pathElements"], DEPTH);
        assert_eq!(by_name["pathIndices"], DEPTH);
    }
}
