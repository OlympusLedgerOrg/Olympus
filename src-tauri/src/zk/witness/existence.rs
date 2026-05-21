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
