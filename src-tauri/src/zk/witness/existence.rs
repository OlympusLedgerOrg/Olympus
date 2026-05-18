//! Witness for the `document_existence` circuit.
//!
//! Public inputs  (3): root, leafIndex, treeSize
//! Private inputs    : leaf, pathElements[20], pathIndices[20]
//!
//! Verification-only path: we don't need to re-derive the witness from an SMT;
//! we just validate the public signals against a locally computed Merkle root
//! using the provided path, then hand the proof + signals to ark-groth16.

use ark_bn254::Fr;
use ark_ff::Zero;
use thiserror::Error;

use crate::zk::poseidon::{compute_merkle_root, PoseidonError};

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
}
