//! Witness for the `redaction_validity` circuit.
//!
//! Public inputs  (3): originalRoot, redactedCommitment, revealedCount
//! Private inputs    : originalLeaves[6], revealMask[6],
//!                     pathElements[6][3], pathIndices[6][3]
//!
//! All 6 leaves (including redacted ones) must be proven in the original tree.
//! The commitment chain: acc = revealedCount, then for each leaf:
//!   acc = DomainPoseidon(3, acc, revealed_value_or_0)

use ark_bn254::Fr;
use thiserror::Error;

use crate::zk::poseidon::{compute_merkle_root, redaction_commitment, PoseidonError};

pub const MAX_LEAVES: usize = 6;
pub const REDACTION_DEPTH: usize = 3;

#[derive(Debug, Error)]
pub enum RedactionError {
    #[error("leaves length must be {MAX_LEAVES}, got {0}")]
    WrongLeaves(usize),
    #[error("reveal_mask length must be {MAX_LEAVES}, got {0}")]
    WrongMask(usize),
    #[error("path_elements must be [6][3], outer len {0}")]
    WrongPathOuter(usize),
    #[error("path_elements[{0}] must have length {REDACTION_DEPTH}, got {1}")]
    WrongPathInner(usize, usize),
    #[error("path_indices[{0}] must have length {REDACTION_DEPTH}, got {1}")]
    WrongIndicesInner(usize, usize),
    #[error("leaf {0} Merkle path does not reach originalRoot")]
    LeafRootMismatch(usize),
    #[error("Computed redactedCommitment does not match claimed value")]
    CommitmentMismatch,
    #[error("Computed revealedCount does not match claimed value")]
    CountMismatch,
    #[error("Poseidon error: {0}")]
    Poseidon(#[from] PoseidonError),
}

pub struct RedactionWitness {
    // Public signals
    pub original_root: Fr,
    pub redacted_commitment: Fr,
    pub revealed_count: u64,
    // Private inputs
    pub original_leaves: Vec<Fr>,  // len == MAX_LEAVES
    pub reveal_mask: Vec<bool>,    // len == MAX_LEAVES
    pub path_elements: Vec<Vec<Fr>>, // [MAX_LEAVES][REDACTION_DEPTH]
    pub path_indices: Vec<Vec<u8>>,  // [MAX_LEAVES][REDACTION_DEPTH]
}

impl RedactionWitness {
    pub fn new(
        original_root: Fr,
        original_leaves: Vec<Fr>,
        reveal_mask: Vec<bool>,
        path_elements: Vec<Vec<Fr>>,
        path_indices: Vec<Vec<u8>>,
    ) -> Result<Self, RedactionError> {
        if original_leaves.len() != MAX_LEAVES {
            return Err(RedactionError::WrongLeaves(original_leaves.len()));
        }
        if reveal_mask.len() != MAX_LEAVES {
            return Err(RedactionError::WrongMask(reveal_mask.len()));
        }
        if path_elements.len() != MAX_LEAVES {
            return Err(RedactionError::WrongPathOuter(path_elements.len()));
        }
        for (i, (pe, pi)) in path_elements.iter().zip(path_indices.iter()).enumerate() {
            if pe.len() != REDACTION_DEPTH {
                return Err(RedactionError::WrongPathInner(i, pe.len()));
            }
            if pi.len() != REDACTION_DEPTH {
                return Err(RedactionError::WrongIndicesInner(i, pi.len()));
            }
        }

        let revealed_count = reveal_mask.iter().filter(|&&b| b).count() as u64;
        let redacted_commitment =
            redaction_commitment(revealed_count, &original_leaves, &reveal_mask)?;

        Ok(Self {
            original_root,
            redacted_commitment,
            revealed_count,
            original_leaves,
            reveal_mask,
            path_elements,
            path_indices,
        })
    }

    /// Verify all 6 leaf Merkle paths reach `original_root`.
    pub fn verify_all_paths(&self) -> Result<(), RedactionError> {
        for i in 0..MAX_LEAVES {
            let pi: Vec<u8> = self.path_indices[i].clone();
            let computed = compute_merkle_root(
                self.original_leaves[i],
                &self.path_elements[i],
                &pi,
                1,
            )?;
            if computed != self.original_root {
                return Err(RedactionError::LeafRootMismatch(i));
            }
        }
        Ok(())
    }

    /// Public signals: [originalRoot, redactedCommitment, revealedCount]
    pub fn public_signals(&self) -> Vec<Fr> {
        vec![
            self.original_root,
            self.redacted_commitment,
            Fr::from(self.revealed_count),
        ]
    }
}
