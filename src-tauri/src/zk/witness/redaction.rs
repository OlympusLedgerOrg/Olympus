//! Witness for the `redaction_validity` circuit.
//!
//! Public signal vector (4): [nullifier, originalRoot, redactedCommitment, revealedCount]
//!   * `nullifier` is a circuit OUTPUT signal — in circom 2 every output is
//!     automatically public and appears BEFORE declared public inputs in the
//!     snarkjs publicSignals vector.
//!   * `nullifier = Poseidon(originalRoot, redactedCommitment, recipientId)`
//!     is bound to a specific recipient so the same disclosure can't be
//!     replayed without producing the same nullifier.
//!
//! Private inputs:
//!   originalLeaves[16], revealMask[16], pathElements[16][4], pathIndices[16][4],
//!   recipientId
//!
//! All 16 leaves (revealed and redacted) are Merkle-proven against
//! `original_root`. Index binding (LSB-first) means `pathIndices[i]` must
//! reconstruct `i` — the same leaf cannot be used twice at different positions.
//!
//! The commitment chain (domain tag 3):
//!     acc[0]   = DomainPoseidon(3, revealedCount, revealedLeaves[0])
//!     acc[k]   = DomainPoseidon(3, acc[k-1],     revealedLeaves[k])
//!     redactedCommitment = acc[MAX_LEAVES - 1]
//! where `revealedLeaves[i] = revealMask[i] * originalLeaves[i]`.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigInt;
use thiserror::Error;

use crate::zk::poseidon::{compute_merkle_root, hash_n, redaction_commitment, PoseidonError};

/// Parameters must mirror `proofs/circuits/parameters.circom`:
/// `REDACTION_MAX_LEAVES = 16`, `REDACTION_MERKLE_DEPTH = 4`.
pub const MAX_LEAVES: usize = 16;
pub const REDACTION_DEPTH: usize = 4;

#[derive(Debug, Error)]
pub enum RedactionError {
    #[error("leaves length must be {MAX_LEAVES}, got {0}")]
    WrongLeaves(usize),
    #[error("reveal_mask length must be {MAX_LEAVES}, got {0}")]
    WrongMask(usize),
    #[error("path_elements outer length must be {MAX_LEAVES}, got {0}")]
    WrongPathOuter(usize),
    #[error("path_elements[{0}] inner length must be {REDACTION_DEPTH}, got {1}")]
    WrongPathInner(usize, usize),
    #[error("path_indices[{0}] inner length must be {REDACTION_DEPTH}, got {1}")]
    WrongIndicesInner(usize, usize),
    #[error("path_indices[{leaf}][{level}] = {got} is not 0 or 1")]
    NonBinaryIndex { leaf: usize, level: usize, got: u8 },
    #[error("leaf {0}: pathIndices LSB-first do not reconstruct index {0}")]
    IndexBindingMismatch(usize),
    #[error("leaf {0} Merkle path does not reach originalRoot")]
    LeafRootMismatch(usize),
    #[error("Poseidon error: {0}")]
    Poseidon(#[from] PoseidonError),
}

pub struct RedactionWitness {
    // ---- Public signals (output then declared-public inputs) ----
    /// Output signal — bound to (originalRoot, redactedCommitment, recipientId).
    pub nullifier: Fr,
    /// Public input — Merkle root of the original document tree.
    pub original_root: Fr,
    /// Public input — domain-3 Poseidon chain over revealedCount + revealed leaves.
    pub redacted_commitment: Fr,
    /// Public input — popcount of `reveal_mask`.
    pub revealed_count: u64,

    // ---- Private inputs ----
    pub original_leaves: Vec<Fr>,    // len == MAX_LEAVES
    pub reveal_mask: Vec<bool>,      // len == MAX_LEAVES
    pub path_elements: Vec<Vec<Fr>>, // [MAX_LEAVES][REDACTION_DEPTH]
    pub path_indices: Vec<Vec<u8>>,  // [MAX_LEAVES][REDACTION_DEPTH]
    pub recipient_id: Fr,
}

impl RedactionWitness {
    /// Build a redaction witness from the raw inputs. Performs structural
    /// validation only — the Merkle paths are checked separately by
    /// [`Self::verify_all_paths`] (which is also called by the prover as a
    /// fast pre-check before invoking ark-circom).
    pub fn new(
        original_root: Fr,
        original_leaves: Vec<Fr>,
        reveal_mask: Vec<bool>,
        path_elements: Vec<Vec<Fr>>,
        path_indices: Vec<Vec<u8>>,
        recipient_id: Fr,
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
        if path_indices.len() != MAX_LEAVES {
            return Err(RedactionError::WrongPathOuter(path_indices.len()));
        }
        for (i, (pe, pi)) in path_elements.iter().zip(path_indices.iter()).enumerate() {
            if pe.len() != REDACTION_DEPTH {
                return Err(RedactionError::WrongPathInner(i, pe.len()));
            }
            if pi.len() != REDACTION_DEPTH {
                return Err(RedactionError::WrongIndicesInner(i, pi.len()));
            }
            // Binary + LSB-first index binding to position `i`.
            let mut reconstructed: usize = 0;
            for (b, &bit) in pi.iter().enumerate() {
                if bit > 1 {
                    return Err(RedactionError::NonBinaryIndex {
                        leaf: i,
                        level: b,
                        got: bit,
                    });
                }
                reconstructed |= (bit as usize) << b;
            }
            if reconstructed != i {
                return Err(RedactionError::IndexBindingMismatch(i));
            }
        }

        let revealed_count = reveal_mask.iter().filter(|&&b| b).count() as u64;
        let redacted_commitment =
            redaction_commitment(revealed_count, &original_leaves, &reveal_mask)?;

        // nullifier = Poseidon(originalRoot, redactedCommitment, recipientId).
        // 3-input Poseidon — the circuit invokes `Poseidon(3)` in nullifierHash.
        let nullifier = hash_n(&[original_root, redacted_commitment, recipient_id])?;

        Ok(Self {
            nullifier,
            original_root,
            redacted_commitment,
            revealed_count,
            original_leaves,
            reveal_mask,
            path_elements,
            path_indices,
            recipient_id,
        })
    }

    /// Verify every leaf's Merkle path reaches `original_root`. Run as a
    /// pre-check before proving — a failed root match here would otherwise
    /// surface as a much more expensive witness-generation panic.
    pub fn verify_all_paths(&self) -> Result<(), RedactionError> {
        for i in 0..MAX_LEAVES {
            let computed = compute_merkle_root(
                self.original_leaves[i],
                &self.path_elements[i],
                &self.path_indices[i],
                1, // node domain
            )?;
            if computed != self.original_root {
                return Err(RedactionError::LeafRootMismatch(i));
            }
        }
        Ok(())
    }

    /// Public signals in snarkjs vector order: outputs first, then declared
    /// public inputs in source order.
    pub fn public_signals(&self) -> Vec<Fr> {
        vec![
            self.nullifier,
            self.original_root,
            self.redacted_commitment,
            Fr::from(self.revealed_count),
        ]
    }

    /// (name, Vec<BigInt>) pairs for ark-circom. Names match the circom
    /// signal declarations exactly.
    pub fn circom_inputs(&self) -> Vec<(String, Vec<BigInt>)> {
        fn fr_to_bigint(f: &Fr) -> BigInt {
            let bytes_be = f.into_bigint().to_bytes_be();
            BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes_be)
        }

        let original_root = vec![fr_to_bigint(&self.original_root)];
        let redacted_commitment = vec![fr_to_bigint(&self.redacted_commitment)];
        let revealed_count = vec![BigInt::from(self.revealed_count)];

        let original_leaves: Vec<BigInt> = self.original_leaves.iter().map(fr_to_bigint).collect();
        let reveal_mask: Vec<BigInt> = self
            .reveal_mask
            .iter()
            .map(|&b| BigInt::from(b as u64))
            .collect();
        // Circom expects flat row-major arrays: `pathElements[16][4]` is pushed
        // as 16*4 = 64 individual values, leaf-major, level-minor.
        let mut path_elements: Vec<BigInt> = Vec::with_capacity(MAX_LEAVES * REDACTION_DEPTH);
        let mut path_indices: Vec<BigInt> = Vec::with_capacity(MAX_LEAVES * REDACTION_DEPTH);
        for i in 0..MAX_LEAVES {
            for j in 0..REDACTION_DEPTH {
                path_elements.push(fr_to_bigint(&self.path_elements[i][j]));
                path_indices.push(BigInt::from(self.path_indices[i][j] as u64));
            }
        }
        let recipient_id = vec![fr_to_bigint(&self.recipient_id)];

        vec![
            ("originalRoot".into(), original_root),
            ("redactedCommitment".into(), redacted_commitment),
            ("revealedCount".into(), revealed_count),
            ("originalLeaves".into(), original_leaves),
            ("revealMask".into(), reveal_mask),
            ("pathElements".into(), path_elements),
            ("pathIndices".into(), path_indices),
            ("recipientId".into(), recipient_id),
        ]
    }
}
