//! Witness for the `non_existence` (Sparse Merkle Tree) circuit.
//!
//! Public inputs  (1): root
//! Private inputs    : key[32] (bytes), pathElements[256]
//!
//! Key design (L4-B security hardening):
//!   - `key` is PRIVATE — the prover cannot choose an arbitrary empty slot
//!   - Path indices are derived MSB-first within each byte, then reversed for
//!     bottom-up traversal: key bit `b*8 + i` maps to Merkle level `255 - (b*8+i)`
//!   - The leaf at the derived path must be 0 (empty sentinel)

use ark_bn254::Fr;
use ark_ff::Zero;
use thiserror::Error;

use crate::zk::poseidon::{compute_merkle_root, PoseidonError};

pub const SMT_DEPTH: usize = 256;

#[derive(Debug, Error)]
pub enum NonExistenceError {
    #[error("key must be exactly 32 bytes, got {0}")]
    WrongKeyLen(usize),
    #[error("pathElements length must be {SMT_DEPTH}, got {0}")]
    WrongDepth(usize),
    #[error("Leaf at key path is not the empty sentinel (0)")]
    LeafNotEmpty,
    #[error("Computed SMT root does not match claimed root")]
    RootMismatch,
    #[error("Poseidon error: {0}")]
    Poseidon(#[from] PoseidonError),
}

pub struct NonExistenceWitness {
    /// Public signal: the SMT root.
    pub root: Fr,
    /// Private: 32-byte key (BLAKE3 hash of the document or similar).
    pub key: [u8; 32],
    /// Private: SMT sibling path, depth=256, leaf-to-root order.
    pub path_elements: Vec<Fr>,
}

impl NonExistenceWitness {
    pub fn new(
        root: Fr,
        key: [u8; 32],
        path_elements: Vec<Fr>,
    ) -> Result<Self, NonExistenceError> {
        if path_elements.len() != SMT_DEPTH {
            return Err(NonExistenceError::WrongDepth(path_elements.len()));
        }
        Ok(Self { root, key, path_elements })
    }

    /// Derive `pathIndices` from `key` exactly as the circuit does:
    ///
    /// For bit `k = byte_idx * 8 + bit_in_byte` (MSB-first within byte):
    ///   path level = 255 - k  →  path_indices[255 - k] = key_bit
    pub fn path_indices(&self) -> Vec<u8> {
        let mut indices = vec![0u8; SMT_DEPTH];
        for (byte_idx, &byte) in self.key.iter().enumerate() {
            for bit_in_byte in 0..8usize {
                // MSB-first extraction
                let bit = (byte >> (7 - bit_in_byte)) & 1;
                let k = byte_idx * 8 + bit_in_byte;
                indices[255 - k] = bit;
            }
        }
        indices
    }

    /// Verify the SMT path: leaf must be 0 and derived root must match.
    pub fn verify_merkle_root(&self) -> Result<(), NonExistenceError> {
        let indices = self.path_indices();
        // Leaf = 0 (empty sentinel)
        let computed = compute_merkle_root(Fr::zero(), &self.path_elements, &indices, 1)?;
        if computed != self.root {
            return Err(NonExistenceError::RootMismatch);
        }
        Ok(())
    }

    /// Public signals: [root]
    pub fn public_signals(&self) -> Vec<Fr> {
        vec![self.root]
    }
}
