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
use ark_ff::{BigInteger, PrimeField, Zero};
use num_bigint::BigInt;
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

    /// Public signals: [root].
    /// The non_existence circuit declares no output signals, so only the
    /// declared-public `root` appears in the snarkjs publicSignals vector.
    pub fn public_signals(&self) -> Vec<Fr> {
        vec![self.root]
    }

    /// (name, Vec<BigInt>) pairs for ark-circom's CircomBuilder.
    /// Circom signal names: `root`, `key[32]`, `pathElements[256]`.
    /// `pathIndices` is derived inside the circuit from `key` (L4-B) — we
    /// do NOT push it.
    pub fn circom_inputs(&self) -> Vec<(String, Vec<BigInt>)> {
        fn fr_to_bigint(f: &Fr) -> BigInt {
            let bytes_be = f.into_bigint().to_bytes_be();
            BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes_be)
        }
        let key: Vec<BigInt> = self.key.iter().map(|&b| BigInt::from(b as u64)).collect();
        let path_elements: Vec<BigInt> = self.path_elements.iter().map(fr_to_bigint).collect();
        vec![
            ("root".into(), vec![fr_to_bigint(&self.root)]),
            ("key".into(), key),
            ("pathElements".into(), path_elements),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_path() -> Vec<Fr> {
        vec![Fr::zero(); SMT_DEPTH]
    }

    #[test]
    fn new_rejects_wrong_path_length() {
        let r = NonExistenceWitness::new(Fr::zero(), [0u8; 32], vec![Fr::zero(); SMT_DEPTH - 1]);
        assert!(matches!(r, Err(NonExistenceError::WrongDepth(n)) if n == SMT_DEPTH - 1));
    }

    #[test]
    fn path_indices_all_zero_key_is_all_zeros() {
        let w = NonExistenceWitness::new(Fr::zero(), [0u8; 32], zero_path()).unwrap();
        assert_eq!(w.path_indices(), vec![0u8; SMT_DEPTH]);
    }

    #[test]
    fn path_indices_all_one_key_is_all_ones() {
        let w = NonExistenceWitness::new(Fr::zero(), [0xffu8; 32], zero_path()).unwrap();
        assert_eq!(w.path_indices(), vec![1u8; SMT_DEPTH]);
    }

    #[test]
    fn path_indices_msb_first_per_byte_then_reverse() {
        // Set only the top bit of the first byte → bit k=0.
        // Mapping rule: indices[255 - k] = key_bit, so indices[255] should be 1.
        let mut key = [0u8; 32];
        key[0] = 0b1000_0000;
        let w = NonExistenceWitness::new(Fr::zero(), key, zero_path()).unwrap();
        let idx = w.path_indices();
        assert_eq!(idx[255], 1, "top bit of byte 0 must land at index 255");
        // All other indices stay zero.
        assert!(idx.iter().take(255).all(|&b| b == 0));
    }

    #[test]
    fn path_indices_lsb_of_last_byte_lands_at_index_zero() {
        // Last byte LSB → k = 31*8 + 7 = 255, so indices[255-255] = indices[0] = 1.
        let mut key = [0u8; 32];
        key[31] = 0b0000_0001;
        let w = NonExistenceWitness::new(Fr::zero(), key, zero_path()).unwrap();
        let idx = w.path_indices();
        assert_eq!(idx[0], 1, "LSB of byte 31 must land at index 0");
        assert!(idx.iter().skip(1).all(|&b| b == 0));
    }

    #[test]
    fn verify_merkle_root_succeeds_for_consistent_root() {
        let key = [0u8; 32];
        let path = zero_path();
        // Compute the expected root using the same indices derivation.
        let w_template = NonExistenceWitness::new(Fr::zero(), key, path.clone()).unwrap();
        let indices = w_template.path_indices();
        let root = compute_merkle_root(Fr::zero(), &path, &indices, 1).expect("merkle");
        let w = NonExistenceWitness::new(root, key, path).unwrap();
        assert!(w.verify_merkle_root().is_ok());
    }

    #[test]
    fn verify_merkle_root_fails_on_wrong_root() {
        let w = NonExistenceWitness::new(Fr::from(0xdeadu64), [0u8; 32], zero_path()).unwrap();
        assert!(matches!(
            w.verify_merkle_root(),
            Err(NonExistenceError::RootMismatch)
        ));
    }

    #[test]
    fn public_signals_is_just_root() {
        let w = NonExistenceWitness::new(Fr::from(99u64), [0u8; 32], zero_path()).unwrap();
        let s = w.public_signals();
        assert_eq!(s, vec![Fr::from(99u64)]);
    }

    #[test]
    fn circom_inputs_have_root_key_and_path_only() {
        let w = NonExistenceWitness::new(Fr::from(1u64), [0x42u8; 32], zero_path()).unwrap();
        let inputs = w.circom_inputs();
        let names: Vec<&str> = inputs.iter().map(|(n, _)| n.as_str()).collect();
        // Crucially, no `pathIndices` — the circuit derives them from `key`.
        assert_eq!(names, vec!["root", "key", "pathElements"]);
        let by_name: std::collections::HashMap<&str, usize> =
            inputs.iter().map(|(n, v)| (n.as_str(), v.len())).collect();
        assert_eq!(by_name["root"], 1);
        assert_eq!(by_name["key"], 32);
        assert_eq!(by_name["pathElements"], SMT_DEPTH);
        // First byte of key should serialize as 0x42 = 66 in BigInt.
        let key_input = &inputs.iter().find(|(n, _)| n == "key").unwrap().1;
        assert_eq!(key_input[0], BigInt::from(0x42u64));
    }
}
