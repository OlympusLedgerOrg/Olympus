//! Witness for the `unified_canonicalization_inclusion_root_sign` circuit.
//!
//! Public signal vector (6, no output signals): `[canonicalHash,
//! merkleRoot, ledgerRoot, treeSize, checkpointTimestamp,
//! authorityPubKeyHash]`.
//!
//! Private inputs:
//!   * `documentSections[8]` — canonical section field elements (padded).
//!   * `sectionCount`         — number of real sections (≤ 8).
//!   * `sectionLengths[8]`    — byte length per section.
//!   * `sectionHashes[8]`     — BLAKE3-of-section as Fr (padded).
//!   * `merklePath[20]`       — sibling values for ledger Merkle inclusion.
//!   * `merkleIndices[20]`    — LSB-first index bits.
//!   * `leafIndex`            — leaf position in the ledger Merkle tree.
//!   * `ledgerPathElements[256]` / `ledgerPathIndices[256]` — SMT path.
//!   * Baby Jubjub authority pubkey `(authorityPubKeyX, authorityPubKeyY)`.
//!   * EdDSA-Poseidon signature `(sigR8x, sigR8y, sigS)` over the message
//!     `Poseidon(ledgerRoot, checkpointTimestamp)`.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigInt;
use thiserror::Error;

use crate::zk::witness::baby_jubjub::{BabyJubJubPubKey, BabyJubJubSignature};

/// Parameters must mirror `proofs/circuits/parameters.circom`.
pub const MAX_SECTIONS: usize = 8;
pub const MERKLE_DEPTH: usize = 20;
pub const SMT_DEPTH: usize = 256;

#[derive(Debug, Error)]
pub enum UnifiedError {
    #[error("documentSections must have length {MAX_SECTIONS}, got {0}")]
    WrongSections(usize),
    #[error("sectionLengths must have length {MAX_SECTIONS}, got {0}")]
    WrongLengths(usize),
    #[error("sectionHashes must have length {MAX_SECTIONS}, got {0}")]
    WrongHashes(usize),
    #[error("merklePath must have length {MERKLE_DEPTH}, got {0}")]
    WrongMerklePath(usize),
    #[error("merkleIndices must have length {MERKLE_DEPTH}, got {0}")]
    WrongMerkleIndices(usize),
    #[error("ledgerPathElements must have length {SMT_DEPTH}, got {0}")]
    WrongLedgerPath(usize),
    #[error("ledgerPathIndices must have length {SMT_DEPTH}, got {0}")]
    WrongLedgerIndices(usize),
    #[error("sectionCount {0} exceeds MAX_SECTIONS {MAX_SECTIONS}")]
    SectionCountOutOfRange(u64),
    #[error("merkleIndices[{0}] = {1} is not 0 or 1")]
    NonBinaryMerkleIndex(usize, u8),
    #[error("ledgerPathIndices[{0}] = {1} is not 0 or 1")]
    NonBinaryLedgerIndex(usize, u8),
}

pub struct UnifiedWitness {
    // ---- Public inputs ----
    pub canonical_hash: Fr,
    pub merkle_root: Fr,
    pub ledger_root: Fr,
    pub tree_size: u64,
    pub checkpoint_timestamp: u64,
    pub authority_pubkey_hash: Fr,

    // ---- Private inputs: document canonicalization ----
    pub document_sections: Vec<Fr>, // len == MAX_SECTIONS
    pub section_count: u64,
    pub section_lengths: Vec<u64>, // len == MAX_SECTIONS
    pub section_hashes: Vec<Fr>,   // len == MAX_SECTIONS

    // ---- Private inputs: Merkle inclusion ----
    pub merkle_path: Vec<Fr>,    // len == MERKLE_DEPTH
    pub merkle_indices: Vec<u8>, // len == MERKLE_DEPTH
    pub leaf_index: u64,

    // ---- Private inputs: SMT commitment ----
    pub ledger_path_elements: Vec<Fr>, // len == SMT_DEPTH
    pub ledger_path_indices: Vec<u8>,  // len == SMT_DEPTH

    // ---- Private inputs: Baby Jubjub authority + signature ----
    pub authority_pubkey: BabyJubJubPubKey,
    pub signature: BabyJubJubSignature,
}

impl UnifiedWitness {
    /// Structural validation only. Cryptographic checks (Merkle path
    /// re-derivation, signature pre-verification) are not yet performed
    /// here — the witness generator runs them inside the circuit, and
    /// adding native pre-checks is a follow-up.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        canonical_hash: Fr,
        merkle_root: Fr,
        ledger_root: Fr,
        tree_size: u64,
        checkpoint_timestamp: u64,
        authority_pubkey: BabyJubJubPubKey,
        document_sections: Vec<Fr>,
        section_count: u64,
        section_lengths: Vec<u64>,
        section_hashes: Vec<Fr>,
        merkle_path: Vec<Fr>,
        merkle_indices: Vec<u8>,
        leaf_index: u64,
        ledger_path_elements: Vec<Fr>,
        ledger_path_indices: Vec<u8>,
        signature: BabyJubJubSignature,
    ) -> Result<Self, UnifiedError> {
        if document_sections.len() != MAX_SECTIONS {
            return Err(UnifiedError::WrongSections(document_sections.len()));
        }
        if section_lengths.len() != MAX_SECTIONS {
            return Err(UnifiedError::WrongLengths(section_lengths.len()));
        }
        if section_hashes.len() != MAX_SECTIONS {
            return Err(UnifiedError::WrongHashes(section_hashes.len()));
        }
        if merkle_path.len() != MERKLE_DEPTH {
            return Err(UnifiedError::WrongMerklePath(merkle_path.len()));
        }
        if merkle_indices.len() != MERKLE_DEPTH {
            return Err(UnifiedError::WrongMerkleIndices(merkle_indices.len()));
        }
        if ledger_path_elements.len() != SMT_DEPTH {
            return Err(UnifiedError::WrongLedgerPath(ledger_path_elements.len()));
        }
        if ledger_path_indices.len() != SMT_DEPTH {
            return Err(UnifiedError::WrongLedgerIndices(ledger_path_indices.len()));
        }
        if section_count > MAX_SECTIONS as u64 {
            return Err(UnifiedError::SectionCountOutOfRange(section_count));
        }
        for (i, &b) in merkle_indices.iter().enumerate() {
            if b > 1 {
                return Err(UnifiedError::NonBinaryMerkleIndex(i, b));
            }
        }
        for (i, &b) in ledger_path_indices.iter().enumerate() {
            if b > 1 {
                return Err(UnifiedError::NonBinaryLedgerIndex(i, b));
            }
        }

        let authority_pubkey_hash = authority_pubkey
            .authority_hash()
            .expect("Poseidon(Ax, Ay) cannot fail for valid Fr inputs");

        Ok(Self {
            canonical_hash,
            merkle_root,
            ledger_root,
            tree_size,
            checkpoint_timestamp,
            authority_pubkey_hash,
            document_sections,
            section_count,
            section_lengths,
            section_hashes,
            merkle_path,
            merkle_indices,
            leaf_index,
            ledger_path_elements,
            ledger_path_indices,
            authority_pubkey,
            signature,
        })
    }

    /// Public signals in declaration order. The unified circuit has no
    /// output signals, so this is exactly `{public [...]}` from the
    /// circom source.
    pub fn public_signals(&self) -> Vec<Fr> {
        vec![
            self.canonical_hash,
            self.merkle_root,
            self.ledger_root,
            Fr::from(self.tree_size),
            Fr::from(self.checkpoint_timestamp),
            self.authority_pubkey_hash,
        ]
    }

    /// (name, Vec<BigInt>) pairs for ark-circom's CircomBuilder.
    pub fn circom_inputs(&self) -> Vec<(String, Vec<BigInt>)> {
        fn fr_to_bigint(f: &Fr) -> BigInt {
            let bytes_be = f.into_bigint().to_bytes_be();
            BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes_be)
        }
        let sections: Vec<BigInt> = self.document_sections.iter().map(fr_to_bigint).collect();
        let lengths: Vec<BigInt> = self.section_lengths.iter().map(|&n| BigInt::from(n)).collect();
        let hashes: Vec<BigInt> = self.section_hashes.iter().map(fr_to_bigint).collect();
        let merkle_path: Vec<BigInt> = self.merkle_path.iter().map(fr_to_bigint).collect();
        let merkle_indices: Vec<BigInt> = self
            .merkle_indices
            .iter()
            .map(|&b| BigInt::from(b as u64))
            .collect();
        let ledger_path: Vec<BigInt> = self.ledger_path_elements.iter().map(fr_to_bigint).collect();
        let ledger_indices: Vec<BigInt> = self
            .ledger_path_indices
            .iter()
            .map(|&b| BigInt::from(b as u64))
            .collect();

        vec![
            // Public inputs (the circuit consumes them as ordinary signals).
            ("canonicalHash".into(), vec![fr_to_bigint(&self.canonical_hash)]),
            ("merkleRoot".into(), vec![fr_to_bigint(&self.merkle_root)]),
            ("ledgerRoot".into(), vec![fr_to_bigint(&self.ledger_root)]),
            ("treeSize".into(), vec![BigInt::from(self.tree_size)]),
            ("checkpointTimestamp".into(), vec![BigInt::from(self.checkpoint_timestamp)]),
            (
                "authorityPubKeyHash".into(),
                vec![fr_to_bigint(&self.authority_pubkey_hash)],
            ),
            // Private inputs.
            ("documentSections".into(), sections),
            ("sectionCount".into(), vec![BigInt::from(self.section_count)]),
            ("sectionLengths".into(), lengths),
            ("sectionHashes".into(), hashes),
            ("merklePath".into(), merkle_path),
            ("merkleIndices".into(), merkle_indices),
            ("leafIndex".into(), vec![BigInt::from(self.leaf_index)]),
            ("ledgerPathElements".into(), ledger_path),
            ("ledgerPathIndices".into(), ledger_indices),
            (
                "authorityPubKeyX".into(),
                vec![fr_to_bigint(&self.authority_pubkey.x)],
            ),
            (
                "authorityPubKeyY".into(),
                vec![fr_to_bigint(&self.authority_pubkey.y)],
            ),
            ("sigR8x".into(), vec![fr_to_bigint(&self.signature.r8x)]),
            ("sigR8y".into(), vec![fr_to_bigint(&self.signature.r8y)]),
            ("sigS".into(), vec![fr_to_bigint(&self.signature.s)]),
        ]
    }
}
