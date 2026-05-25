//! Witness for the `unified_canonicalization_inclusion_root_sign` circuit.
//!
//! Public signal vector (4, matching the circuit's `component main {public
//! [...]}`): `[canonicalHash, merkleRoot, ledgerRoot, treeSize]`.
//!
//! Private inputs the circuit actually declares:
//!   * `documentSections[8]` — canonical section field elements (padded).
//!   * `sectionCount`         — number of real sections (≤ 8).
//!   * `sectionLengths[8]`    — byte length per section.
//!   * `sectionHashes[8]`     — BLAKE3-of-section as Fr (padded).
//!   * `merklePath[20]`       — sibling values for ledger Merkle inclusion.
//!   * `merkleIndices[20]`    — LSB-first index bits.
//!   * `leafIndex`            — leaf position in the ledger Merkle tree.
//!   * `ledgerPathElements[256]` / `ledgerPathIndices[256]` — SMT path.
//!
//! **Off-circuit-only context this struct also carries:**
//! `checkpoint_timestamp`, `authority_pubkey`, `authority_pubkey_hash`, and
//! `signature` are NOT consumed by the circuit. They live on the witness so
//! `sign_checkpoint` (used by `federation::checkpoint::build_own_checkpoint`)
//! has the message material on hand to produce a Baby Jubjub EdDSA-Poseidon
//! signature that the federation verifier checks **off-circuit** in
//! `federation::verify::verify_checkpoint_signature`. Earlier revisions of
//! this file claimed the `_root_sign` suffix in the circuit name implied an
//! in-circuit `EdDSAPoseidonVerifier`; that template was never wired in, and
//! the circuit's own docstring (`proofs/circuits/...:42`) is explicit that
//! checkpoint integrity is verified at the Rust/federation layer. Audit C-1.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigInt;
use thiserror::Error;

use crate::zk::poseidon::hash2;
use crate::zk::witness::baby_jubjub::{
    sign as bjj_sign, BabyJubJubError, BabyJubJubPubKey, BabyJubJubSignature,
};

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

    /// Convenience: sign the checkpoint message `Poseidon(ledgerRoot,
    /// checkpointTimestamp)` with the supplied 32-byte raw private key and
    /// return a `BabyJubJubSignature` ready to drop into `UnifiedWitness`
    /// (or into a federation `PeerCheckpoint.bjj_signature` directly).
    ///
    /// This signature is verified **off-circuit** by
    /// `federation::verify::verify_checkpoint_signature`. The unified circuit
    /// does NOT contain an `EdDSAPoseidonVerifier` template — the signature
    /// rides on the witness as off-circuit context only. Using this helper
    /// guarantees the caller signs the same message digest the federation
    /// verifier reconstructs (`Poseidon(ledger_root, checkpoint_timestamp)`).
    /// Audit C-1.
    pub fn sign_checkpoint(
        priv_key: &[u8; 32],
        ledger_root: Fr,
        checkpoint_timestamp: u64,
    ) -> Result<BabyJubJubSignature, BabyJubJubError> {
        let msg = hash2(ledger_root, Fr::from(checkpoint_timestamp))?;
        bjj_sign(priv_key, msg)
    }

    /// Public signals in the order the circuit's `component main {public
    /// [...]}` declares them: `[canonicalHash, merkleRoot, ledgerRoot,
    /// treeSize]`. The unified circuit has no `signal output`, so no
    /// synthetic public signals precede these.
    ///
    /// Earlier revisions also appended `checkpointTimestamp` and
    /// `authorityPubKeyHash` (returning a 6-vec) on the assumption the
    /// circuit would grow an in-circuit `EdDSAPoseidonVerifier`. That
    /// template was never added; appending those values silently produced
    /// a witness vector with the wrong arity for the live circuit and any
    /// caller threading it into `verify_with_processed_vk` would have been
    /// rejected. The two values still live on the struct because
    /// `sign_checkpoint` and `federation::verify_checkpoint_signature`
    /// reconstruct the off-circuit message digest from them — they are
    /// just not in the public-signal vector. Audit C-2.
    pub fn public_signals(&self) -> Vec<Fr> {
        vec![
            self.canonical_hash,
            self.merkle_root,
            self.ledger_root,
            Fr::from(self.tree_size),
        ]
    }

    /// (name, Vec<BigInt>) pairs for ark-circom's CircomBuilder. Only the
    /// signals the circuit actually declares are pushed — the four
    /// `component main` publics plus the nine private inputs in the circom
    /// source.
    ///
    /// Earlier revisions also pushed `checkpointTimestamp`,
    /// `authorityPubKeyHash`, `authorityPubKeyX`, `authorityPubKeyY`,
    /// `sigR8x`, `sigR8y`, `sigS` on the assumption the circuit would
    /// later add an in-circuit `EdDSAPoseidonVerifier`. The circuit never
    /// did. ark-circom's `CircomBuilder::push_input` silently discards
    /// unknown signal names, so the dead pushes were a doc/intent lie
    /// rather than a runtime error — but they made it look like the
    /// witness was binding values the prover doesn't actually constrain.
    /// Removed in this pass to keep witness intent and circuit reality
    /// in sync. Audit C-1.
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
            // Public inputs (the four `component main {public [...]}` entries).
            ("canonicalHash".into(), vec![fr_to_bigint(&self.canonical_hash)]),
            ("merkleRoot".into(), vec![fr_to_bigint(&self.merkle_root)]),
            ("ledgerRoot".into(), vec![fr_to_bigint(&self.ledger_root)]),
            ("treeSize".into(), vec![BigInt::from(self.tree_size)]),
            // Private inputs the circuit actually declares.
            ("documentSections".into(), sections),
            ("sectionCount".into(), vec![BigInt::from(self.section_count)]),
            ("sectionLengths".into(), lengths),
            ("sectionHashes".into(), hashes),
            ("merklePath".into(), merkle_path),
            ("merkleIndices".into(), merkle_indices),
            ("leafIndex".into(), vec![BigInt::from(self.leaf_index)]),
            ("ledgerPathElements".into(), ledger_path),
            ("ledgerPathIndices".into(), ledger_indices),
        ]
    }
}
