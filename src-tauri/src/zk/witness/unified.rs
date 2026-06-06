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

use crate::zk::poseidon::{compute_merkle_root, hash2, PoseidonError};
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
    #[error(
        "merkle inclusion mismatch: recomputed merkleRoot {recomputed} does not equal the \
         witness merkleRoot {expected} — check canonicalHash, merklePath, merkleIndices"
    )]
    MerkleRootMismatch {
        recomputed: String,
        expected: String,
    },
    #[error(
        "SMT inclusion mismatch: recomputed ledgerRoot {recomputed} does not equal the witness \
         ledgerRoot {expected} — check merkleRoot, ledgerPathElements, ledgerPathIndices"
    )]
    LedgerRootMismatch {
        recomputed: String,
        expected: String,
    },
    #[error("Poseidon hashing failed during native pre-check: {0}")]
    Poseidon(#[from] PoseidonError),
    #[error(
        "sectionHashes[{index}] mismatch: recomputed Poseidon(documentSections[{index}]) = \
         {recomputed} does not equal the witness sectionHashes[{index}] = {expected} \
         (audit H-1: the in-circuit binding requires sectionHashes[i] == Poseidon(documentSections[i]))"
    )]
    SectionHashMismatch {
        index: usize,
        recomputed: String,
        expected: String,
    },
}

fn fr_to_bigint(f: &Fr) -> BigInt {
    let bytes_be = f.into_bigint().to_bytes_be();
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes_be)
}

use crate::zk::proof::fr_to_decimal;

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

    /// Audit M-Z1: native Rust pre-check that the witness is consistent
    /// with the public inputs *before* handing it to the WASM witness
    /// generator. Without this, a malformed witness (typo in a path
    /// element, off-by-one index, stale Merkle root) burns a 4-slot
    /// `WASM_SEM` semaphore for the full witness-construction time on
    /// the way to an opaque failure — a DoS lever for callers that can
    /// hold open four bad proves in parallel.
    ///
    /// Checks performed:
    ///   1. `compute_merkle_root(canonical_hash, merkle_path, merkle_indices)
    ///      == merkle_root` (mirrors `merkleProof.leaf <== canonicalHash`
    ///      in unified_canonicalization_inclusion_root_sign.circom).
    ///   2. `compute_merkle_root(merkle_root, ledger_path_elements,
    ///      ledger_path_indices) == ledger_root` (mirrors
    ///      `ledgerSMTProof.leaf <== merkleRoot`).
    ///
    /// **Not checked here:** EdDSA-Poseidon signature verification (heavy
    /// — defer to in-circuit) and the structured canonicalization chain
    /// (the section-hashes Poseidon chain that produces `canonicalHash`
    /// from `sectionHashes[]`/`sectionLengths[]`). Both surface as clean
    /// circuit-side failures with the cheap pre-check passing; the goal
    /// here is just to catch the two most common shape errors fast.
    pub fn verify_inputs(&self) -> Result<(), UnifiedError> {
        // Audit H-1: sectionHashes[i] must equal Poseidon(documentSections[i]),
        // mirroring the in-circuit binding so a malformed witness fails the
        // pre-check fast (microseconds) instead of waiting for WASM witness
        // generation to surface the same constraint failure.
        for i in 0..MAX_SECTIONS {
            let computed = crate::zk::poseidon::hash_n(&[self.document_sections[i]])?;
            if computed != self.section_hashes[i] {
                return Err(UnifiedError::SectionHashMismatch {
                    index: i,
                    recomputed: fr_to_decimal(&computed),
                    expected: fr_to_decimal(&self.section_hashes[i]),
                });
            }
        }

        // 1. Merkle inclusion: canonicalHash → merkleRoot via merklePath.
        let computed_merkle = compute_merkle_root(
            self.canonical_hash,
            &self.merkle_path,
            &self.merkle_indices,
            1, // node domain — matches existence / non_existence circuits.
        )?;
        if computed_merkle != self.merkle_root {
            return Err(UnifiedError::MerkleRootMismatch {
                recomputed: fr_to_decimal(&computed_merkle),
                expected: fr_to_decimal(&self.merkle_root),
            });
        }

        // 2. SMT inclusion: merkleRoot → ledgerRoot via ledgerPath{Elements,Indices}.
        let computed_ledger = compute_merkle_root(
            self.merkle_root,
            &self.ledger_path_elements,
            &self.ledger_path_indices,
            1,
        )?;
        if computed_ledger != self.ledger_root {
            return Err(UnifiedError::LedgerRootMismatch {
                recomputed: fr_to_decimal(&computed_ledger),
                expected: fr_to_decimal(&self.ledger_root),
            });
        }

        Ok(())
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
        let sections: Vec<BigInt> = self.document_sections.iter().map(fr_to_bigint).collect();
        let lengths: Vec<BigInt> = self
            .section_lengths
            .iter()
            .map(|&n| BigInt::from(n))
            .collect();
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
            (
                "canonicalHash".into(),
                vec![fr_to_bigint(&self.canonical_hash)],
            ),
            ("merkleRoot".into(), vec![fr_to_bigint(&self.merkle_root)]),
            ("ledgerRoot".into(), vec![fr_to_bigint(&self.ledger_root)]),
            ("treeSize".into(), vec![BigInt::from(self.tree_size)]),
            // Private inputs the circuit actually declares.
            ("documentSections".into(), sections),
            (
                "sectionCount".into(),
                vec![BigInt::from(self.section_count)],
            ),
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

#[cfg(test)]
mod tests {
    //! Audit M-Z1: pin the `verify_inputs` pre-check behaviour so future
    //! refactors of the unified circuit recipe must update the native
    //! mirror in lockstep.
    use super::*;
    use ark_ff::Zero;

    /// Build a self-consistent witness: pick a canonical_hash, derive
    /// merkle_root from a zero-padded path, then derive ledger_root from
    /// a zero-padded SMT path under that merkle_root. Signature is a
    /// throwaway zero — verify_inputs doesn't touch it.
    fn consistent_witness(canonical: Fr) -> UnifiedWitness {
        let merkle_path = vec![Fr::zero(); MERKLE_DEPTH];
        let merkle_indices = vec![0u8; MERKLE_DEPTH];
        let merkle_root = compute_merkle_root(canonical, &merkle_path, &merkle_indices, 1).unwrap();
        let ledger_path = vec![Fr::zero(); SMT_DEPTH];
        let ledger_indices = vec![0u8; SMT_DEPTH];
        let ledger_root =
            compute_merkle_root(merkle_root, &ledger_path, &ledger_indices, 1).unwrap();

        let authority_pubkey = BabyJubJubPubKey {
            x: Fr::from(1u64),
            y: Fr::from(2u64),
        };
        let signature = BabyJubJubSignature {
            r8x: Fr::zero(),
            r8y: Fr::zero(),
            s: Fr::zero(),
        };
        UnifiedWitness {
            canonical_hash: canonical,
            merkle_root,
            ledger_root,
            tree_size: 1,
            checkpoint_timestamp: 1_700_000_000,
            authority_pubkey_hash: authority_pubkey.authority_hash().unwrap(),
            // Audit H-1: section_hashes[i] = Poseidon(document_sections[i]).
            // The test fixture uses zero-filled sections; the matching hashes
            // must therefore be Poseidon(0), not zero.
            document_sections: vec![Fr::zero(); MAX_SECTIONS],
            section_count: 0,
            section_lengths: vec![0; MAX_SECTIONS],
            section_hashes: vec![crate::zk::poseidon::hash_n(&[Fr::zero()]).unwrap(); MAX_SECTIONS],
            merkle_path,
            merkle_indices,
            leaf_index: 0,
            ledger_path_elements: ledger_path,
            ledger_path_indices: ledger_indices,
            authority_pubkey,
            signature,
        }
    }

    #[test]
    fn verify_inputs_accepts_consistent_witness() {
        // Baseline: a witness whose merkle/ledger roots are re-derivable
        // from the supplied paths must pass.
        let w = consistent_witness(Fr::from(42u64));
        assert!(w.verify_inputs().is_ok());
    }

    #[test]
    fn verify_inputs_rejects_tampered_merkle_root() {
        // M-Z1: flipping merkle_root after path construction must be
        // caught by the native pre-check before WASM witness gen runs.
        let mut w = consistent_witness(Fr::from(7u64));
        w.merkle_root = Fr::from(0xdeadu64);
        let err = w.verify_inputs().expect_err("must reject");
        assert!(
            matches!(err, UnifiedError::MerkleRootMismatch { .. }),
            "wanted MerkleRootMismatch, got {err:?}"
        );
    }

    #[test]
    fn verify_inputs_rejects_tampered_canonical_hash() {
        // M-Z1: canonicalHash is the Merkle leaf — tampering with it
        // makes the recomputed merkleRoot diverge.
        let mut w = consistent_witness(Fr::from(11u64));
        w.canonical_hash = Fr::from(99u64);
        assert!(matches!(
            w.verify_inputs(),
            Err(UnifiedError::MerkleRootMismatch { .. })
        ));
    }

    #[test]
    fn verify_inputs_rejects_tampered_ledger_root() {
        // M-Z1: ledger SMT inclusion is the second check; flipping
        // ledger_root must fire LedgerRootMismatch (not Merkle —
        // Merkle stage passes first).
        let mut w = consistent_witness(Fr::from(17u64));
        w.ledger_root = Fr::from(0xbeefu64);
        let err = w.verify_inputs().expect_err("must reject");
        assert!(
            matches!(err, UnifiedError::LedgerRootMismatch { .. }),
            "wanted LedgerRootMismatch, got {err:?}"
        );
    }

    #[test]
    fn verify_inputs_rejects_tampered_merkle_path() {
        // M-Z1: flipping a single sibling in the Merkle path silently
        // changes the recomputed root. Native check catches it.
        let mut w = consistent_witness(Fr::from(23u64));
        w.merkle_path[5] = Fr::from(0xcafeu64);
        assert!(matches!(
            w.verify_inputs(),
            Err(UnifiedError::MerkleRootMismatch { .. })
        ));
    }

    #[test]
    fn verify_inputs_rejects_tampered_smt_path() {
        // M-Z1: same as above but for the SMT side — surfaces as
        // LedgerRootMismatch.
        let mut w = consistent_witness(Fr::from(29u64));
        w.ledger_path_elements[100] = Fr::from(0xf00du64);
        assert!(matches!(
            w.verify_inputs(),
            Err(UnifiedError::LedgerRootMismatch { .. })
        ));
    }

    #[test]
    fn error_message_includes_both_roots_for_debug() {
        // Error variants carry the recomputed AND expected roots so an
        // operator debugging a malformed witness can spot the
        // disagreement without re-running the prove path with extra
        // logging.
        let mut w = consistent_witness(Fr::from(31u64));
        w.merkle_root = Fr::from(123u64);
        let msg = w.verify_inputs().expect_err("must reject").to_string();
        assert!(msg.contains("recomputed"), "got: {msg}");
        assert!(msg.contains("123"), "got: {msg}");
    }
}
