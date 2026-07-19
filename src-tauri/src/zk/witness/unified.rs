//! Witness for the `unified_canonicalization_inclusion_root_sign` circuit.
//!
//! Public signal vector (5, matching the circuit's `component main {public
//! [...]}`): `[canonicalHash, merkleRoot, ledgerRoot, treeSize, ledgerKeyHash]`.
//!
//! Private inputs the circuit actually declares:
//!   * `documentSections[8]` — canonical section field elements (padded).
//!   * `sectionCount`         — number of real sections (≤ 8).
//!   * `sectionLengths[8]`    — byte length per section.
//!   * `sectionHashes[8]`     — BLAKE3-of-section as Fr (padded).
//!   * `merklePath[20]`       — sibling values for ledger Merkle inclusion.
//!   * `merkleIndices[20]`    — LSB-first index bits.
//!   * `leafIndex`            — leaf position in the ledger Merkle tree.
//!   * `ledgerPathElements[256]` — SMT path siblings.
//!   * `ledgerKey[32]`           — SMT lookup key; path bits derive in-circuit.
//!
//! The historical `_root_sign` artifact suffix does not describe the live
//! R1CS: checkpoint timestamps, authority keys, and signatures are not circuit
//! signals. They therefore do not belong in this witness. Checkpoint authority
//! is authenticated separately by the Rust/federation verifier. Audit C-1.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use num_bigint::BigInt;
use thiserror::Error;

use crate::zk::poseidon::{compute_merkle_root, hash2, PoseidonError, NODE_DOMAIN};

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
    #[error("sectionCount {0} exceeds MAX_SECTIONS {MAX_SECTIONS}")]
    SectionCountOutOfRange(u64),
    #[error("merkleIndices[{0}] = {1} is not 0 or 1")]
    NonBinaryMerkleIndex(usize, u8),
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
         ledgerRoot {expected} — check merkleRoot, ledgerPathElements, ledgerKey"
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
    pub ledger_key: [u8; 32],
}

impl UnifiedWitness {
    /// Structural validation only. Cryptographic path re-derivation is
    /// performed by [`Self::verify_inputs`] before witness generation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        canonical_hash: Fr,
        merkle_root: Fr,
        ledger_root: Fr,
        tree_size: u64,
        document_sections: Vec<Fr>,
        section_count: u64,
        section_lengths: Vec<u64>,
        section_hashes: Vec<Fr>,
        merkle_path: Vec<Fr>,
        merkle_indices: Vec<u8>,
        leaf_index: u64,
        ledger_path_elements: Vec<Fr>,
        ledger_key: [u8; 32],
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
        if section_count > MAX_SECTIONS as u64 {
            return Err(UnifiedError::SectionCountOutOfRange(section_count));
        }
        for (i, &b) in merkle_indices.iter().enumerate() {
            if b > 1 {
                return Err(UnifiedError::NonBinaryMerkleIndex(i, b));
            }
        }
        Ok(Self {
            canonical_hash,
            merkle_root,
            ledger_root,
            tree_size,
            document_sections,
            section_count,
            section_lengths,
            section_hashes,
            merkle_path,
            merkle_indices,
            leaf_index,
            ledger_path_elements,
            ledger_key,
        })
    }

    /// Derive ledger SMT `pathIndices` from `ledger_key` exactly as the unified
    /// circuit does: key bytes are decomposed MSB-first, then reversed so the
    /// leaf level consumes bit 255 and the root level consumes bit 0.
    pub fn ledger_path_indices(&self) -> Vec<u8> {
        let mut indices = vec![0u8; SMT_DEPTH];
        for (byte_idx, &byte) in self.ledger_key.iter().enumerate() {
            for bit_in_byte in 0..8usize {
                let bit = (byte >> (7 - bit_in_byte)) & 1;
                let k = byte_idx * 8 + bit_in_byte;
                indices[255 - k] = bit;
            }
        }
        indices
    }

    /// Compute the public `ledgerKeyHash = Poseidon(key_lo, key_hi)` commitment,
    /// matching the in-circuit Σ-loop copied from `non_existence.circom`.
    pub fn ledger_key_hash(&self) -> Result<Fr, PoseidonError> {
        let lo = pack_le_bytes(&self.ledger_key[..16]);
        let hi = pack_le_bytes(&self.ledger_key[16..]);
        hash2(lo, hi)
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
    ///      ledger_path_indices()) == ledger_root` (mirrors
    ///      `ledgerSMTProof.leaf <== merkleRoot` with path bits derived
    ///      from `ledgerKey`).
    ///
    /// **Not checked here:** the structured commitment chain that produces
    /// `canonicalHash` from `sectionHashes[]`/`sectionLengths[]`. It surfaces
    /// as a clean circuit-side failure; this pre-check catches the common path
    /// and section-hash shape errors before witness generation.
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
            NODE_DOMAIN, // node domain — matches existence / non_existence circuits.
        )?;
        if computed_merkle != self.merkle_root {
            return Err(UnifiedError::MerkleRootMismatch {
                recomputed: fr_to_decimal(&computed_merkle),
                expected: fr_to_decimal(&self.merkle_root),
            });
        }

        // 2. SMT inclusion: merkleRoot → ledgerRoot via ledgerPathElements and ledgerKey.
        let ledger_path_indices = self.ledger_path_indices();
        let computed_ledger = compute_merkle_root(
            self.merkle_root,
            &self.ledger_path_elements,
            &ledger_path_indices,
            NODE_DOMAIN,
        )?;
        if computed_ledger != self.ledger_root {
            return Err(UnifiedError::LedgerRootMismatch {
                recomputed: fr_to_decimal(&computed_ledger),
                expected: fr_to_decimal(&self.ledger_root),
            });
        }

        Ok(())
    }

    /// Public signals in the order the circuit's `component main {public
    /// [...]}` declares them: `[canonicalHash, merkleRoot, ledgerRoot,
    /// treeSize, ledgerKeyHash]`. The unified circuit has no `signal output`, so no
    /// synthetic public signals precede these.
    ///
    /// Earlier revisions also appended `checkpointTimestamp` and
    /// `authorityPubKeyHash` (returning a 6-vec) on the assumption the
    /// circuit would grow an in-circuit `EdDSAPoseidonVerifier`. That
    /// template was never added; appending those values silently produced
    /// a witness vector with the wrong arity for the live circuit and any
    /// caller threading it into `verify_with_processed_vk` would have been
    /// rejected. Authority context is deliberately absent from this circuit
    /// witness and is verified separately by the federation layer. Audit C-2.
    pub fn public_signals(&self) -> Vec<Fr> {
        vec![
            self.canonical_hash,
            self.merkle_root,
            self.ledger_root,
            Fr::from(self.tree_size),
            self.ledger_key_hash()
                .expect("Poseidon(2) cannot fail for in-field inputs"),
        ]
    }

    /// (name, Vec<BigInt>) pairs for ark-circom's CircomBuilder. Only the
    /// signals the circuit actually declares are pushed — the five
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
        let ledger_key: Vec<BigInt> = self
            .ledger_key
            .iter()
            .map(|&b| BigInt::from(b as u64))
            .collect();
        let ledger_key_hash = self
            .ledger_key_hash()
            .expect("Poseidon(2) cannot fail for in-field inputs");

        vec![
            // Public inputs (the five `component main {public [...]}` entries).
            (
                "canonicalHash".into(),
                vec![fr_to_bigint(&self.canonical_hash)],
            ),
            ("merkleRoot".into(), vec![fr_to_bigint(&self.merkle_root)]),
            ("ledgerRoot".into(), vec![fr_to_bigint(&self.ledger_root)]),
            ("treeSize".into(), vec![BigInt::from(self.tree_size)]),
            ("ledgerKeyHash".into(), vec![fr_to_bigint(&ledger_key_hash)]),
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
            ("ledgerKey".into(), ledger_key),
        ]
    }
}

/// Pack up to 16 little-endian bytes into a single Fr. Mirrors the Circom
/// Σ-loop copied from `non_existence.circom`.
fn pack_le_bytes(bytes: &[u8]) -> Fr {
    debug_assert!(bytes.len() <= 16);
    let mut acc = Fr::zero();
    let mut weight = Fr::from(1u64);
    let base = Fr::from(256u64);
    for &b in bytes {
        acc += weight * Fr::from(b as u64);
        weight *= base;
    }
    acc
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
    /// a zero-padded SMT path under that merkle_root.
    fn consistent_witness(canonical: Fr) -> UnifiedWitness {
        let merkle_path = vec![Fr::zero(); MERKLE_DEPTH];
        let merkle_indices = vec![0u8; MERKLE_DEPTH];
        let merkle_root =
            compute_merkle_root(canonical, &merkle_path, &merkle_indices, NODE_DOMAIN).unwrap();
        let ledger_path = vec![Fr::zero(); SMT_DEPTH];
        let ledger_key = [0u8; 32];
        let ledger_indices = vec![0u8; SMT_DEPTH];
        let ledger_root =
            compute_merkle_root(merkle_root, &ledger_path, &ledger_indices, NODE_DOMAIN).unwrap();

        UnifiedWitness {
            canonical_hash: canonical,
            merkle_root,
            ledger_root,
            tree_size: 1,
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
            ledger_key,
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
    fn ledger_key_derivation_matches_circom_js_reference() {
        // Cross-check against proofs/test_inputs/generate_unified_inputs.js
        // for ledgerKey = 00 01 ... 1f. This pins both the little-endian
        // lo/hi field packing and the MSB-first, reversed SMT path bit order.
        let mut w = consistent_witness(Fr::from(42u64));
        for (i, byte) in w.ledger_key.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let expected_hash =
            "16938703040793104250568799127694112507129851377230786879980445624124228829629"
                .parse::<Fr>()
                .expect("valid Fr");
        assert_eq!(w.ledger_key_hash().unwrap(), expected_hash);

        let indices = w.ledger_path_indices();
        assert_eq!(
            &indices[..16],
            &[1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0]
        );
        assert_eq!(
            &indices[240..],
            &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(indices.iter().map(|bit| u64::from(*bit)).sum::<u64>(), 80);
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
