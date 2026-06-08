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
//!   originalLeaves[MAX_LEAVES], revealMask[MAX_LEAVES],
//!   pathElements[MAX_LEAVES][REDACTION_DEPTH],
//!   pathIndices[MAX_LEAVES][REDACTION_DEPTH], recipientId
//!
//! All leaves (revealed and redacted) are Merkle-proven against
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
/// `REDACTION_MAX_LEAVES = 1024`, `REDACTION_MERKLE_DEPTH = 10` (ADR-0025 —
/// PDF object-level commitment; one leaf per indirect object instead of 16
/// raw-byte chunks). The circuit template is unchanged — only these
/// dimensions and the witness leaf construction changed. `2^REDACTION_DEPTH`
/// MUST equal `MAX_LEAVES`.
pub const MAX_LEAVES: usize = 1024;
pub const REDACTION_DEPTH: usize = 10;

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
    #[error(
        "issuer EdDSA-Poseidon signature does not verify against the nullifier digest \
         (audit M-2): the in-circuit EdDSAPoseidonVerifier would reject this witness"
    )]
    IssuerSigInvalid,
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
    /// Public input (audit M-2): trusted-issuer BJJ pubkey `(Ax, Ay)` the
    /// in-circuit EdDSAPoseidonVerifier checks the signature against.
    pub issuer_ax: Fr,
    pub issuer_ay: Fr,

    // ---- Private inputs ----
    pub original_leaves: Vec<Fr>,    // len == MAX_LEAVES
    pub reveal_mask: Vec<bool>,      // len == MAX_LEAVES
    pub path_elements: Vec<Vec<Fr>>, // [MAX_LEAVES][REDACTION_DEPTH]
    pub path_indices: Vec<Vec<u8>>,  // [MAX_LEAVES][REDACTION_DEPTH]
    pub recipient_id: Fr,
    /// Audit M-2: issuer's EdDSA-Poseidon signature over the nullifier
    /// digest (= Poseidon(originalRoot, redactedCommitment, recipientId)).
    /// Without this, a recipient who holds the cleartext can re-prove
    /// the same redaction for any other recipient — see audit notes.
    pub issuer_sig: crate::zk::witness::baby_jubjub::BabyJubJubSignature,
}

impl RedactionWitness {
    /// Build a redaction witness from the raw inputs. Performs structural
    /// validation only — the Merkle paths are checked separately by
    /// [`Self::verify_all_paths`] (which is also called by the prover as a
    /// fast pre-check before invoking ark-circom).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        original_root: Fr,
        original_leaves: Vec<Fr>,
        reveal_mask: Vec<bool>,
        path_elements: Vec<Vec<Fr>>,
        path_indices: Vec<Vec<u8>>,
        recipient_id: Fr,
        issuer_pubkey: crate::zk::witness::baby_jubjub::BabyJubJubPubKey,
        issuer_sig: crate::zk::witness::baby_jubjub::BabyJubJubSignature,
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

        // Audit M-2: native pre-check the issuer signature so a bad
        // witness fails in microseconds rather than burning a WASM slot
        // for the full witness-construction time.
        if !crate::zk::witness::baby_jubjub::verify_signature(
            &issuer_pubkey,
            &issuer_sig,
            nullifier,
        ) {
            return Err(RedactionError::IssuerSigInvalid);
        }

        Ok(Self {
            nullifier,
            original_root,
            redacted_commitment,
            revealed_count,
            issuer_ax: issuer_pubkey.x,
            issuer_ay: issuer_pubkey.y,
            original_leaves,
            reveal_mask,
            path_elements,
            path_indices,
            recipient_id,
            issuer_sig,
        })
    }

    /// Test-only helper that builds + signs the witness in one shot from a
    /// 32-byte issuer private key. Mirrors the prior `new` signature so
    /// the existing unit tests don't have to thread issuer material
    /// through every fixture. Audit M-2.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_test(
        original_root: Fr,
        original_leaves: Vec<Fr>,
        reveal_mask: Vec<bool>,
        path_elements: Vec<Vec<Fr>>,
        path_indices: Vec<Vec<u8>>,
        recipient_id: Fr,
    ) -> Result<Self, RedactionError> {
        let priv_key = [0x33u8; 32];
        let pubkey = crate::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(&priv_key)
            .expect("test pubkey derive");
        // Mirror `Self::new`'s length validation up front: the nullifier
        // signature is derived below from `redaction_commitment`, which
        // requires `original_leaves.len() == reveal_mask.len()`. Without
        // these guards a deliberately-malformed fixture would trip the
        // internal `debug_assert_eq!` in `redaction_commitment` instead of
        // surfacing the same typed error `Self::new` returns.
        if original_leaves.len() != MAX_LEAVES {
            return Err(RedactionError::WrongLeaves(original_leaves.len()));
        }
        if reveal_mask.len() != MAX_LEAVES {
            return Err(RedactionError::WrongMask(reveal_mask.len()));
        }
        // We need the nullifier (= signed message) before constructing —
        // derive it manually so the sign call uses the right digest.
        let revealed_count = reveal_mask.iter().filter(|&&b| b).count() as u64;
        let redacted_commitment =
            redaction_commitment(revealed_count, &original_leaves, &reveal_mask)?;
        let nullifier = hash_n(&[original_root, redacted_commitment, recipient_id])?;
        let sig = crate::zk::witness::baby_jubjub::sign(&priv_key, nullifier).expect("test sign");
        Self::new(
            original_root,
            original_leaves,
            reveal_mask,
            path_elements,
            path_indices,
            recipient_id,
            pubkey,
            sig,
        )
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
    /// public inputs in source order. Audit M-2 added `issuerAx`/`issuerAy`
    /// as the trailing declared-public inputs.
    pub fn public_signals(&self) -> Vec<Fr> {
        vec![
            self.nullifier,
            self.original_root,
            self.redacted_commitment,
            Fr::from(self.revealed_count),
            self.issuer_ax,
            self.issuer_ay,
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
        // ADR-0025 flat fold: the circuit recomputes originalRoot from ALL
        // leaves directly, so `pathElements`/`pathIndices` are no longer circuit
        // signals and MUST NOT be emitted (ark-circom rejects unknown inputs).
        // The struct still carries the paths for `verify_all_paths` (a host-side
        // pre-check) and the deprecated chunk caller.
        let recipient_id = vec![fr_to_bigint(&self.recipient_id)];

        vec![
            ("originalRoot".into(), original_root),
            ("redactedCommitment".into(), redacted_commitment),
            ("revealedCount".into(), revealed_count),
            ("issuerAx".into(), vec![fr_to_bigint(&self.issuer_ax)]),
            ("issuerAy".into(), vec![fr_to_bigint(&self.issuer_ay)]),
            ("originalLeaves".into(), original_leaves),
            ("revealMask".into(), reveal_mask),
            ("recipientId".into(), recipient_id),
            (
                "issuerSigR8x".into(),
                vec![fr_to_bigint(&self.issuer_sig.r8x)],
            ),
            (
                "issuerSigR8y".into(),
                vec![fr_to_bigint(&self.issuer_sig.r8y)],
            ),
            ("issuerSigS".into(), vec![fr_to_bigint(&self.issuer_sig.s)]),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    // Helper: build the LSB-first binary expansion of `i` to length DEPTH.
    // This is what the index-binding check requires.
    fn lsb_bits(i: usize, len: usize) -> Vec<u8> {
        (0..len).map(|b| ((i >> b) & 1) as u8).collect()
    }

    // Build a 4-deep all-zero sibling path for one leaf. Used only for tests
    // that don't actually call verify_all_paths (the structural-validation
    // path) so the bogus siblings never get checked.
    fn zero_inner_path() -> Vec<Fr> {
        vec![Fr::zero(); REDACTION_DEPTH]
    }

    fn zero_path_matrix() -> Vec<Vec<Fr>> {
        (0..MAX_LEAVES).map(|_| zero_inner_path()).collect()
    }

    fn binding_indices_matrix() -> Vec<Vec<u8>> {
        (0..MAX_LEAVES)
            .map(|i| lsb_bits(i, REDACTION_DEPTH))
            .collect()
    }

    // Build a "uniform" Merkle tree where every leaf equals `leaf`. Returns
    // (root, single_sibling_path). Because every node at level k is the same
    // value, the sibling at level k equals the current node at level k —
    // which means the merkle-step is order-independent and the same path
    // applies to every leaf position.
    fn uniform_tree(leaf: Fr) -> (Fr, Vec<Fr>) {
        use crate::zk::poseidon::merkle_node;
        let mut current = leaf;
        let mut siblings = Vec::with_capacity(REDACTION_DEPTH);
        for _ in 0..REDACTION_DEPTH {
            siblings.push(current);
            current = merkle_node(current, current, 0, 1).expect("merkle_node");
        }
        (current, siblings)
    }

    #[test]
    fn new_rejects_wrong_leaves_length() {
        let r = RedactionWitness::new_test(
            Fr::zero(),
            vec![Fr::zero(); MAX_LEAVES - 1],
            vec![false; MAX_LEAVES],
            zero_path_matrix(),
            binding_indices_matrix(),
            Fr::zero(),
        );
        assert!(matches!(r, Err(RedactionError::WrongLeaves(n)) if n == MAX_LEAVES - 1));
    }

    #[test]
    fn new_rejects_wrong_mask_length() {
        let r = RedactionWitness::new_test(
            Fr::zero(),
            vec![Fr::zero(); MAX_LEAVES],
            vec![false; MAX_LEAVES - 1],
            zero_path_matrix(),
            binding_indices_matrix(),
            Fr::zero(),
        );
        assert!(matches!(r, Err(RedactionError::WrongMask(n)) if n == MAX_LEAVES - 1));
    }

    #[test]
    fn new_rejects_wrong_path_outer_length() {
        let r = RedactionWitness::new_test(
            Fr::zero(),
            vec![Fr::zero(); MAX_LEAVES],
            vec![false; MAX_LEAVES],
            vec![zero_inner_path(); MAX_LEAVES - 1],
            binding_indices_matrix(),
            Fr::zero(),
        );
        assert!(matches!(r, Err(RedactionError::WrongPathOuter(n)) if n == MAX_LEAVES - 1));
    }

    #[test]
    fn new_rejects_wrong_path_inner_length() {
        let mut paths = zero_path_matrix();
        paths[3] = vec![Fr::zero(); REDACTION_DEPTH - 1];
        let r = RedactionWitness::new_test(
            Fr::zero(),
            vec![Fr::zero(); MAX_LEAVES],
            vec![false; MAX_LEAVES],
            paths,
            binding_indices_matrix(),
            Fr::zero(),
        );
        assert!(matches!(
            r,
            Err(RedactionError::WrongPathInner(3, n)) if n == REDACTION_DEPTH - 1
        ));
    }

    #[test]
    fn new_rejects_non_binary_index() {
        let mut indices = binding_indices_matrix();
        indices[2][1] = 5;
        let r = RedactionWitness::new_test(
            Fr::zero(),
            vec![Fr::zero(); MAX_LEAVES],
            vec![false; MAX_LEAVES],
            zero_path_matrix(),
            indices,
            Fr::zero(),
        );
        assert!(matches!(
            r,
            Err(RedactionError::NonBinaryIndex {
                leaf: 2,
                level: 1,
                got: 5
            })
        ));
    }

    #[test]
    fn new_rejects_index_binding_mismatch() {
        // Swap leaf 0 and leaf 1's indices so neither reconstructs its position.
        let mut indices = binding_indices_matrix();
        indices.swap(0, 1);
        let r = RedactionWitness::new_test(
            Fr::zero(),
            vec![Fr::zero(); MAX_LEAVES],
            vec![false; MAX_LEAVES],
            zero_path_matrix(),
            indices,
            Fr::zero(),
        );
        // Leaf 0 now has indices for position 1, which fails first.
        assert!(matches!(r, Err(RedactionError::IndexBindingMismatch(0))));
    }

    #[test]
    fn new_computes_revealed_count_as_popcount_of_mask() {
        // 5 trues set across the mask. (Root validity isn't part of `new`;
        // it's checked separately by verify_all_paths, so the bogus zero
        // sibling matrix doesn't matter here.)
        let mut mask = vec![false; MAX_LEAVES];
        for i in [0, 3, 7, 11, 15] {
            mask[i] = true;
        }
        let w = RedactionWitness::new_test(
            Fr::zero(),
            vec![Fr::from(1u64); MAX_LEAVES],
            mask,
            zero_path_matrix(),
            binding_indices_matrix(),
            Fr::from(99u64),
        )
        .unwrap();
        assert_eq!(w.revealed_count, 5);
    }

    #[test]
    fn new_computes_nullifier_deterministically() {
        // Same (root, commitment, recipient) → same nullifier across constructions.
        // Note: `new` doesn't verify paths, so the bogus zero sibling matrix is fine.
        let leaves = vec![Fr::from(2u64); MAX_LEAVES];
        let mask = vec![false; MAX_LEAVES];
        let w1 = RedactionWitness::new_test(
            Fr::from(123u64),
            leaves.clone(),
            mask.clone(),
            zero_path_matrix(),
            binding_indices_matrix(),
            Fr::from(7u64),
        )
        .unwrap();
        let w2 = RedactionWitness::new_test(
            Fr::from(123u64),
            leaves,
            mask,
            zero_path_matrix(),
            binding_indices_matrix(),
            Fr::from(7u64),
        )
        .unwrap();
        assert_eq!(w1.nullifier, w2.nullifier);
    }

    #[test]
    fn new_nullifier_depends_on_recipient_id() {
        // Same inputs except recipient_id → different nullifier (the whole point).
        let leaves = vec![Fr::from(3u64); MAX_LEAVES];
        let mask = vec![false; MAX_LEAVES];
        let w_alice = RedactionWitness::new_test(
            Fr::from(456u64),
            leaves.clone(),
            mask.clone(),
            zero_path_matrix(),
            binding_indices_matrix(),
            Fr::from(1u64),
        )
        .unwrap();
        let w_bob = RedactionWitness::new_test(
            Fr::from(456u64),
            leaves,
            mask,
            zero_path_matrix(),
            binding_indices_matrix(),
            Fr::from(2u64),
        )
        .unwrap();
        assert_ne!(w_alice.nullifier, w_bob.nullifier);
    }

    #[test]
    fn verify_all_paths_succeeds_when_root_matches() {
        // Build a uniform Merkle tree (every leaf == 7). The sibling at each
        // level equals the current node, so the merkle-step is order-
        // independent — the same single sibling path validates every leaf
        // position regardless of its LSB-binding index bits.
        let leaf = Fr::from(7u64);
        let (root, siblings) = uniform_tree(leaf);
        let path_elements: Vec<Vec<Fr>> = (0..MAX_LEAVES).map(|_| siblings.clone()).collect();
        let w = RedactionWitness::new_test(
            root,
            vec![leaf; MAX_LEAVES],
            vec![false; MAX_LEAVES],
            path_elements,
            binding_indices_matrix(),
            Fr::zero(),
        )
        .unwrap();
        assert!(w.verify_all_paths().is_ok());
    }

    #[test]
    fn verify_all_paths_fails_on_root_mismatch() {
        let leaf = Fr::from(7u64);
        let (_correct_root, siblings) = uniform_tree(leaf);
        let path_elements: Vec<Vec<Fr>> = (0..MAX_LEAVES).map(|_| siblings.clone()).collect();
        let w = RedactionWitness::new_test(
            Fr::from(0xbadu64), // wrong root
            vec![leaf; MAX_LEAVES],
            vec![false; MAX_LEAVES],
            path_elements,
            binding_indices_matrix(),
            Fr::zero(),
        )
        .unwrap();
        assert!(matches!(
            w.verify_all_paths(),
            Err(RedactionError::LeafRootMismatch(0))
        ));
    }

    #[test]
    fn public_signals_order_is_nullifier_root_commitment_count() {
        let w = RedactionWitness::new_test(
            Fr::from(789u64),
            vec![Fr::from(8u64); MAX_LEAVES],
            vec![false; MAX_LEAVES],
            zero_path_matrix(),
            binding_indices_matrix(),
            Fr::from(42u64),
        )
        .unwrap();
        let s = w.public_signals();
        // Audit M-2 made the issuer pubkey (Ax, Ay) public, so the signal
        // vector matches the circuit's `component main` ordering:
        // [nullifier output, originalRoot, redactedCommitment, revealedCount,
        //  issuerAx, issuerAy].
        assert_eq!(s.len(), 6);
        assert_eq!(s[0], w.nullifier);
        assert_eq!(s[1], w.original_root);
        assert_eq!(s[2], w.redacted_commitment);
        assert_eq!(s[3], Fr::from(w.revealed_count));
        assert_eq!(s[4], w.issuer_ax);
        assert_eq!(s[5], w.issuer_ay);
    }

    #[test]
    fn circom_inputs_match_flat_fold_circuit_signals() {
        // ADR-0025 flat fold: the circuit recomputes the root from all leaves,
        // so pathElements/pathIndices are NOT circuit inputs and must not be
        // emitted (ark-circom rejects unknown inputs).
        let w = RedactionWitness::new_test(
            Fr::from(1u64),
            vec![Fr::from(1u64); MAX_LEAVES],
            vec![false; MAX_LEAVES],
            zero_path_matrix(),
            binding_indices_matrix(),
            Fr::zero(),
        )
        .unwrap();
        let inputs = w.circom_inputs();
        let by_name: std::collections::HashMap<&str, usize> =
            inputs.iter().map(|(n, v)| (n.as_str(), v.len())).collect();
        assert!(
            !by_name.contains_key("pathElements"),
            "flat fold takes no pathElements"
        );
        assert!(
            !by_name.contains_key("pathIndices"),
            "flat fold takes no pathIndices"
        );
        assert_eq!(by_name["originalLeaves"], MAX_LEAVES);
        assert_eq!(by_name["revealMask"], MAX_LEAVES);
        assert_eq!(by_name["originalRoot"], 1);
        assert_eq!(by_name["redactedCommitment"], 1);
        assert_eq!(by_name["revealedCount"], 1);
        assert_eq!(by_name["recipientId"], 1);
        assert_eq!(by_name["issuerAx"], 1);
        assert_eq!(by_name["issuerAy"], 1);
        assert_eq!(by_name["issuerSigS"], 1);
    }

    // ── L-18: circuit↔Rust parity, artifact-independent ───────────────────
    //
    // The full prove↔verify roundtrip lives in
    // `tests/zk_prove_redaction.rs` but is skipped when WASM/r1cs/zkey
    // artifacts aren't on disk (i.e. on every fresh CI run that hasn't
    // executed `bash proofs/setup_circuits.sh`). The tests below lock the
    // Rust-side computations of `redacted_commitment` and `nullifier`
    // against hand-traced reference values so divergence at the witness
    // layer surfaces in `cargo test` without needing any circuit
    // artifacts. If a future refactor changes the commitment chain
    // ordering, the domain tag, or the nullifier digest shape, these
    // tests fail before anyone tries to generate a proof against the
    // new shape.

    /// Recompute the chain that `redaction_commitment` walks, by hand,
    /// in the same order the circuit performs it: start with
    /// `Fr::from(revealed_count)`, then for each leaf accumulate
    /// `domain_node(3, acc, masked_leaf)`. If the Rust helper and the
    /// circuit ever disagree here, this is the first thing to break.
    fn hand_redaction_commitment(revealed_count: u64, leaves: &[Fr], mask: &[bool]) -> Fr {
        use crate::zk::poseidon::domain_node;
        assert_eq!(leaves.len(), mask.len());
        let mut acc = Fr::from(revealed_count);
        for (leaf, &revealed) in leaves.iter().zip(mask.iter()) {
            let val = if revealed { *leaf } else { Fr::from(0u64) };
            acc = domain_node(3, acc, val).expect("domain_node");
        }
        acc
    }

    #[test]
    fn rust_redacted_commitment_matches_hand_traced_chain() {
        let leaves: Vec<Fr> = (1..=MAX_LEAVES as u64).map(Fr::from).collect();
        let mask: Vec<bool> = (0..MAX_LEAVES).map(|i| i % 2 == 0).collect();
        let revealed_count = mask.iter().filter(|&&b| b).count() as u64;
        let got =
            crate::zk::poseidon::redaction_commitment(revealed_count, &leaves, &mask).unwrap();
        let want = hand_redaction_commitment(revealed_count, &leaves, &mask);
        assert_eq!(got, want);
    }

    #[test]
    fn nullifier_is_poseidon3_of_root_commit_recipient() {
        // The circuit computes nullifier = Poseidon(3)(originalRoot,
        // redactedCommitment, recipientId). Witness::new exposes
        // `self.nullifier`; verify it agrees with a direct hash_n(3) call.
        use crate::zk::poseidon::hash_n;
        let leaves: Vec<Fr> = (1..=MAX_LEAVES as u64).map(Fr::from).collect();
        let mask: Vec<bool> = vec![true; MAX_LEAVES];
        let recipient_id = Fr::from(0xC0FFEEu64);
        // Use any consistent root — the test doesn't run verify_all_paths,
        // just exercises the digest derivation.
        let original_root = Fr::from(0x12345678u64);
        let revealed_count = MAX_LEAVES as u64;
        let commit =
            crate::zk::poseidon::redaction_commitment(revealed_count, &leaves, &mask).unwrap();
        let expected_nullifier = hash_n(&[original_root, commit, recipient_id]).unwrap();

        // Build a witness through new_test (test-helper that synthesises
        // a signed envelope), and confirm its nullifier equals the
        // independently-computed digest. Use `lsb_bits` for valid path
        // indices but zero siblings — verify_all_paths is not called.
        let paths = zero_path_matrix();
        let indices = binding_indices_matrix();
        let w =
            RedactionWitness::new_test(original_root, leaves, mask, paths, indices, recipient_id)
                .expect("witness");
        assert_eq!(w.nullifier, expected_nullifier);
    }

    #[test]
    fn public_signals_order_locked_to_circuit() {
        // Audit M-2 + L-18: the circom file declares
        //   component main { public [originalRoot, redactedCommitment,
        //                            revealedCount, issuerAx, issuerAy] }
        // and the output `nullifier` precedes them. The witness's
        // public_signals() MUST return them in exactly this order;
        // ark-circom's `get_public_inputs()` returns the same order, so
        // any drift here would mean `verify_with_processed_vk` rejects
        // every legitimate proof. Lock the layout.
        let leaves: Vec<Fr> = (1..=MAX_LEAVES as u64).map(Fr::from).collect();
        let mask: Vec<bool> = vec![true; MAX_LEAVES];
        let w = RedactionWitness::new_test(
            Fr::from(7u64),
            leaves,
            mask,
            zero_path_matrix(),
            binding_indices_matrix(),
            Fr::from(11u64),
        )
        .unwrap();
        let s = w.public_signals();
        assert_eq!(s.len(), 6);
        assert_eq!(s[0], w.nullifier);
        assert_eq!(s[1], w.original_root);
        assert_eq!(s[2], w.redacted_commitment);
        assert_eq!(s[3], Fr::from(w.revealed_count));
        assert_eq!(s[4], w.issuer_ax);
        assert_eq!(s[5], w.issuer_ay);
    }
}
