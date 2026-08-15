//! Witness for the `federation_quorum` circuit.
//!
//! Proves "≥ M of these N pinned federation signers co-signed `msg`" without
//! revealing WHICH subset signed. See `proofs/circuits/federation_quorum.circom`
//! for the circuit and [`crate::quorum`] for the off-circuit (explicit
//! signature-set) verifier, which is the authoritative path today — the ZK
//! attestation is an optional privacy layer that becomes provable once the
//! circuit's trusted-setup ceremony has been run (the vkey is gitignored /
//! placeholder until then, exactly like the unified circuit).
//!
//! Public signal vector (matching `component main {public [msg, signerAx,
//! signerAy, threshold]}`, arrays expanded in declaration order, no output
//! signals):
//!
//! ```text
//! [ msg, signerAx[0..N], signerAy[0..N], threshold ]   // length 2N + 2
//! ```
//!
//! Slot binding & padding
//! ----------------------
//! Slot `i` is bound to the public pinned pubkey `(signerAx[i], signerAy[i])`.
//! When the real signer set is smaller than `N`, the trailing slots repeat the
//! last real signer's pubkey (deterministic, so the verifier reconstructs the
//! same public vector) with `enabled = 0`. Disabled slots carry a real,
//! on-curve `(R8, S)` borrowed from one of the enabled signatures so the
//! circuit's unconditional scalar-multiplications stay satisfiable — only the
//! final EdDSA equality is gated by `enabled`, so the borrowed signature is
//! never actually checked there.
//!
//! Repeating the last real pubkey is safe against a *malicious* prover only
//! because the circuit forbids enabling any slot whose pubkey duplicates an
//! earlier slot's (audit OLY-M5). Before that constraint existed, a prover
//! holding one signature could enable every padding slot repeating that signer
//! and inflate the counted quorum from a single signature. The distinctness
//! and on-curve guards in this module mirror the circuit for fast failure;
//! they are not what makes the proof sound.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigInt;
use thiserror::Error;

use crate::quorum::{quorum_cosign_message, CollectedSignature, QuorumSigner, FEDERATION_QUORUM_N};
use crate::zk::proof::parse_fr;
use crate::zk::witness::baby_jubjub::{self, BabyJubJubPubKey, BabyJubJubSignature};

const N: usize = FEDERATION_QUORUM_N;

#[derive(Debug, Error)]
pub enum QuorumWitnessError {
    #[error("pinned signer set is empty")]
    EmptySignerSet,
    #[error("pinned signer set has {0} members, exceeds circuit capacity N={N}")]
    TooManySigners(usize),
    #[error("threshold {0} exceeds pinned signer set size {1}")]
    ThresholdTooHigh(u64, usize),
    #[error("threshold must be >= 1 (a zero threshold makes the quorum trivially satisfiable)")]
    ThresholdZero,
    #[error(
        "pinned signer {0} is a duplicate; the pinned set must be distinct so one signature \
         cannot be counted for multiple circuit slots"
    )]
    DuplicateSigner(usize),
    #[error("pinned signer {0} has a non-canonical / off-field coordinate")]
    BadSigner(usize),
    #[error(
        "pinned signer {0} is not a Baby Jubjub point in the prime-order subgroup (off-curve, \
         the identity, or a cofactor-coset point)"
    )]
    OffCurveSigner(usize),
    #[error(
        "threshold {0} is outside the circuit's 8-bit comparator range; GreaterEqThan(8) is \
         only sound for operands < 256"
    )]
    ThresholdOutOfRange(u64),
    #[error("a collected signature for signer {0} has a non-canonical / off-field field")]
    BadSignature(usize),
    #[error(
        "only {valid} of the pinned signers supplied a valid signature; need >= {threshold} to \
         build a satisfying quorum proof"
    )]
    InsufficientValidSignatures { valid: usize, threshold: u64 },
}

/// Witness for the M-of-N `federation_quorum` circuit.
#[derive(Debug, Clone)]
pub struct QuorumProofWitness {
    pub msg: Fr,
    pub signer_ax: [Fr; N],
    pub signer_ay: [Fr; N],
    pub threshold: u64,
    pub enabled: [u8; N],
    pub r8x: [Fr; N],
    pub r8y: [Fr; N],
    pub s: [Fr; N],
}

fn fr_to_bigint(f: &Fr) -> BigInt {
    let bytes_be = f.into_bigint().to_bytes_be();
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes_be)
}

/// Parse a [`QuorumSigner`] into a [`BabyJubJubPubKey`], rejecting non-canonical
/// decimals via the strict `parse_fr`.
fn parse_signer(s: &QuorumSigner) -> Option<BabyJubJubPubKey> {
    Some(BabyJubJubPubKey {
        x: parse_fr(&s.x).ok()?,
        y: parse_fr(&s.y).ok()?,
    })
}

/// Reject a pinned pubkey that is not a Baby Jubjub point in the prime-order
/// subgroup.
///
/// Native mirror of the circuit's per-slot, ungated `BabyCheck` (audit
/// OLY-L12) plus the not-small-order check circomlib's `EdDSAPoseidonVerifier`
/// applies to enabled slots. The circuit is the enforcement; this is the fast
/// path that fails in microseconds instead of inside WASM witness generation.
fn validate_pinned(i: usize, pk: &BabyJubJubPubKey) -> Result<(), QuorumWitnessError> {
    baby_jubjub::validate_pubkey_subgroup(pk).map_err(|_| QuorumWitnessError::OffCurveSigner(i))
}

/// Reconstruct the public-signal vector a verifier must compare against, from a
/// credential's pinned signer set, threshold, and `commit_id` — WITHOUT any
/// private signature material. The padding rule matches [`QuorumProofWitness`].
///
/// Returns `Err` if the pinned set is empty, larger than `N`, or has a
/// malformed coordinate.
pub fn expected_public_signals(
    commit_id: &[u8; 32],
    pinned: &[QuorumSigner],
    threshold: u64,
) -> Result<Vec<Fr>, QuorumWitnessError> {
    if pinned.is_empty() {
        return Err(QuorumWitnessError::EmptySignerSet);
    }
    if pinned.len() > N {
        return Err(QuorumWitnessError::TooManySigners(pinned.len()));
    }
    // Mirror the circuit's threshold range constraint exactly: it rejects 0
    // (thresholdIsZero) and anything >= 256 (Num2Bits(8)). Reconstructing a
    // signal vector the circuit can never satisfy would only defer the
    // failure to proof verification with a less useful error.
    if threshold == 0 {
        return Err(QuorumWitnessError::ThresholdZero);
    }
    if threshold >= 256 {
        return Err(QuorumWitnessError::ThresholdOutOfRange(threshold));
    }
    // Parse the real pinned set once and enforce distinctness — the same
    // invariant the circuit's soundness relies on (see `from_quorum`). A
    // duplicate pinned pubkey would let one signature satisfy multiple slots,
    // so a credential whose stored signer set has a duplicate must fail
    // verification here rather than reconstruct a "valid-looking" signal vector.
    let parsed: Vec<BabyJubJubPubKey> = pinned
        .iter()
        .enumerate()
        .map(|(i, s)| parse_signer(s).ok_or(QuorumWitnessError::BadSigner(i)))
        .collect::<Result<_, _>>()?;
    let mut seen = std::collections::BTreeSet::new();
    for (i, pk) in parsed.iter().enumerate() {
        validate_pinned(i, pk)?;
        if !seen.insert((fr_to_bigint(&pk.x), fr_to_bigint(&pk.y))) {
            return Err(QuorumWitnessError::DuplicateSigner(i));
        }
    }
    let mut ax = [Fr::from(0u64); N];
    let mut ay = [Fr::from(0u64); N];
    let last = pinned.len() - 1;
    for i in 0..N {
        let src = if i < pinned.len() { i } else { last };
        ax[i] = parsed[src].x;
        ay[i] = parsed[src].y;
    }
    let msg = quorum_cosign_message(commit_id, threshold as usize, pinned);
    let mut signals = Vec::with_capacity(2 * N + 2);
    signals.push(msg);
    signals.extend_from_slice(&ax);
    signals.extend_from_slice(&ay);
    signals.push(Fr::from(threshold));
    Ok(signals)
}

impl QuorumProofWitness {
    /// Build a witness from a pinned signer set + the collected co-signatures.
    ///
    /// `enabled[i]` is set iff pinned signer `i` supplied a signature that
    /// verifies over `msg`. Trailing padding slots repeat the last real signer
    /// (`enabled = 0`). Disabled slots borrow `(R8, S)` from the first enabled
    /// slot so the circuit's scalar-mults stay satisfiable.
    pub fn from_quorum(
        commit_id: &[u8; 32],
        pinned: &[QuorumSigner],
        threshold: u64,
        sigs: &[CollectedSignature],
    ) -> Result<Self, QuorumWitnessError> {
        if pinned.is_empty() {
            return Err(QuorumWitnessError::EmptySignerSet);
        }
        if pinned.len() > N {
            return Err(QuorumWitnessError::TooManySigners(pinned.len()));
        }
        // A zero threshold would make `valid >= threshold` trivially true and,
        // with no enabled slots, fall through to `filler.expect(...)` below and
        // panic. Config clamps the default to >= 1, but this pub fn must reject
        // it rather than rely on the caller. (Checked before ThresholdTooHigh.)
        if threshold == 0 {
            return Err(QuorumWitnessError::ThresholdZero);
        }
        if threshold > pinned.len() as u64 {
            return Err(QuorumWitnessError::ThresholdTooHigh(
                threshold,
                pinned.len(),
            ));
        }

        let msg = quorum_cosign_message(commit_id, threshold as usize, pinned);

        // Index collected signatures by normalised signer identity.
        // For each pinned slot, find a matching, *verifying* signature.
        let parsed_pinned: Vec<BabyJubJubPubKey> = pinned
            .iter()
            .enumerate()
            .map(|(i, s)| parse_signer(s).ok_or(QuorumWitnessError::BadSigner(i)))
            .collect::<Result<_, _>>()?;

        // Distinctness: the circuit binds each enabled slot to its pinned
        // pubkey and counts enabled slots as distinct signers (soundness sketch
        // in federation_quorum.circom). A duplicate pinned pubkey would let one
        // signature satisfy multiple slots and inflate the count past the real
        // distinct-signer total. The host pins a deduplicated set
        // (crate::quorum::trusted_signer_set); enforce the invariant here too
        // rather than trust the caller of this pub fn.
        let mut seen = std::collections::BTreeSet::new();
        for (i, pk) in parsed_pinned.iter().enumerate() {
            validate_pinned(i, pk)?;
            if !seen.insert((fr_to_bigint(&pk.x), fr_to_bigint(&pk.y))) {
                return Err(QuorumWitnessError::DuplicateSigner(i));
            }
        }

        let mut enabled = [0u8; N];
        let mut r8x = [Fr::from(0u64); N];
        let mut r8y = [Fr::from(0u64); N];
        let mut s_arr = [Fr::from(0u64); N];
        let mut filler: Option<(Fr, Fr, Fr)> = None;

        for (i, pk) in parsed_pinned.iter().enumerate() {
            if let Some((sr8x, sr8y, ss)) = matching_signature(msg, pk, sigs) {
                enabled[i] = 1;
                r8x[i] = sr8x;
                r8y[i] = sr8y;
                s_arr[i] = ss;
                filler.get_or_insert((sr8x, sr8y, ss));
            }
        }

        let valid = enabled.iter().filter(|&&b| b == 1).count();
        if (valid as u64) < threshold {
            return Err(QuorumWitnessError::InsufficientValidSignatures { valid, threshold });
        }
        // `filler` is Some because valid >= threshold >= 1 (threshold==0 is
        // clamped to 1 by config; from_quorum callers pass >= 1).
        let (fr8x, fr8y, fs) = filler.expect("at least one enabled slot => filler set");

        // Public pubkey arrays (padded by repeating the last real signer), and
        // borrowed (R8, S) for every disabled slot.
        let mut signer_ax = [Fr::from(0u64); N];
        let mut signer_ay = [Fr::from(0u64); N];
        let last = pinned.len() - 1;
        for i in 0..N {
            let src = if i < pinned.len() { i } else { last };
            signer_ax[i] = parsed_pinned[src].x;
            signer_ay[i] = parsed_pinned[src].y;
            if enabled[i] == 0 {
                r8x[i] = fr8x;
                r8y[i] = fr8y;
                s_arr[i] = fs;
            }
        }

        Ok(Self {
            msg,
            signer_ax,
            signer_ay,
            threshold,
            enabled,
            r8x,
            r8y,
            s: s_arr,
        })
    }

    /// Native pre-check mirroring the circuit, constraint for constraint.
    ///
    /// Catches a malformed witness in microseconds before the (heavy) WASM
    /// witness generation runs. Each check below corresponds to one in
    /// `proofs/circuits/federation_quorum.circom`; keep the two in step.
    ///
    /// | check | circuit counterpart |
    /// |---|---|
    /// | `threshold` in `[1, 256)` | `Num2Bits(8)` + `thresholdIsZero.out === 0` |
    /// | every slot's pubkey on-curve, prime-order | ungated `BabyCheck` per slot (+ the enabled-gated small-order check inside `EdDSAPoseidonVerifier`) |
    /// | `enabled[i]` is 0 or 1 | `enabled[i] * (enabled[i] - 1) === 0` |
    /// | an enabled slot's signature verifies | `EdDSAPoseidonVerifier` gated by `enabled[i]` |
    /// | an enabled slot's key differs from every earlier slot's | `enabled[i] * samePoint[p] === 0` |
    /// | `count >= threshold` | `GreaterEqThan(8)` |
    ///
    /// This is defence in depth, **not** the enforcement: a malicious prover
    /// bypasses it by never calling the host witness builder. The circuit is
    /// what makes the statement sound.
    pub fn verify_inputs(&self) -> Result<(), QuorumWitnessError> {
        if self.threshold == 0 {
            return Err(QuorumWitnessError::ThresholdZero);
        }
        if self.threshold >= 256 {
            return Err(QuorumWitnessError::ThresholdOutOfRange(self.threshold));
        }

        // Ungated, exactly like the circuit's BabyCheck: a malformed key parked
        // on a disabled padding slot is rejected too.
        for i in 0..N {
            let pk = BabyJubJubPubKey {
                x: self.signer_ax[i],
                y: self.signer_ay[i],
            };
            validate_pinned(i, &pk)?;
        }

        let mut count = 0u64;
        for i in 0..N {
            match self.enabled[i] {
                0 => {}
                1 => {
                    // Slot distinctness: an enabled slot may not repeat any
                    // earlier slot's pubkey, or one signature would be counted
                    // more than once (audit OLY-M5). Duplicates on *disabled*
                    // slots stay legal — that is what the padding produces.
                    for j in 0..i {
                        if self.signer_ax[i] == self.signer_ax[j]
                            && self.signer_ay[i] == self.signer_ay[j]
                        {
                            return Err(QuorumWitnessError::DuplicateSigner(i));
                        }
                    }
                    let pk = BabyJubJubPubKey {
                        x: self.signer_ax[i],
                        y: self.signer_ay[i],
                    };
                    let sig = BabyJubJubSignature {
                        r8x: self.r8x[i],
                        r8y: self.r8y[i],
                        s: self.s[i],
                    };
                    if !baby_jubjub::verify_signature(&pk, &sig, self.msg) {
                        return Err(QuorumWitnessError::BadSignature(i));
                    }
                    count += 1;
                }
                _ => return Err(QuorumWitnessError::BadSignature(i)),
            }
        }
        if count < self.threshold {
            return Err(QuorumWitnessError::InsufficientValidSignatures {
                valid: count as usize,
                threshold: self.threshold,
            });
        }
        Ok(())
    }

    /// Public signals in circuit order: `[msg, signerAx[0..N], signerAy[0..N], threshold]`.
    pub fn public_signals(&self) -> Vec<Fr> {
        let mut v = Vec::with_capacity(2 * N + 2);
        v.push(self.msg);
        v.extend_from_slice(&self.signer_ax);
        v.extend_from_slice(&self.signer_ay);
        v.push(Fr::from(self.threshold));
        v
    }

    /// `(name, Vec<BigInt>)` inputs for ark-circom's `CircomBuilder`.
    pub fn circom_inputs(&self) -> Vec<(String, Vec<BigInt>)> {
        let to_vec = |arr: &[Fr; N]| -> Vec<BigInt> { arr.iter().map(fr_to_bigint).collect() };
        vec![
            ("msg".into(), vec![fr_to_bigint(&self.msg)]),
            ("signerAx".into(), to_vec(&self.signer_ax)),
            ("signerAy".into(), to_vec(&self.signer_ay)),
            ("threshold".into(), vec![BigInt::from(self.threshold)]),
            (
                "enabled".into(),
                self.enabled
                    .iter()
                    .map(|&b| BigInt::from(b as u64))
                    .collect(),
            ),
            ("R8x".into(), to_vec(&self.r8x)),
            ("R8y".into(), to_vec(&self.r8y)),
            ("S".into(), to_vec(&self.s)),
        ]
    }
}

/// Return the `(R8x, R8y, S)` of the first signature in `sigs` whose signer
/// matches `pk` AND verifies over `msg`. `None` if no such signature exists.
fn matching_signature(
    msg: Fr,
    pk: &BabyJubJubPubKey,
    sigs: &[CollectedSignature],
) -> Option<(Fr, Fr, Fr)> {
    for cs in sigs {
        let (Ok(sx), Ok(sy)) = (parse_fr(&cs.signer.x), parse_fr(&cs.signer.y)) else {
            continue;
        };
        if sx != pk.x || sy != pk.y {
            continue;
        }
        let (Ok(r8x), Ok(r8y), Ok(s)) = (parse_fr(&cs.r8x), parse_fr(&cs.r8y), parse_fr(&cs.s))
        else {
            continue;
        };
        let sig = BabyJubJubSignature { r8x, r8y, s };
        if baby_jubjub::verify_signature(pk, &sig, msg) {
            return Some((r8x, r8y, s));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quorum::fr_to_decimal;

    fn signer_and_key(priv_key: &[u8; 32]) -> (QuorumSigner, [u8; 32]) {
        let pk = baby_jubjub::BabyJubJubPubKey::from_private(priv_key).unwrap();
        (
            QuorumSigner {
                x: fr_to_decimal(&pk.x),
                y: fr_to_decimal(&pk.y),
            },
            *priv_key,
        )
    }

    fn cosign(
        priv_key: &[u8; 32],
        signer: &QuorumSigner,
        cid: &[u8; 32],
        threshold: u64,
        pinned: &[QuorumSigner],
    ) -> CollectedSignature {
        let msg = quorum_cosign_message(cid, threshold as usize, pinned);
        let sig = baby_jubjub::sign(priv_key, msg).unwrap();
        CollectedSignature {
            signer: signer.clone(),
            r8x: fr_to_decimal(&sig.r8x),
            r8y: fr_to_decimal(&sig.r8y),
            s: fr_to_decimal(&sig.s),
        }
    }

    #[test]
    fn builds_and_verifies_two_of_three() {
        let (s1, k1) = signer_and_key(&[1u8; 32]);
        let (s2, k2) = signer_and_key(&[2u8; 32]);
        let (s3, _k3) = signer_and_key(&[3u8; 32]);
        let pinned = vec![s1.clone(), s2.clone(), s3];
        let cid = [42u8; 32];
        let sigs = vec![
            cosign(&k1, &s1, &cid, 2, &pinned),
            cosign(&k2, &s2, &cid, 2, &pinned),
        ];

        let w = QuorumProofWitness::from_quorum(&cid, &pinned, 2, &sigs).expect("build");
        // Exactly two enabled bits.
        assert_eq!(w.enabled.iter().filter(|&&b| b == 1).count(), 2);
        // Native pre-check must pass.
        w.verify_inputs().expect("verify_inputs");
        // Public-signal arity = 2N + 2.
        assert_eq!(w.public_signals().len(), 2 * N + 2);
        // Reconstructed expected signals match the witness's own.
        let expected = expected_public_signals(&cid, &pinned, 2).expect("expected");
        assert_eq!(expected, w.public_signals());
    }

    #[test]
    fn insufficient_signatures_is_rejected() {
        let (s1, k1) = signer_and_key(&[1u8; 32]);
        let (s2, _k2) = signer_and_key(&[2u8; 32]);
        let (s3, _k3) = signer_and_key(&[3u8; 32]);
        let pinned = vec![s1.clone(), s2, s3];
        let cid = [7u8; 32];
        // Only one valid signature, threshold 2.
        let sigs = vec![cosign(&k1, &s1, &cid, 2, &pinned)];
        let err = QuorumProofWitness::from_quorum(&cid, &pinned, 2, &sigs).unwrap_err();
        assert!(matches!(
            err,
            QuorumWitnessError::InsufficientValidSignatures {
                valid: 1,
                threshold: 2
            }
        ));
    }

    #[test]
    fn threshold_above_set_size_rejected() {
        let (s1, _k1) = signer_and_key(&[1u8; 32]);
        let pinned = vec![s1];
        let cid = [9u8; 32];
        let err = QuorumProofWitness::from_quorum(&cid, &pinned, 5, &[]).unwrap_err();
        assert!(matches!(err, QuorumWitnessError::ThresholdTooHigh(5, 1)));
    }

    #[test]
    fn threshold_zero_is_rejected() {
        // A zero threshold is nonsensical and previously fell through to a
        // panic at the `filler.expect(...)` when no signatures were supplied.
        let (s1, _k1) = signer_and_key(&[1u8; 32]);
        let pinned = vec![s1];
        let cid = [4u8; 32];
        let err = QuorumProofWitness::from_quorum(&cid, &pinned, 0, &[]).unwrap_err();
        assert!(matches!(err, QuorumWitnessError::ThresholdZero));
    }

    #[test]
    fn duplicate_pinned_signer_is_rejected() {
        // The same signer pinned twice must be rejected so one signature
        // cannot be counted for both slots (the circuit's soundness sketch
        // assumes a distinct pinned set).
        let (s1, k1) = signer_and_key(&[1u8; 32]);
        let pinned = vec![s1.clone(), s1.clone()];
        let cid = [8u8; 32];
        let sigs = vec![cosign(&k1, &s1, &cid, 2, &pinned)];
        let err = QuorumProofWitness::from_quorum(&cid, &pinned, 2, &sigs).unwrap_err();
        assert!(matches!(err, QuorumWitnessError::DuplicateSigner(1)));
        // The verifier's signal reconstruction must reject the same set.
        let err2 = expected_public_signals(&cid, &pinned, 2).unwrap_err();
        assert!(matches!(err2, QuorumWitnessError::DuplicateSigner(1)));
    }

    #[test]
    fn padding_slots_carry_on_curve_points_and_are_disabled() {
        // Single real signer, padded to N. All padding pubkeys repeat signer 0,
        // all padding (R8,S) borrow the one real signature, padding disabled.
        let (s1, k1) = signer_and_key(&[5u8; 32]);
        let pinned = vec![s1.clone()];
        let cid = [3u8; 32];
        let sigs = vec![cosign(&k1, &s1, &cid, 1, &pinned)];
        let w = QuorumProofWitness::from_quorum(&cid, &pinned, 1, &sigs).expect("build");
        assert_eq!(w.enabled[0], 1);
        for i in 1..N {
            assert_eq!(w.enabled[i], 0, "padding slot {i} must be disabled");
            // Padding pubkey repeats the last real signer (here, signer 0).
            assert_eq!(w.signer_ax[i], w.signer_ax[0]);
            assert_eq!(w.signer_ay[i], w.signer_ay[0]);
        }
        w.verify_inputs().expect("verify_inputs");
    }

    #[test]
    fn tampered_enabled_slot_fails_verify_inputs() {
        let (s1, k1) = signer_and_key(&[1u8; 32]);
        let (s2, _k2) = signer_and_key(&[2u8; 32]);
        let pinned = vec![s1.clone(), s2];
        let cid = [11u8; 32];
        let sigs = vec![cosign(&k1, &s1, &cid, 1, &pinned)];
        let mut w = QuorumProofWitness::from_quorum(&cid, &pinned, 1, &sigs).expect("build");
        // Force slot 1 enabled without a real signature there (it holds filler).
        w.enabled[1] = 1;
        // Slot 1 pins signer 2's *distinct* pubkey, so this is a signature
        // failure, not a distinctness failure — name which, so the test cannot
        // pass for an unrelated reason.
        assert!(matches!(
            w.verify_inputs().unwrap_err(),
            QuorumWitnessError::BadSignature(1)
        ));
    }

    /// The OLY-M5 shape, at the witness level: one real signer padded to `N`,
    /// then every padding slot flipped on to reuse that one signature.
    #[test]
    fn padding_slots_flipped_enabled_are_rejected_as_duplicates() {
        let (s1, k1) = signer_and_key(&[5u8; 32]);
        let pinned = vec![s1.clone()];
        let cid = [3u8; 32];
        let sigs = vec![cosign(&k1, &s1, &cid, 1, &pinned)];
        let mut w = QuorumProofWitness::from_quorum(&cid, &pinned, 1, &sigs).expect("build");
        // Every slot repeats signer 0's pubkey and borrows its signature, so
        // each one verifies under EdDSA. Only distinctness can reject this.
        w.enabled = [1u8; N];
        w.threshold = N as u64;
        assert!(matches!(
            w.verify_inputs().unwrap_err(),
            QuorumWitnessError::DuplicateSigner(1)
        ));
    }

    /// Disabling the real slot and enabling a padding copy must fail too —
    /// the distinctness rule is one-directional (only the *first* occurrence of
    /// a key may be enabled), which is what makes this case a rejection.
    #[test]
    fn enabling_a_padding_copy_instead_of_the_original_is_rejected() {
        let (s1, k1) = signer_and_key(&[5u8; 32]);
        let pinned = vec![s1.clone()];
        let cid = [3u8; 32];
        let sigs = vec![cosign(&k1, &s1, &cid, 1, &pinned)];
        let mut w = QuorumProofWitness::from_quorum(&cid, &pinned, 1, &sigs).expect("build");
        w.enabled = [0u8; N];
        w.enabled[3] = 1;
        assert!(matches!(
            w.verify_inputs().unwrap_err(),
            QuorumWitnessError::DuplicateSigner(3)
        ));
    }

    #[test]
    fn off_curve_pinned_signer_is_rejected() {
        let (s1, _k1) = signer_and_key(&[1u8; 32]);
        // Perturb x so the point leaves the curve while staying in-field.
        let bad = QuorumSigner {
            x: fr_to_decimal(&(parse_fr(&s1.x).unwrap() + Fr::from(1u64))),
            y: s1.y.clone(),
        };
        let pk = parse_signer(&bad).expect("still parses as two field elements");
        assert!(
            !baby_jubjub::bjj_is_on_curve(&baby_jubjub::bjj_affine(pk.x, pk.y)),
            "test vector must actually be off-curve"
        );
        let cid = [12u8; 32];
        let pinned = vec![bad];
        assert!(matches!(
            QuorumProofWitness::from_quorum(&cid, &pinned, 1, &[]).unwrap_err(),
            QuorumWitnessError::OffCurveSigner(0)
        ));
        assert!(matches!(
            expected_public_signals(&cid, &pinned, 1).unwrap_err(),
            QuorumWitnessError::OffCurveSigner(0)
        ));
    }

    #[test]
    fn identity_pinned_signer_is_rejected() {
        // (0, 1) is on the curve but is the identity — order 1, so it is not a
        // real pubkey and trivially satisfies a naive subgroup multiplication.
        let identity = QuorumSigner {
            x: "0".into(),
            y: "1".into(),
        };
        let cid = [13u8; 32];
        let pinned = vec![identity];
        assert!(matches!(
            QuorumProofWitness::from_quorum(&cid, &pinned, 1, &[]).unwrap_err(),
            QuorumWitnessError::OffCurveSigner(0)
        ));
    }

    #[test]
    fn off_curve_key_on_a_disabled_padding_slot_is_rejected() {
        // Pre-fix this passed silently: the disabled slot's key was never
        // checked. The circuit's BabyCheck is ungated, so this mirror is too.
        let (s1, k1) = signer_and_key(&[5u8; 32]);
        let pinned = vec![s1.clone()];
        let cid = [3u8; 32];
        let sigs = vec![cosign(&k1, &s1, &cid, 1, &pinned)];
        let mut w = QuorumProofWitness::from_quorum(&cid, &pinned, 1, &sigs).expect("build");
        assert_eq!(w.enabled[7], 0, "slot 7 must be padding for this test");
        w.signer_ax[7] += Fr::from(1u64);
        assert!(matches!(
            w.verify_inputs().unwrap_err(),
            QuorumWitnessError::OffCurveSigner(7)
        ));
    }

    #[test]
    fn expected_public_signals_rejects_out_of_range_thresholds() {
        // The circuit rejects threshold = 0 (thresholdIsZero) and >= 256
        // (Num2Bits(8)); the verifier-side reconstruction must refuse to build
        // a signal vector for either rather than defer to proof verification.
        let (s1, _k1) = signer_and_key(&[1u8; 32]);
        let pinned = vec![s1];
        let cid = [15u8; 32];
        assert!(matches!(
            expected_public_signals(&cid, &pinned, 0).unwrap_err(),
            QuorumWitnessError::ThresholdZero
        ));
        assert!(matches!(
            expected_public_signals(&cid, &pinned, 256).unwrap_err(),
            QuorumWitnessError::ThresholdOutOfRange(256)
        ));
        // 255 is the last value inside the comparator's range and must build.
        assert!(expected_public_signals(&cid, &pinned, 255).is_ok());
    }

    #[test]
    fn threshold_outside_the_comparator_range_is_rejected() {
        let (s1, k1) = signer_and_key(&[1u8; 32]);
        let pinned = vec![s1.clone()];
        let cid = [14u8; 32];
        let sigs = vec![cosign(&k1, &s1, &cid, 1, &pinned)];
        let mut w = QuorumProofWitness::from_quorum(&cid, &pinned, 1, &sigs).expect("build");
        // GreaterEqThan(8) is only sound for operands < 256; 256 is the first
        // value that can wrap it.
        w.threshold = 256;
        assert!(matches!(
            w.verify_inputs().unwrap_err(),
            QuorumWitnessError::ThresholdOutOfRange(256)
        ));

        w.threshold = 0;
        assert!(matches!(
            w.verify_inputs().unwrap_err(),
            QuorumWitnessError::ThresholdZero
        ));
    }

    /// Emit circom input fixtures for `proofs/test/federation_quorum.test.js`.
    ///
    /// The circuit-level negative tests need *real* BJJ-EdDSA signatures, or a
    /// case meant to trip the distinctness constraint would instead trip the
    /// signature check and prove nothing. There is no `circomlibjs` in
    /// `proofs/node_modules` (only circuit sources), so rather than add a
    /// signing dependency to JS the fixtures are generated here, where the
    /// signing path is already unit-tested.
    ///
    /// They are written to **`proofs/test_inputs/quorum_fixtures/` (tracked)**,
    /// not to the gitignored `proofs/build/`, for the same reason
    /// `clients/python/tests/vectors.json` is committed: it lets the JS harness
    /// run in a CI job that has circom and Node but not the whole Tauri/GTK
    /// Rust build. Everything here is deterministic — fixed private keys, fixed
    /// commit id — so regenerating produces a byte-identical result and any
    /// diff is real drift.
    ///
    /// Regenerate + commit whenever the witness layout changes:
    /// ```text
    /// cargo test --no-default-features --features prover,quorum-circuit \
    ///     --lib zk::witness::quorum
    /// ```
    ///
    /// Kept as a test (not a bin) so CI's `--features quorum-circuit` run
    /// refreshes them for free. It asserts the shape of what it emits, so it
    /// fails rather than writing a fixture that would silently test nothing.
    #[test]
    fn emit_circom_fixtures_for_the_witness_harness() {
        use std::path::PathBuf;

        // A witness's circom inputs as JSON. `msg` and `threshold` are scalar
        // signals; everything else is an array of length N.
        fn to_json(w: &QuorumProofWitness) -> serde_json::Value {
            let mut map = serde_json::Map::new();
            for (name, vals) in w.circom_inputs() {
                let strs: Vec<String> = vals.iter().map(|v| v.to_string()).collect();
                let v = if name == "msg" || name == "threshold" {
                    serde_json::Value::String(strs[0].clone())
                } else {
                    serde_json::Value::from(strs)
                };
                map.insert(name, v);
            }
            serde_json::Value::Object(map)
        }

        let dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../proofs/test_inputs/quorum_fixtures");
        std::fs::create_dir_all(&dir).expect("create fixture dir");

        let write = |name: &str, v: &serde_json::Value| {
            std::fs::write(
                dir.join(format!("{name}.json")),
                serde_json::to_string_pretty(v).expect("serialize fixture"),
            )
            .unwrap_or_else(|e| panic!("write fixture {name}: {e}"));
        };

        // ---- p1: three distinct signers, all three co-sign, threshold 3 ----
        let (a, ka) = signer_and_key(&[21u8; 32]);
        let (b, kb) = signer_and_key(&[22u8; 32]);
        let (c, kc) = signer_and_key(&[23u8; 32]);
        let trio = vec![a.clone(), b.clone(), c.clone()];
        let cid = [77u8; 32];
        let trio_sigs = vec![
            cosign(&ka, &a, &cid, 3, &trio),
            cosign(&kb, &b, &cid, 3, &trio),
            cosign(&kc, &c, &cid, 3, &trio),
        ];
        let p1 = QuorumProofWitness::from_quorum(&cid, &trio, 3, &trio_sigs).expect("p1");
        p1.verify_inputs().expect("p1 must be a satisfying witness");
        write("p1_three_of_three", &to_json(&p1));

        // ---- p2: one signer padded to N — the honest duplicate shape ----
        let (solo, ksolo) = signer_and_key(&[24u8; 32]);
        let solo_set = vec![solo.clone()];
        let solo_sigs = vec![cosign(&ksolo, &solo, &cid, 1, &solo_set)];
        let p2 = QuorumProofWitness::from_quorum(&cid, &solo_set, 1, &solo_sigs).expect("p2");
        p2.verify_inputs().expect("p2 must be a satisfying witness");
        // The whole point of this fixture: slots 1..N repeat slot 0's key.
        for i in 1..N {
            assert_eq!(p2.signer_ax[i], p2.signer_ax[0]);
            assert_eq!(p2.enabled[i], 0);
        }
        write("p2_padded_single_signer", &to_json(&p2));

        // ---- n1 (OLY-M5): every padding slot flipped on, one signature ----
        // Each slot carries slot 0's key AND slot 0's signature, so EdDSA
        // verifies on all eight. Distinctness is the only thing that can reject.
        let mut n1 = p2.clone();
        n1.enabled = [1u8; N];
        n1.threshold = N as u64;
        for i in 0..N {
            assert!(
                baby_jubjub::verify_signature(
                    &BabyJubJubPubKey {
                        x: n1.signer_ax[i],
                        y: n1.signer_ay[i]
                    },
                    &BabyJubJubSignature {
                        r8x: n1.r8x[i],
                        r8y: n1.r8y[i],
                        s: n1.s[i]
                    },
                    n1.msg
                ),
                "slot {i} must carry a VERIFYING signature, else the fixture would \
                 fail on the EdDSA check instead of the distinctness check"
            );
        }
        write("n1_m5_all_padding_enabled", &to_json(&n1));

        // ---- n2 (OLY-M5): disable the original, enable a padding copy ----
        let mut n2 = p2.clone();
        n2.enabled = [0u8; N];
        n2.enabled[3] = 1;
        n2.threshold = 1;
        write("n2_m5_padding_copy_enabled", &to_json(&n2));

        // ---- n3/n4/n5: threshold out of the comparator's range, and zero ----
        let mut n3 = to_json(&p1);
        n3["threshold"] = serde_json::Value::String("256".into());
        write("n3_threshold_256", &n3);

        let mut n4 = to_json(&p1);
        // Fr(-1) = r - 1: in-field, but astronomically outside 8 bits.
        n4["threshold"] =
            serde_json::Value::String(fr_to_decimal(&(Fr::from(0u64) - Fr::from(1u64))));
        write("n4_threshold_field_max", &n4);

        let mut n5 = to_json(&p1);
        n5["threshold"] = serde_json::Value::String("0".into());
        write("n5_threshold_zero", &n5);

        // ---- n6/n7 (OLY-L12): off-curve key, enabled and disabled slot ----
        let mut n6 = p1.clone();
        n6.signer_ax[0] += Fr::from(1u64);
        assert_eq!(n6.enabled[0], 1);
        assert!(!baby_jubjub::bjj_is_on_curve(&baby_jubjub::bjj_affine(
            n6.signer_ax[0],
            n6.signer_ay[0]
        )));
        write("n6_off_curve_enabled_slot", &to_json(&n6));

        let mut n7 = p2.clone();
        n7.signer_ax[7] += Fr::from(1u64);
        assert_eq!(n7.enabled[7], 0, "slot 7 must be disabled padding");
        write("n7_off_curve_disabled_slot", &to_json(&n7));
    }
}
