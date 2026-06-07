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

    /// Native pre-check mirroring the circuit: every `enabled` slot must carry a
    /// signature that verifies under its pinned pubkey over `msg`, and the count
    /// of enabled slots must be `>= threshold`. Catches a malformed witness in
    /// microseconds before the (heavy) WASM witness generation runs.
    pub fn verify_inputs(&self) -> Result<(), QuorumWitnessError> {
        let mut count = 0u64;
        for i in 0..N {
            match self.enabled[i] {
                0 => {}
                1 => {
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
        assert!(w.verify_inputs().is_err());
    }
}
