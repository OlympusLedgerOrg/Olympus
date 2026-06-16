//! Checkpoint-quorum co-signatures: M-of-N over a ledger `root`.
//!
//! ADR-0032 endpoint. Where [`super::verify_quorum`] co-signs a credential
//! `commit_id`, this co-signs a **checkpoint `ledger_root`** — N pinned
//! federation signers each BJJ-EdDSA-sign the same domain-separated message,
//! and anyone holding the pinned `N` pubkeys can re-verify the M-of-N quorum
//! offline. It reuses the parent module's hardened machinery verbatim (pinned
//! signer set, member-only counting, dedup by normalized key, threshold bound
//! into the signed message, fail-closed); only the **domain tag** and the
//! **bound object** (root vs commit_id) change.
//!
//! This deliberately does NOT replace the existing single-signer checkpoint
//! signature (`federation::verify::verify_checkpoint_signature`, where one
//! authority signs the bare `ledger_root`). It is the M-of-N extension a peer
//! set co-signs a checkpoint with — the disjoint domain tag keeps the two from
//! ever being confused.
//!
//! Phase 1 (no producer yet): exercised by the unit tests below and the golden
//! vector in `verifiers/test_vectors/checkpoint_quorum_vectors.json`. The Phase 2
//! producer (co-signing real `own_checkpoints` roots over Tor, the way
//! `federation::cosign` collects SBT quorum signatures) will be the non-test
//! caller. Until then `#![allow(dead_code)]` keeps the bin-target compilation —
//! which has no producer — warning-clean; the items are public API on the lib
//! target regardless.
#![allow(dead_code)]

use ark_bn254::Fr;
use ark_ff::PrimeField;

use super::{normalize_signer, CollectedSignature, QuorumSigner, QuorumStatus};
use crate::zk::proof::{fr_to_decimal, parse_fr};
use crate::zk::witness::baby_jubjub::{
    self, BabyJubJubError, BabyJubJubPubKey, BabyJubJubSignature,
};

/// Domain tag for checkpoint-quorum co-signatures.
///
/// Disjoint from the SBT quorum tag (`OLY:SBT:QUORUM:V2`,
/// [`super::QUORUM_COSIGN_PREFIX`]), the single-issuer credential signature
/// (bare `commit_id`), and revocation (`OLY:SBT:REVOKE:V1`). A signature minted
/// in one of those roles can never verify in another, and vice-versa — the
/// prefix enters the BLAKE3 pre-image, so a different role yields a different
/// message field element.
pub const CHECKPOINT_QUORUM_PREFIX: &[u8] = b"OLY:CHECKPOINT:QUORUM:V1";

/// Derive the checkpoint-quorum co-sign message (a BN254 `Fr`) every signer
/// signs.
///
/// Binds the checkpoint `root` (as its canonical decimal field element) **and**
/// the pinned quorum parameters — `threshold` plus the canonical signer set — so
/// none of the three can change after the fact without invalidating every
/// collected signature (the same R3-01 binding the SBT quorum uses). `signers`
/// is normalised and sorted internally (malformed entries dropped, exactly as
/// [`verify_checkpoint_quorum`] builds its eligible set), so the digest does not
/// depend on signer ordering or on non-canonical decimal encodings.
///
/// Byte layout (length-prefixed BLAKE3, identical framing to
/// [`super::quorum_cosign_message`] — only the tag and leading value differ):
///
/// ```text
/// msg = Fr_le( BLAKE3(
///     "OLY:CHECKPOINT:QUORUM:V1"
///   | u32_be(len(root_dec)) || root_dec
///   | u32_be(threshold)
///   | u32_be(N) || for each canonical signer: u32_be(len(x))||x||u32_be(len(y))||y
/// ) )
/// ```
///
/// `root_dec = fr_to_decimal(root)` is the canonical decimal of the field
/// element, so `"007"` and `"7"` (and any value `>= r`) can never produce a
/// distinct message from their canonical form.
pub fn checkpoint_quorum_message(root: &Fr, threshold: usize, signers: &[QuorumSigner]) -> Fr {
    use std::collections::BTreeSet;

    let root_dec = fr_to_decimal(root);
    let canonical: BTreeSet<(String, String)> =
        signers.iter().filter_map(normalize_signer).collect();

    let mut h = blake3::Hasher::new();
    h.update(CHECKPOINT_QUORUM_PREFIX);
    h.update(&(root_dec.len() as u32).to_be_bytes());
    h.update(root_dec.as_bytes());
    h.update(&(threshold as u32).to_be_bytes());
    h.update(&(canonical.len() as u32).to_be_bytes());
    for (x, y) in &canonical {
        h.update(&(x.len() as u32).to_be_bytes());
        h.update(x.as_bytes());
        h.update(&(y.len() as u32).to_be_bytes());
        h.update(y.as_bytes());
    }
    let digest = *h.finalize().as_bytes();
    Fr::from_le_bytes_mod_order(&digest)
}

/// Verify an M-of-N quorum over a checkpoint `root` against the pinned `signers`.
///
/// A signature counts toward the quorum iff ALL hold (identical rules to
/// [`super::verify_quorum`]):
///   1. its signer is a member of the pinned `signers` set,
///   2. the BJJ-EdDSA signature verifies over [`checkpoint_quorum_message`]
///      (which enforces subgroup + malleability guards inside
///      [`baby_jubjub::verify_signature`]),
///   3. the signer has not already been counted (distinctness — keyed on the
///      normalized pubkey, so one key under two labels counts once).
///
/// Fails closed: any parse failure on a signature or signer drops that entry
/// rather than aborting. `satisfied` requires `valid_signatures >= threshold`
/// AND `threshold >= 1` (a zero threshold is never vacuously satisfied).
pub fn verify_checkpoint_quorum(
    root: &Fr,
    signers: &[QuorumSigner],
    threshold: usize,
    sigs: &[CollectedSignature],
) -> QuorumStatus {
    use std::collections::BTreeSet;

    // The message binds root + threshold + the pinned set, so a post-hoc tamper
    // to any of them makes every stored signature verify against a different
    // message and drop out below.
    let msg = checkpoint_quorum_message(root, threshold, signers);

    let allowed: BTreeSet<(String, String)> = signers.iter().filter_map(normalize_signer).collect();

    let mut counted: BTreeSet<(String, String)> = BTreeSet::new();
    for cs in sigs {
        let Some(id) = normalize_signer(&cs.signer) else {
            continue;
        };
        if !allowed.contains(&id) || counted.contains(&id) {
            continue;
        }
        let (Ok(px), Ok(py)) = (parse_fr(&cs.signer.x), parse_fr(&cs.signer.y)) else {
            continue;
        };
        let (Ok(r8x), Ok(r8y), Ok(s)) = (parse_fr(&cs.r8x), parse_fr(&cs.r8y), parse_fr(&cs.s))
        else {
            continue;
        };
        let pubkey = BabyJubJubPubKey { x: px, y: py };
        let sig = BabyJubJubSignature { r8x, r8y, s };
        if baby_jubjub::verify_signature(&pubkey, &sig, msg) {
            counted.insert(id);
        }
    }

    let valid_signatures = counted.len();
    QuorumStatus {
        threshold,
        total_signers: allowed.len(),
        valid_signatures,
        satisfied: threshold >= 1 && valid_signatures >= threshold,
    }
}

/// Build a [`QuorumSigner`] (canonical decimal pubkey coords) from a 32-byte BJJ
/// private key — the inverse of what [`verify_checkpoint_quorum`] normalises,
/// exposed for producers and the golden-vector generator.
pub fn signer_from_private(priv_key: &[u8; 32]) -> Result<QuorumSigner, BabyJubJubError> {
    let pk = BabyJubJubPubKey::from_private(priv_key)?;
    Ok(QuorumSigner {
        x: fr_to_decimal(&pk.x),
        y: fr_to_decimal(&pk.y),
    })
}

/// Co-sign a checkpoint `root` under the pinned `(threshold, signers)` with a BJJ
/// private key, returning the wire-shaped [`CollectedSignature`].
///
/// This is the signing primitive a Phase-2 checkpoint co-sign producer calls
/// (the checkpoint analogue of `federation::cosign` for SBT quorums); it also
/// generates the golden vectors. The result verifies through
/// [`verify_checkpoint_quorum`] for the same `(root, threshold, signers)`.
pub fn cosign_checkpoint(
    priv_key: &[u8; 32],
    root: &Fr,
    threshold: usize,
    signers: &[QuorumSigner],
) -> Result<CollectedSignature, BabyJubJubError> {
    let signer = signer_from_private(priv_key)?;
    let msg = checkpoint_quorum_message(root, threshold, signers);
    let sig = baby_jubjub::sign(priv_key, msg)?;
    Ok(CollectedSignature {
        signer,
        r8x: fr_to_decimal(&sig.r8x),
        r8y: fr_to_decimal(&sig.r8y),
        s: fr_to_decimal(&sig.s),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer_for(priv_key: &[u8; 32]) -> (QuorumSigner, [u8; 32]) {
        (signer_from_private(priv_key).expect("pubkey"), *priv_key)
    }

    fn cosign(
        priv_key: &[u8; 32],
        _signer: &QuorumSigner,
        root: &Fr,
        threshold: usize,
        signers: &[QuorumSigner],
    ) -> CollectedSignature {
        cosign_checkpoint(priv_key, root, threshold, signers).expect("sign")
    }

    #[test]
    fn message_is_deterministic_root_threshold_and_set_bound() {
        let (s1, _) = signer_for(&[1u8; 32]);
        let (s2, _) = signer_for(&[2u8; 32]);
        let signers = vec![s1.clone(), s2.clone()];
        let root = Fr::from(123456u64);
        let m = |r: &Fr, t, sg: &[QuorumSigner]| checkpoint_quorum_message(r, t, sg);

        assert_eq!(m(&root, 2, &signers), m(&root, 2, &signers));
        // A different root changes the message.
        assert_ne!(m(&root, 2, &signers), m(&Fr::from(123457u64), 2, &signers));
        // Threshold is bound.
        assert_ne!(m(&root, 2, &signers), m(&root, 1, &signers));
        // The signer set is bound.
        assert_ne!(m(&root, 2, &signers), m(&root, 2, &signers[..1]));
        // Canonical ordering: signer order does NOT change the message.
        let reordered = vec![s2, s1];
        assert_eq!(m(&root, 2, &signers), m(&root, 2, &reordered));
    }

    #[test]
    fn message_is_domain_separated_from_sbt_quorum() {
        // The same N-byte value bound as a checkpoint root vs. an SBT commit_id
        // must yield different messages — the only difference is the domain tag
        // (and the root-decimal vs commit-hex framing), both of which enter the
        // BLAKE3 pre-image. This is what stops a checkpoint co-signature from
        // being replayed as an SBT quorum co-signature.
        use ark_ff::BigInteger;
        let (s1, _) = signer_for(&[1u8; 32]);
        let signers = vec![s1];
        let root = Fr::from(42u64);
        let mut root_be = [0u8; 32];
        let bytes = root.into_bigint().to_bytes_be();
        root_be.copy_from_slice(&bytes);

        let cp_msg = checkpoint_quorum_message(&root, 1, &signers);
        let sbt_msg = crate::quorum::quorum_cosign_message(&root_be, 1, &signers);
        assert_ne!(cp_msg, sbt_msg);
    }

    #[test]
    fn two_of_three_is_satisfied_by_two_valid_signatures() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let (s2, k2) = signer_for(&[2u8; 32]);
        let (s3, _k3) = signer_for(&[3u8; 32]);
        let signers = vec![s1.clone(), s2.clone(), s3.clone()];
        let root = Fr::from(99u64);

        let sigs = vec![
            cosign(&k1, &s1, &root, 2, &signers),
            cosign(&k2, &s2, &root, 2, &signers),
        ];
        let status = verify_checkpoint_quorum(&root, &signers, 2, &sigs);
        assert_eq!(status.total_signers, 3);
        assert_eq!(status.valid_signatures, 2);
        assert!(status.satisfied);
    }

    #[test]
    fn one_valid_signature_does_not_satisfy_two_of_three() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let (s2, _k2) = signer_for(&[2u8; 32]);
        let (s3, _k3) = signer_for(&[3u8; 32]);
        let signers = vec![s1.clone(), s2, s3];
        let root = Fr::from(7u64);

        let sigs = vec![cosign(&k1, &s1, &root, 2, &signers)];
        let status = verify_checkpoint_quorum(&root, &signers, 2, &sigs);
        assert_eq!(status.valid_signatures, 1);
        assert!(!status.satisfied);
    }

    #[test]
    fn signature_from_non_member_is_not_counted() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let (s2, _k2) = signer_for(&[2u8; 32]);
        let (outsider, ko) = signer_for(&[99u8; 32]);
        let signers = vec![s1.clone(), s2];
        let root = Fr::from(5u64);

        let sigs = vec![
            cosign(&k1, &s1, &root, 2, &signers),
            cosign(&ko, &outsider, &root, 2, &signers),
        ];
        let status = verify_checkpoint_quorum(&root, &signers, 2, &sigs);
        assert_eq!(status.valid_signatures, 1, "outsider sig must be ignored");
        assert!(!status.satisfied);
    }

    #[test]
    fn duplicate_signer_counts_once() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let (s2, _k2) = signer_for(&[2u8; 32]);
        let signers = vec![s1.clone(), s2];
        let root = Fr::from(11u64);

        let sigs = vec![
            cosign(&k1, &s1, &root, 2, &signers),
            cosign(&k1, &s1, &root, 2, &signers),
        ];
        let status = verify_checkpoint_quorum(&root, &signers, 2, &sigs);
        assert_eq!(status.valid_signatures, 1);
        assert!(!status.satisfied);
    }

    #[test]
    fn signature_over_wrong_root_is_rejected() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let signers = vec![s1.clone()];
        let root = Fr::from(1u64);
        let wrong_root = Fr::from(2u64);

        let sigs = vec![cosign(&k1, &s1, &wrong_root, 1, &signers)];
        let status = verify_checkpoint_quorum(&root, &signers, 1, &sigs);
        assert_eq!(status.valid_signatures, 0);
        assert!(!status.satisfied);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let signers = vec![s1.clone()];
        let root = Fr::from(3u64);
        let mut sig = cosign(&k1, &s1, &root, 1, &signers);
        sig.s = "12345".to_owned();
        let status = verify_checkpoint_quorum(&root, &signers, 1, &[sig]);
        assert_eq!(status.valid_signatures, 0);
        assert!(!status.satisfied);
    }

    #[test]
    fn tampering_root_threshold_or_signer_set_breaks_the_quorum() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let (s2, k2) = signer_for(&[2u8; 32]);
        let (s3, _k3) = signer_for(&[3u8; 32]);
        let signers = vec![s1.clone(), s2.clone(), s3.clone()];
        let root = Fr::from(42u64);
        let sigs = vec![
            cosign(&k1, &s1, &root, 2, &signers),
            cosign(&k2, &s2, &root, 2, &signers),
        ];
        assert!(verify_checkpoint_quorum(&root, &signers, 2, &sigs).satisfied);

        // Tamper the root: signatures were made over `root`, so against a
        // different root none verify.
        let other_root = Fr::from(43u64);
        let rerooted = verify_checkpoint_quorum(&other_root, &signers, 2, &sigs);
        assert_eq!(rerooted.valid_signatures, 0);
        assert!(!rerooted.satisfied);

        // Downgrade threshold 2 -> 1: the bound message changes, so none verify.
        let downgraded = verify_checkpoint_quorum(&root, &signers, 1, &sigs);
        assert_eq!(downgraded.valid_signatures, 0);
        assert!(!downgraded.satisfied);

        // Substitute an attacker key into the pinned set.
        let (attacker, _ka) = signer_for(&[123u8; 32]);
        let swapped = vec![s1.clone(), s2.clone(), attacker];
        let swapped_status = verify_checkpoint_quorum(&root, &swapped, 2, &sigs);
        assert_eq!(swapped_status.valid_signatures, 0);
        assert!(!swapped_status.satisfied);
    }

    #[test]
    fn zero_threshold_is_never_vacuously_satisfied() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let signers = vec![s1.clone()];
        let root = Fr::from(8u64);
        // A genuinely valid signature, but threshold 0 must NOT be "satisfied".
        let sigs = vec![cosign(&k1, &s1, &root, 0, &signers)];
        let status = verify_checkpoint_quorum(&root, &signers, 0, &sigs);
        assert!(!status.satisfied);
    }

    #[test]
    fn golden_vectors_match_committed_file() {
        // Pin the committed golden vector (consumed byte-for-byte by the JS
        // differential verifier, verifiers/javascript/test_checkpoint_quorum.js)
        // against this implementation. If this fails after an intentional change,
        // regenerate with:
        //   cargo run -p olympus-desktop --example gen_checkpoint_quorum_vectors
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../verifiers/test_vectors/checkpoint_quorum_vectors.json"
        );
        let raw = std::fs::read_to_string(path).expect("read golden vector");
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse golden vector");
        assert_eq!(doc["domain"], "OLY:CHECKPOINT:QUORUM:V1");
        let cases = doc["cases"].as_array().expect("cases array");
        assert!(!cases.is_empty(), "vector must have cases");

        for c in cases {
            let name = c["name"].as_str().unwrap_or("<unnamed>");
            let root = parse_fr(c["root"].as_str().expect("root")).expect("root parses");
            let threshold = c["threshold"].as_u64().expect("threshold") as usize;
            let signers: Vec<QuorumSigner> =
                serde_json::from_value(c["signers"].clone()).expect("signers");
            let cosigs: Vec<CollectedSignature> =
                serde_json::from_value(c["cosignatures"].clone()).expect("cosignatures");

            let status = verify_checkpoint_quorum(&root, &signers, threshold, &cosigs);
            let message = fr_to_decimal(&checkpoint_quorum_message(&root, threshold, &signers));

            assert_eq!(
                message,
                c["expected"]["message"].as_str().unwrap(),
                "{name}: message mismatch"
            );
            assert_eq!(
                status.satisfied,
                c["expected"]["satisfied"].as_bool().unwrap(),
                "{name}: satisfied mismatch"
            );
            assert_eq!(
                status.valid_signatures as u64,
                c["expected"]["valid_signatures"].as_u64().unwrap(),
                "{name}: valid_signatures mismatch"
            );
            assert_eq!(
                status.total_signers as u64,
                c["expected"]["total_signers"].as_u64().unwrap(),
                "{name}: total_signers mismatch"
            );
        }
    }
}
