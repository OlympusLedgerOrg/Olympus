// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Trust-list transition approvals (ADR-0041 §5/§7/§8): M-of-N BJJ-EdDSA
//! verification for the three trust domains — routine rotation
//! (`OLY:TRUST:ROTATE:V1`), offline role-scoped recovery
//! (`OLY:TRUST:RECOVER:V1`), and genesis (`OLY:TRUST:GENESIS:V1`).
//!
//! The domain-prefixed BLAKE3 message layouts live in
//! `olympus_crypto::trust_list` so every conforming implementation computes
//! identical digests (ADR-0041 security invariant 15) without needing a
//! curve stack. This module is the runtime half: it reduces those digests
//! into `Fr` (via [`super::QuorumMessage`]'s trust constructors — the same
//! `from_le_bytes_mod_order` reduction the SBT and checkpoint domains use)
//! and routes them through the shared, hardened
//! [`super::verify_generic_quorum`] loop (pinned signer set, member-only
//! counting, dedup by normalized key, fail-closed on parse failures).
//!
//! # Who is a signer, per domain
//!
//! * **Rotation**: the *previous accepted* snapshot's [`RotationPolicy`] for
//!   each affected role — never the candidate's own policy (ADR-0041 §2; a
//!   candidate must not be able to lower its own threshold and
//!   self-authorize). The caller resolves which policy applies; this module
//!   verifies against exactly the policy it is handed.
//! * **Recovery**: the affected role's pinned offline recovery key — a fixed
//!   1-of-1 "quorum" (ADR-0041 §7). Threshold 1 is intrinsic to the domain,
//!   not configurable, so a compromised routine quorum cannot vote its way
//!   into a recovery.
//! * **Genesis**: the explicit [`GenesisApprovalPolicy`] supplied to (and
//!   persisted with) genesis (ADR-0041 §8). The message binds the complete
//!   canonical snapshot body *and* the policy itself, so an approval can
//!   never be replayed onto another payload, signer set, profile, or
//!   threshold.
//!
//! Signer identity conversion ([`quorum_signer_from_trust_pubkey`]) is
//! **fallible and fail-closed**: trust-list keys are canonical 32-byte
//! big-endian coordinates, and a non-canonical coordinate (`>= r`) is
//! rejected outright rather than reduced — reduction would silently alias
//! two "different" pinned signers onto one field element. Curve/subgroup
//! validity is deliberately NOT re-checked here: `baby_jubjub::
//! verify_signature` (inside the shared loop) fails closed on any
//! off-subgroup pubkey, so an off-curve pinned signer simply never counts.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use thiserror::Error;

use olympus_crypto::trust_list::{
    GenesisApprovalPolicy, RecoveryReason, RotationPolicy, TrustListSnapshotV1, TrustPubKey,
    TrustRole,
};

use super::{
    verify_generic_quorum_with_identities, CollectedSignature, QuorumMessage, QuorumSigner,
    QuorumStatus,
};
use crate::zk::proof::fr_to_decimal;
use crate::zk::witness::baby_jubjub::{self, BabyJubJubError};

/// Verification-side failures that precede signature counting. All are
/// fail-closed rejections of the *verification inputs* (the pinned policy or
/// key), not of submitted signatures — a bad submitted signature is simply
/// not counted by the shared loop.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustQuorumError {
    #[error(
        "trust pubkey coordinate is not a canonical BN254 field encoding (>= r); \
         reducing it would alias a distinct-looking signer onto an existing one"
    )]
    NonCanonicalTrustPubKey,
    #[error("pinned approval policy is invalid: {0}")]
    InvalidPolicy(#[from] olympus_crypto::trust_list::TrustListError),
}

/// Convert a trust-list public key (canonical 32-byte big-endian
/// coordinates) into the quorum layer's identity shape (canonical decimal
/// `Fr` strings).
///
/// Fallible on non-canonical input: a coordinate `>= r` denotes a field
/// element that already has a canonical encoding, so accepting it (by
/// modular reduction) would let one signer appear under two identities —
/// exactly the aliasing `normalize_signer` exists to prevent on the decimal
/// side. `TrustListSnapshotV1::validate` already rejects such keys, but this
/// conversion is a public boundary and must not rely on every caller having
/// validated first.
pub fn quorum_signer_from_trust_pubkey(
    key: &TrustPubKey,
) -> Result<QuorumSigner, TrustQuorumError> {
    if !key.is_canonical() {
        return Err(TrustQuorumError::NonCanonicalTrustPubKey);
    }
    // Canonicality was just checked, so `from_be_bytes_mod_order` performs no
    // actual reduction — it is a lossless decode.
    let x = Fr::from_be_bytes_mod_order(&key.x);
    let y = Fr::from_be_bytes_mod_order(&key.y);
    Ok(QuorumSigner {
        x: fr_to_decimal(&x),
        y: fr_to_decimal(&y),
    })
}

fn quorum_signers_from_trust_pubkeys(
    keys: &[TrustPubKey],
) -> Result<Vec<QuorumSigner>, TrustQuorumError> {
    keys.iter().map(quorum_signer_from_trust_pubkey).collect()
}

/// Verify a routine rotation approval set against one role's policy from the
/// **previously accepted** snapshot (ADR-0041 §2/§5).
///
/// The policy is validated before any counting (fail closed on a malformed
/// pinned policy), and its `threshold`/signer set are taken verbatim — the
/// message itself binds the complete predecessor→successor transition
/// (digests, sequences, signed `activation_at`), so an approval cannot be
/// replayed onto a different transition. A transition affecting multiple
/// roles must satisfy every affected role's prior policy: call this once per
/// affected role over the same `sigs`.
pub fn verify_trust_rotation_approval(
    prior_policy: &RotationPolicy,
    previous_snapshot_digest: &[u8; 32],
    next_snapshot_digest: &[u8; 32],
    previous_sequence: u64,
    next_sequence: u64,
    activation_at: i64,
    sigs: &[CollectedSignature],
) -> Result<QuorumStatus, TrustQuorumError> {
    Ok(verify_trust_rotation_approval_with_identities(
        prior_policy,
        previous_snapshot_digest,
        next_snapshot_digest,
        previous_sequence,
        next_sequence,
        activation_at,
        sigs,
    )?
    .0)
}

/// [`verify_trust_rotation_approval`], additionally returning the normalized
/// identities of the signers whose signature counted (ADR-0041 §6).
pub fn verify_trust_rotation_approval_with_identities(
    prior_policy: &RotationPolicy,
    previous_snapshot_digest: &[u8; 32],
    next_snapshot_digest: &[u8; 32],
    previous_sequence: u64,
    next_sequence: u64,
    activation_at: i64,
    sigs: &[CollectedSignature],
) -> Result<(QuorumStatus, Vec<(String, String)>), TrustQuorumError> {
    prior_policy.validate()?;
    let signers = quorum_signers_from_trust_pubkeys(&prior_policy.signers)?;
    let message = QuorumMessage::trust_rotation(
        previous_snapshot_digest,
        next_snapshot_digest,
        previous_sequence,
        next_sequence,
        activation_at,
    );
    Ok(verify_generic_quorum_with_identities(
        &message,
        &signers,
        usize::from(prior_policy.threshold),
        sigs,
    ))
}

/// Verify a role-scoped recovery approval against that role's pinned offline
/// recovery key from the **previously accepted** snapshot (ADR-0041 §7).
///
/// Recovery is intrinsically 1-of-1: the pinned recovery key is the entire
/// signer set and the threshold is fixed at 1 by construction, so no policy
/// (and no quorum of routine signers — security invariant 12) can widen it.
#[allow(clippy::too_many_arguments)]
pub fn verify_trust_recovery_approval(
    pinned_recovery_key: &TrustPubKey,
    role: TrustRole,
    previous_snapshot_digest: &[u8; 32],
    recovery_snapshot_digest: &[u8; 32],
    previous_sequence: u64,
    next_sequence: u64,
    reason: RecoveryReason,
    activation_at: i64,
    sigs: &[CollectedSignature],
) -> Result<QuorumStatus, TrustQuorumError> {
    Ok(verify_trust_recovery_approval_with_identities(
        pinned_recovery_key,
        role,
        previous_snapshot_digest,
        recovery_snapshot_digest,
        previous_sequence,
        next_sequence,
        reason,
        activation_at,
        sigs,
    )?
    .0)
}

/// [`verify_trust_recovery_approval`], additionally returning the normalized
/// identity of the pinned recovery key if (and only if) its signature counted
/// (ADR-0041 §6) — either empty (no valid signature) or exactly one entry,
/// since recovery is intrinsically 1-of-1.
#[allow(clippy::too_many_arguments)]
pub fn verify_trust_recovery_approval_with_identities(
    pinned_recovery_key: &TrustPubKey,
    role: TrustRole,
    previous_snapshot_digest: &[u8; 32],
    recovery_snapshot_digest: &[u8; 32],
    previous_sequence: u64,
    next_sequence: u64,
    reason: RecoveryReason,
    activation_at: i64,
    sigs: &[CollectedSignature],
) -> Result<(QuorumStatus, Vec<(String, String)>), TrustQuorumError> {
    let signer = quorum_signer_from_trust_pubkey(pinned_recovery_key)?;
    let message = QuorumMessage::trust_recovery(
        role,
        previous_snapshot_digest,
        recovery_snapshot_digest,
        previous_sequence,
        next_sequence,
        reason,
        activation_at,
    );
    Ok(verify_generic_quorum_with_identities(
        &message,
        &[signer],
        1,
        sigs,
    ))
}

/// Verify a genesis approval set against the explicit
/// [`GenesisApprovalPolicy`] (ADR-0041 §8).
///
/// The message is recomputed from the snapshot and the policy themselves
/// (never from a caller-supplied digest), so it structurally satisfies §8's
/// "the verifier recomputes `snapshot_digest` from those same bytes":
/// signatures over a digest alone, another encoding, another policy, or
/// another genesis payload verify against a different field element and
/// count zero. Duplicate signatures from one signer count once and
/// out-of-set signers never count — both inherited from the shared loop.
pub fn verify_trust_genesis_approval(
    approval_policy: &GenesisApprovalPolicy,
    snapshot: &TrustListSnapshotV1,
    sigs: &[CollectedSignature],
) -> Result<QuorumStatus, TrustQuorumError> {
    Ok(verify_trust_genesis_approval_with_identities(approval_policy, snapshot, sigs)?.0)
}

/// [`verify_trust_genesis_approval`], additionally returning the normalized
/// identities of the signers whose signature counted (ADR-0041 §6).
pub fn verify_trust_genesis_approval_with_identities(
    approval_policy: &GenesisApprovalPolicy,
    snapshot: &TrustListSnapshotV1,
    sigs: &[CollectedSignature],
) -> Result<(QuorumStatus, Vec<(String, String)>), TrustQuorumError> {
    approval_policy.validate()?;
    let signers = quorum_signers_from_trust_pubkeys(&approval_policy.signers)?;
    let message = QuorumMessage::trust_genesis(snapshot, approval_policy);
    Ok(verify_generic_quorum_with_identities(
        &message,
        &signers,
        usize::from(approval_policy.threshold),
        sigs,
    ))
}

// ── Signing primitives ────────────────────────────────────────────────────
// The approval-side counterparts of the verifiers above, mirroring
// `checkpoint::cosign_checkpoint`: the pre-server genesis/rotation/recovery
// CLIs (ADR-0041 §7/§8, a later PR) and the tests both need to produce
// wire-shaped approvals, and shipping signer + verifier together keeps the
// two derived from one message construction.

fn approve(priv_key: &[u8; 32], message: Fr) -> Result<CollectedSignature, BabyJubJubError> {
    let pk = baby_jubjub::BabyJubJubPubKey::from_private(priv_key)?;
    let sig = baby_jubjub::sign(priv_key, message)?;
    Ok(CollectedSignature {
        signer: QuorumSigner {
            x: fr_to_decimal(&pk.x),
            y: fr_to_decimal(&pk.y),
        },
        r8x: fr_to_decimal(&sig.r8x),
        r8y: fr_to_decimal(&sig.r8y),
        s: fr_to_decimal(&sig.s),
    })
}

/// Sign a routine rotation approval (`OLY:TRUST:ROTATE:V1`) with a BJJ
/// private key, returning the wire-shaped [`CollectedSignature`].
pub fn approve_trust_rotation(
    priv_key: &[u8; 32],
    previous_snapshot_digest: &[u8; 32],
    next_snapshot_digest: &[u8; 32],
    previous_sequence: u64,
    next_sequence: u64,
    activation_at: i64,
) -> Result<CollectedSignature, BabyJubJubError> {
    approve(
        priv_key,
        QuorumMessage::trust_rotation(
            previous_snapshot_digest,
            next_snapshot_digest,
            previous_sequence,
            next_sequence,
            activation_at,
        )
        .0,
    )
}

/// Sign a role-scoped recovery approval (`OLY:TRUST:RECOVER:V1`).
#[allow(clippy::too_many_arguments)]
pub fn approve_trust_recovery(
    priv_key: &[u8; 32],
    role: TrustRole,
    previous_snapshot_digest: &[u8; 32],
    recovery_snapshot_digest: &[u8; 32],
    previous_sequence: u64,
    next_sequence: u64,
    reason: RecoveryReason,
    activation_at: i64,
) -> Result<CollectedSignature, BabyJubJubError> {
    approve(
        priv_key,
        QuorumMessage::trust_recovery(
            role,
            previous_snapshot_digest,
            recovery_snapshot_digest,
            previous_sequence,
            next_sequence,
            reason,
            activation_at,
        )
        .0,
    )
}

/// Sign a genesis approval (`OLY:TRUST:GENESIS:V1`) over the complete
/// snapshot body + approval policy.
pub fn approve_trust_genesis(
    priv_key: &[u8; 32],
    snapshot: &TrustListSnapshotV1,
    approval_policy: &GenesisApprovalPolicy,
) -> Result<CollectedSignature, BabyJubJubError> {
    approve(
        priv_key,
        QuorumMessage::trust_genesis(snapshot, approval_policy).0,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::quorum::{quorum_cosign_message, verify_quorum};
    use crate::zk::proof::parse_fr;

    /// A trust-list key whose coordinates are the canonical big-endian bytes
    /// of a *real* BJJ public key derived from `priv_key`, so approvals
    /// signed with that private key verify against it.
    fn trust_key_for(priv_key: &[u8; 32]) -> TrustPubKey {
        use ark_ff::BigInteger;
        let pk = baby_jubjub::BabyJubJubPubKey::from_private(priv_key).expect("pubkey");
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&pk.x.into_bigint().to_bytes_be());
        y.copy_from_slice(&pk.y.into_bigint().to_bytes_be());
        TrustPubKey::new(x, y)
    }

    fn sorted(mut keys: Vec<TrustPubKey>) -> Vec<TrustPubKey> {
        keys.sort_unstable();
        keys
    }

    fn rotation_policy(signer_keys: &[[u8; 32]], threshold: u16) -> RotationPolicy {
        RotationPolicy {
            profile: olympus_crypto::trust_list::RotationPolicyProfile::Production,
            signers: sorted(signer_keys.iter().map(trust_key_for).collect()),
            threshold,
        }
    }

    /// A minimal valid snapshot for genesis-approval tests, with the
    /// credential-authority role covered by `trust_key_for(&[1; 32])`.
    fn snapshot() -> TrustListSnapshotV1 {
        let role = TrustRole::CredentialAuthority;
        TrustListSnapshotV1 {
            format_version: 1,
            sequence: 1,
            issued_at: 1_700_000_000,
            expires_at: 1_700_090_000,
            activation_at: 1_700_000_500,
            previous_snapshot_digest: None,
            active_roles: BTreeSet::from([role]),
            entries: vec![olympus_crypto::trust_list::TrustedIssuerEntry {
                pubkey: trust_key_for(&[1u8; 32]),
                roles: BTreeSet::from([role]),
                valid_from: 1_700_000_100,
                valid_until: 1_700_080_000,
            }],
            rotation_policies: BTreeMap::from([(
                role,
                rotation_policy(&[[10u8; 32], [11u8; 32]], 2),
            )]),
            recovery_keys: BTreeMap::from([(role, trust_key_for(&[200u8; 32]))]),
        }
    }

    fn genesis_policy(signer_keys: &[[u8; 32]], threshold: u16) -> GenesisApprovalPolicy {
        GenesisApprovalPolicy {
            profile: olympus_crypto::trust_list::RotationPolicyProfile::Production,
            signers: sorted(signer_keys.iter().map(trust_key_for).collect()),
            threshold,
        }
    }

    #[test]
    fn trust_pubkey_conversion_is_canonical_and_fallible() {
        let key = trust_key_for(&[1u8; 32]);
        let signer = quorum_signer_from_trust_pubkey(&key).expect("canonical key converts");
        // The decimal identity must be the canonical form `normalize_signer`
        // accepts (parse → format round-trips to itself).
        assert_eq!(
            fr_to_decimal(&parse_fr(&signer.x).expect("parses")),
            signer.x
        );
        assert_eq!(
            fr_to_decimal(&parse_fr(&signer.y).expect("parses")),
            signer.y
        );

        // A non-canonical coordinate (>= r) is rejected, never reduced.
        let non_canonical = TrustPubKey::new([0xFF; 32], key.y);
        assert_eq!(
            quorum_signer_from_trust_pubkey(&non_canonical),
            Err(TrustQuorumError::NonCanonicalTrustPubKey)
        );
    }

    #[test]
    fn rotation_approval_verifies_against_the_prior_policy() {
        let (k1, k2, k3) = ([10u8; 32], [11u8; 32], [12u8; 32]);
        let policy = rotation_policy(&[k1, k2, k3], 2);
        let prev = [0x11u8; 32];
        let next = [0x22u8; 32];

        let sigs = vec![
            approve_trust_rotation(&k1, &prev, &next, 4, 5, 1_700_000_000).expect("sign"),
            approve_trust_rotation(&k2, &prev, &next, 4, 5, 1_700_000_000).expect("sign"),
        ];
        let status =
            verify_trust_rotation_approval(&policy, &prev, &next, 4, 5, 1_700_000_000, &sigs)
                .expect("verify");
        assert_eq!(status.total_signers, 3);
        assert_eq!(status.valid_signatures, 2);
        assert!(status.satisfied);

        // One signature short of the threshold is not satisfied.
        let short =
            verify_trust_rotation_approval(&policy, &prev, &next, 4, 5, 1_700_000_000, &sigs[..1])
                .expect("verify");
        assert_eq!(short.valid_signatures, 1);
        assert!(!short.satisfied);

        // An approval over a different transition (next sequence bumped) is
        // worth nothing against this one — the message binds the transition.
        let other = vec![
            approve_trust_rotation(&k1, &prev, &next, 5, 6, 1_700_000_000).expect("sign"),
            approve_trust_rotation(&k2, &prev, &next, 5, 6, 1_700_000_000).expect("sign"),
        ];
        let replayed =
            verify_trust_rotation_approval(&policy, &prev, &next, 4, 5, 1_700_000_000, &other)
                .expect("verify");
        assert_eq!(replayed.valid_signatures, 0);
        assert!(!replayed.satisfied);

        // ...and so is one over a different activation_at.
        let other_activation = vec![
            approve_trust_rotation(&k1, &prev, &next, 4, 5, 1_700_000_001).expect("sign"),
            approve_trust_rotation(&k2, &prev, &next, 4, 5, 1_700_000_001).expect("sign"),
        ];
        let replayed = verify_trust_rotation_approval(
            &policy,
            &prev,
            &next,
            4,
            5,
            1_700_000_000,
            &other_activation,
        )
        .expect("verify");
        assert_eq!(replayed.valid_signatures, 0);
    }

    #[test]
    fn rotation_approval_rejects_an_invalid_pinned_policy() {
        // Threshold above the signer count: the policy itself is the broken
        // input, so the verifier errors instead of counting anything.
        let mut policy = rotation_policy(&[[10u8; 32], [11u8; 32]], 2);
        policy.threshold = 3;
        let result = verify_trust_rotation_approval(
            &policy,
            &[0x11; 32],
            &[0x22; 32],
            4,
            5,
            1_700_000_000,
            &[],
        );
        assert!(
            matches!(
                result,
                Err(TrustQuorumError::InvalidPolicy(
                    olympus_crypto::trust_list::TrustListError::ThresholdOutOfRange { .. }
                ))
            ),
            "expected ThresholdOutOfRange, got {result:?}"
        );
    }

    #[test]
    fn recovery_approval_is_one_of_one_under_the_pinned_key_only() {
        let recovery_priv = [200u8; 32];
        let routine_priv = [10u8; 32];
        let pinned = trust_key_for(&recovery_priv);
        let prev = [0x11u8; 32];
        let next = [0x22u8; 32];
        let args = (
            TrustRole::CredentialAuthority,
            RecoveryReason::QuorumCompromise,
            1_700_000_000i64,
        );

        let sig =
            approve_trust_recovery(&recovery_priv, args.0, &prev, &next, 4, 5, args.1, args.2)
                .expect("sign");
        let status = verify_trust_recovery_approval(
            &pinned,
            args.0,
            &prev,
            &next,
            4,
            5,
            args.1,
            args.2,
            std::slice::from_ref(&sig),
        )
        .expect("verify");
        assert_eq!(status.threshold, 1);
        assert_eq!(status.total_signers, 1);
        assert!(status.satisfied);

        // A routine-quorum member signing the same recovery message does not
        // count: it is not the pinned recovery key (security invariant 12).
        let routine_sig =
            approve_trust_recovery(&routine_priv, args.0, &prev, &next, 4, 5, args.1, args.2)
                .expect("sign");
        let routine_only = verify_trust_recovery_approval(
            &pinned,
            args.0,
            &prev,
            &next,
            4,
            5,
            args.1,
            args.2,
            &[routine_sig],
        )
        .expect("verify");
        assert_eq!(routine_only.valid_signatures, 0);
        assert!(!routine_only.satisfied);

        // A recovery approval for one role does not verify for another role
        // over the same transition — the message binds the role.
        let wrong_role = verify_trust_recovery_approval(
            &pinned,
            TrustRole::CheckpointAuthority,
            &prev,
            &next,
            4,
            5,
            args.1,
            args.2,
            &[sig],
        )
        .expect("verify");
        assert_eq!(wrong_role.valid_signatures, 0);
    }

    #[test]
    fn genesis_approval_binds_snapshot_and_policy() {
        let (k1, k2) = ([20u8; 32], [21u8; 32]);
        let policy = genesis_policy(&[k1, k2], 2);
        let snap = snapshot();

        let sigs = vec![
            approve_trust_genesis(&k1, &snap, &policy).expect("sign"),
            approve_trust_genesis(&k2, &snap, &policy).expect("sign"),
        ];
        let status = verify_trust_genesis_approval(&policy, &snap, &sigs).expect("verify");
        assert_eq!(status.valid_signatures, 2);
        assert!(status.satisfied);

        // Duplicate signatures from one signer count once.
        let dup = vec![sigs[0].clone(), sigs[0].clone()];
        let dup_status = verify_trust_genesis_approval(&policy, &snap, &dup).expect("verify");
        assert_eq!(dup_status.valid_signatures, 1);
        assert!(!dup_status.satisfied);

        // The same signers approving a *different* snapshot body count zero
        // here (genesis replay onto another payload, ADR-0041 §8).
        let mut other_snap = snap.clone();
        other_snap.activation_at += 1;
        let other = vec![
            approve_trust_genesis(&k1, &other_snap, &policy).expect("sign"),
            approve_trust_genesis(&k2, &other_snap, &policy).expect("sign"),
        ];
        let replayed = verify_trust_genesis_approval(&policy, &snap, &other).expect("verify");
        assert_eq!(replayed.valid_signatures, 0);

        // ...and approvals over the same snapshot under a different signer
        // set count zero — the signer set is bound.
        let mut policy_with_extra = policy.clone();
        policy_with_extra.signers = sorted(vec![
            trust_key_for(&k1),
            trust_key_for(&k2),
            trust_key_for(&[22u8; 32]),
        ]);
        let cross_policy =
            verify_trust_genesis_approval(&policy_with_extra, &snap, &sigs).expect("verify");
        assert_eq!(cross_policy.valid_signatures, 0);

        // ...and the threshold alone is bound too: same signers, threshold 3.
        let mut policy_with_higher_threshold = genesis_policy(&[k1, k2, [22u8; 32]], 3);
        policy_with_higher_threshold.signers = policy_with_extra.signers.clone();
        let cross_threshold =
            verify_trust_genesis_approval(&policy_with_higher_threshold, &snap, &sigs)
                .expect("verify");
        assert_eq!(cross_threshold.valid_signatures, 0);
    }

    /// ADR-0041 §5 regression: all five quorum domains routed through the
    /// shared verifier — SBT, checkpoint, rotation, recovery, genesis — are
    /// pairwise non-replayable. One signer signs once in each domain over
    /// inputs derived from the same bytes; each signature satisfies its own
    /// 1-of-1 domain and counts zero in the other four.
    #[test]
    fn all_five_domains_are_pairwise_non_replayable() {
        let priv_key = [42u8; 32];
        let trust_key = trust_key_for(&priv_key);
        let quorum_signer = quorum_signer_from_trust_pubkey(&trust_key).expect("convert");
        let signers = vec![quorum_signer.clone()];

        let commit_id = [0x33u8; 32];
        let prev = [0x11u8; 32];
        let next = [0x22u8; 32];
        let chain_id = Fr::from(1u64);
        let root = Fr::from_le_bytes_mod_order(&commit_id);
        let (role, reason, activation) = (
            TrustRole::CredentialAuthority,
            RecoveryReason::QuorumCompromise,
            1_700_000_000i64,
        );
        let recovery_policy = GenesisApprovalPolicy {
            profile: olympus_crypto::trust_list::RotationPolicyProfile::LocalOnly,
            signers: vec![trust_key],
            threshold: 1,
        };
        let snap = snapshot();

        // One signature per domain, all by the same key.
        let sbt_sig = {
            let msg = quorum_cosign_message(&commit_id, 1, &signers);
            let sig = baby_jubjub::sign(&priv_key, msg).expect("sign");
            CollectedSignature {
                signer: quorum_signer.clone(),
                r8x: fr_to_decimal(&sig.r8x),
                r8y: fr_to_decimal(&sig.r8y),
                s: fr_to_decimal(&sig.s),
            }
        };
        let checkpoint_sig = crate::quorum::checkpoint::cosign_checkpoint(
            &priv_key, &chain_id, 1, &root, 1, &signers,
        )
        .expect("sign");
        let rotation_sig =
            approve_trust_rotation(&priv_key, &prev, &next, 4, 5, activation).expect("sign");
        let recovery_sig =
            approve_trust_recovery(&priv_key, role, &prev, &next, 4, 5, reason, activation)
                .expect("sign");
        let genesis_sig = approve_trust_genesis(&priv_key, &snap, &recovery_policy).expect("sign");

        let labelled: [(&str, &CollectedSignature); 5] = [
            ("sbt", &sbt_sig),
            ("checkpoint", &checkpoint_sig),
            ("rotation", &rotation_sig),
            ("recovery", &recovery_sig),
            ("genesis", &genesis_sig),
        ];

        // Count how many valid signatures each domain's verifier sees for a
        // given single submitted signature.
        let count_in_domain = |domain: &str, sig: &CollectedSignature| -> usize {
            let sigs = std::slice::from_ref(sig);
            match domain {
                "sbt" => verify_quorum(&commit_id, &signers, 1, sigs).valid_signatures,
                "checkpoint" => {
                    crate::quorum::checkpoint::verify_checkpoint_quorum(
                        &chain_id, 1, &root, &signers, 1, sigs,
                    )
                    .valid_signatures
                }
                "rotation" => {
                    verify_trust_rotation_approval(
                        &RotationPolicy {
                            profile: olympus_crypto::trust_list::RotationPolicyProfile::LocalOnly,
                            signers: vec![trust_key_for(&priv_key)],
                            threshold: 1,
                        },
                        &prev,
                        &next,
                        4,
                        5,
                        activation,
                        sigs,
                    )
                    .expect("verify")
                    .valid_signatures
                }
                "recovery" => {
                    verify_trust_recovery_approval(
                        &trust_key_for(&priv_key),
                        role,
                        &prev,
                        &next,
                        4,
                        5,
                        reason,
                        activation,
                        sigs,
                    )
                    .expect("verify")
                    .valid_signatures
                }
                "genesis" => {
                    verify_trust_genesis_approval(&recovery_policy, &snap, sigs)
                        .expect("verify")
                        .valid_signatures
                }
                other => unreachable!("unknown domain {other}"),
            }
        };

        for (signed_domain, sig) in labelled {
            for (verifying_domain, _) in labelled {
                let count = count_in_domain(verifying_domain, sig);
                if signed_domain == verifying_domain {
                    assert_eq!(
                        count, 1,
                        "a {signed_domain} approval must verify in its own domain"
                    );
                } else {
                    assert_eq!(
                        count, 0,
                        "a {signed_domain} approval must NOT verify in the \
                         {verifying_domain} domain"
                    );
                }
            }
        }
    }

    /// Pin the exact `Fr` messages the SBT and checkpoint domains produce for
    /// fixed inputs. The trust constructors share `verify_generic_quorum`
    /// with these two domains, so this guards the "existing SBT and
    /// checkpoint message construction and behavior remain unchanged"
    /// half of ADR-0041 §5 at the message level — any refactor of the shared
    /// core that perturbs either legacy message fails here loudly (the
    /// committed cross-language golden vectors are the end-to-end half).
    #[test]
    fn legacy_sbt_and_checkpoint_messages_are_unchanged_by_the_trust_domains() {
        let signers = vec![
            QuorumSigner {
                x: "7".into(),
                y: "8".into(),
            },
            QuorumSigner {
                x: "9".into(),
                y: "10".into(),
            },
        ];
        let sbt = quorum_cosign_message(&[0x5Au8; 32], 2, &signers);
        assert_eq!(
            fr_to_decimal(&sbt),
            "20192933143121735260623838180047851867270600891771514248241989857672050855723"
        );
        let checkpoint = crate::quorum::checkpoint::checkpoint_quorum_message(
            &Fr::from(3u64),
            77,
            &Fr::from(123_456u64),
            2,
            &signers,
        );
        assert_eq!(
            fr_to_decimal(&checkpoint),
            "10756056504285431600722430279846295815264550826016281055197336258237002114272"
        );
    }
}
