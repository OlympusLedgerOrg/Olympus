// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Append-only persistence for ADR-0041 trust-list transitions
//! (migration `0063`): immutable candidates, lifecycle events, and the
//! monotonic accepted chain.
//!
//! # Lifecycle
//!
//! * [`stage_candidate`] validates a signed transition file — canonical
//!   encoding, snapshot invariants, freshness plausibility, and approval
//!   signatures under the **currently accepted** snapshot's policies — and
//!   inserts one immutable candidate row. Staging reserves no sequence slot
//!   (ADR-0041 §3): any number of candidates may target the same successor
//!   slot.
//! * [`accept_candidate`] is the single serialised commitment point. Inside
//!   one transaction under a dedicated `pg_advisory_xact_lock` (the H-4
//!   pattern `smt::backend` established: `READ COMMITTED` pinned so the
//!   post-lock reads observe the prior writer's commit, `lock_timeout` so a
//!   stuck peer surfaces as an error rather than a hang), it re-validates
//!   authorization against the chain tip *as of the lock*, acquires the
//!   successor-uniqueness constraints, appends the `accepted` event, and
//!   advances the accepted-state marker. A losing candidate gets a terminal
//!   event — `superseded` with the winning candidate's reference, or
//!   `rejected` with the stable reason — and its immutable row is never
//!   touched.
//! * [`activate_transition`] appends the `activated` event once ADR-0041
//!   §3's six activation preconditions hold. Startup reconciliation
//!   ([`super::reconcile`]) drives it in sequence order.
//! * [`load_accepted_chain`] reconstructs current trust state from the
//!   immutable rows alone (security invariant 14) and **re-verifies**
//!   everything on every load: per-link digest recomputation from the
//!   decoded snapshot (never trusting stored JSON bytes or digest columns),
//!   chain contiguity and predecessor linkage, nondecreasing signed
//!   `activation_at`, and every link's approval signatures under its
//!   predecessor's policies. A database that has drifted from what was
//!   signed fails closed here, before any trust decision sees it.
//!
//! # Authorization rules (resolved ADR ambiguities are called out)
//!
//! A rotation is authorized under the **prior** snapshot's policies, never
//! the candidate's own (ADR-0041 §2 — self-authorization is structurally
//! impossible because the candidate's policies are simply never consulted).
//! "Affected role" is defined as any role whose canonical per-role
//! projection (`project_role`, ADR-0041 §7) differs between predecessor and
//! candidate. Two cases the ADR does not spell out are pinned here, both
//! fail-closed:
//!
//! * **Role introduction** — an affected role with no policy in the prior
//!   snapshot (the role is being introduced) cannot be authorized by its own
//!   not-yet-accepted policy, and a vacuous pass would let anyone graft new
//!   role content. Such a transition instead requires the approval set to
//!   satisfy **every** role policy active in the prior snapshot: expanding
//!   the governed role set is a whole-system decision.
//! * **Envelope-only rotations** — a rotation whose projections all match
//!   the predecessor's (only `issued_at`/`expires_at`/`activation_at`
//!   moved) re-freshens the list for every role, so it likewise requires
//!   every prior active role's policy. Without this, an expiry extension
//!   would need no signatures at all — a freshness-reset bypass.

use std::collections::BTreeMap;

use olympus_crypto::trust_list::{
    project_role, snapshot_digest, RotationPolicy, RotationPolicyProfile, TrustListError,
    TrustListSnapshotV1, TrustRole, TrustTransitionKind,
};
use olympus_crypto::trust_wire::{
    ThresholdPolicyWire, TrustApprovalWire, TrustSnapshotWireV1, TrustTransitionFile,
    TrustWireError,
};
use sqlx::{PgConnection, PgPool};
use thiserror::Error;
use uuid::Uuid;

use super::config::{snapshot_freshness_violation, FreshnessViolation, TrustFreshnessConfig};
use crate::quorum::trust::{
    verify_trust_genesis_approval, verify_trust_genesis_approval_with_identities,
    verify_trust_recovery_approval, verify_trust_recovery_approval_with_identities,
    verify_trust_rotation_approval, verify_trust_rotation_approval_with_identities,
    TrustQuorumError,
};
use crate::quorum::{CollectedSignature, QuorumSigner};

/// Advisory-lock key serialising trust-transition acceptance + activation.
/// Same distinctive range as `smt::backend::SMT_WRITE_LOCK_KEY`
/// (`…5330`, "OLYMPUS0"); this is "OLYMPUS1" so the two subsystems never
/// contend with each other.
pub(crate) const TRUST_ACCEPT_LOCK_KEY: i64 = 0x4F4C_594D_5055_5331_u64 as i64;

/// Typed failure reasons. Negative tests assert these variants — the stable
/// reason codes ADR-0041 §11 asks the logs to carry are the variant names.
#[derive(Debug, Error)]
pub enum TrustTransitionError {
    // ── candidate / wire integrity ────────────────────────────────────────
    #[error("snapshot validation failed: {0}")]
    SnapshotInvalid(#[from] TrustListError),
    #[error("stored transition JSON failed to decode: {0}")]
    WireInvalid(#[from] TrustWireError),
    #[error("stored transition JSON failed to deserialize: {0}")]
    StoredJsonInvalid(#[from] serde_json::Error),
    #[error("no trust-transition candidate {0} exists")]
    CandidateNotFound(Uuid),
    #[error(
        "candidate {candidate_id} stored digest {stored} disagrees with the digest \
         recomputed from its canonical snapshot body ({recomputed}) — storage corruption"
    )]
    CandidateDigestMismatch {
        candidate_id: Uuid,
        stored: String,
        recomputed: String,
    },
    #[error("sequence {0} exceeds the storable range")]
    SequenceOutOfRange(u64),

    // ── transition-shape rejections (ADR-0041 §4) ─────────────────────────
    #[error("no accepted genesis exists; only a genesis transition can be first")]
    NoAcceptedGenesis,
    #[error("an accepted genesis already exists (accepted sequence {accepted_sequence})")]
    GenesisAlreadyExists { accepted_sequence: u64 },
    #[error("genesis snapshot must have sequence 1 (got {sequence})")]
    GenesisSequenceNotOne { sequence: u64 },
    #[error("candidate sequence {candidate} does not advance beyond accepted sequence {accepted}")]
    RollbackToOlderSequence { candidate: u64, accepted: u64 },
    #[error(
        "candidate sequence {candidate} skips ahead of accepted sequence {accepted} \
         (successors must increment by exactly one)"
    )]
    SkippedSequence { candidate: u64, accepted: u64 },
    #[error(
        "candidate proposes sequence {sequence}, which is already accepted with a \
         different snapshot digest (same-sequence equivocation)"
    )]
    SameSequenceEquivocation { sequence: u64 },
    #[error(
        "candidate names predecessor digest {named:?} but the accepted predecessor \
         digest is {expected}"
    )]
    WrongPredecessorDigest {
        expected: String,
        named: Option<String>,
    },
    #[error(
        "signed activation_at {candidate} is earlier than the predecessor's signed \
         activation_at {predecessor} (retroactive activation ordering)"
    )]
    DecreasingActivationTime { predecessor: i64, candidate: i64 },
    #[error("snapshot fails the freshness window: {0}")]
    SnapshotNotFresh(#[from] FreshnessViolation),

    // ── authorization rejections ──────────────────────────────────────────
    #[error("trust-quorum verification input was invalid: {0}")]
    TrustQuorum(#[from] TrustQuorumError),
    #[error(
        "production refuses active role {role} governed by a local_only rotation policy \
         (ADR-0041 §2)"
    )]
    LocalOnlyPolicyInProduction { role: &'static str },
    #[error("production refuses a local_only genesis approval policy (ADR-0041 §8)")]
    LocalOnlyGenesisPolicyInProduction,
    #[error(
        "approvals satisfy {valid} of the {required} required signatures for role {role} \
         under the prior snapshot's policy"
    )]
    InsufficientRoleApprovals {
        role: &'static str,
        valid: usize,
        required: usize,
    },
    #[error(
        "rotation has no authorizing prior policy: the prior snapshot has no active \
         roles, so neither an affected policy-less role nor an envelope-only change \
         can be authorized"
    )]
    RotationHasNoAuthorizingPolicy,
    #[error("genesis approvals satisfy {valid} of the required {required} signatures")]
    InsufficientGenesisApprovals { valid: usize, required: usize },
    #[error("genesis transition carries no approval policy")]
    MissingGenesisApprovalPolicy,
    #[error("recovery transition carries no role/reason")]
    MissingRecoveryFields,
    #[error("prior snapshot pins no recovery key for role {role}")]
    RecoveryKeyNotPinned { role: &'static str },
    #[error("recovery approval for role {role} does not verify under the pinned recovery key")]
    InsufficientRecoveryApproval { role: &'static str },
    #[error(
        "recovery for role {recovering} modifies unrelated role {modified}'s canonical \
         projection (ADR-0041 §7 scope violation)"
    )]
    RecoveryScopeViolation {
        recovering: &'static str,
        modified: &'static str,
    },

    // ── acceptance / activation lifecycle ─────────────────────────────────
    #[error("candidate {candidate_id} is already accepted")]
    CandidateAlreadyAccepted { candidate_id: Uuid },
    #[error(
        "candidate {candidate_id} already carries a terminal {event_kind} event; \
         re-stage a new candidate instead (candidates are immutable, ADR-0041 §6)"
    )]
    CandidateTerminal {
        candidate_id: Uuid,
        event_kind: String,
    },
    #[error(
        "successor slot at sequence {sequence} is already owned by accepted candidate \
         {winner}; this candidate was superseded"
    )]
    SupersededByAcceptedWinner { winner: Uuid, sequence: u64 },
    #[error("candidate {candidate_id} is not accepted; only accepted transitions activate")]
    NotAccepted { candidate_id: Uuid },
    #[error("candidate {candidate_id} is already active")]
    AlreadyActivated { candidate_id: Uuid },
    #[error("predecessor at sequence {predecessor_sequence} is not the current Active snapshot")]
    PredecessorNotActive { predecessor_sequence: u64 },
    #[error("signed activation_at {activation_at} has not been reached (now {now})")]
    ActivationTimeNotReached { activation_at: i64, now: i64 },

    // ── accepted-chain integrity (reconstruction) ─────────────────────────
    #[error("accepted chain does not start with a genesis at sequence 1 (first is {first})")]
    ChainMissingGenesis { first: u64 },
    #[error("accepted chain has a gap: expected sequence {expected}, found {found}")]
    ChainSequenceGap { expected: u64, found: u64 },
    #[error("accepted chain linkage broken at sequence {sequence}: predecessor digest mismatch")]
    ChainLinkageBroken { sequence: u64 },
    #[error(
        "accepted row at sequence {sequence} disagrees with its signed snapshot on {field} — \
         no unsigned database field may override the signed value"
    )]
    ChainRowDisagreesWithSignedSnapshot { sequence: u64, field: &'static str },
    #[error("accepted chain violates nondecreasing signed activation_at at sequence {sequence}")]
    ChainActivationOrderViolation { sequence: u64 },
    #[error(
        "accepted chain has an activation gap at sequence {sequence}: a successor is \
         activated while its predecessor is not"
    )]
    ChainActivationGap { sequence: u64 },
    #[error("accepted link at sequence {sequence} fails authorization re-verification: {reason}")]
    ChainAuthorizationInvalid { sequence: u64, reason: String },

    // ── startup reconciliation ────────────────────────────────────────────
    #[error("required trust freshness configuration is missing or invalid in production: {0:?}")]
    MissingFreshnessConfig(Vec<String>),
    #[error(
        "no fresh Active trust snapshot could be established \
         (earliest pending activation_at: {earliest_pending_activation:?})"
    )]
    NoFreshActiveSnapshot {
        earliest_pending_activation: Option<i64>,
    },

    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

/// Result of [`stage_candidate`].
#[derive(Debug, Clone)]
pub struct StagedCandidate {
    pub candidate_id: Uuid,
    pub next_sequence: u64,
    pub next_snapshot_digest: [u8; 32],
}

/// One accepted (and possibly activated) link of the trust chain, fully
/// re-verified by [`load_accepted_chain`].
#[derive(Debug, Clone)]
pub struct AcceptedLink {
    pub candidate_id: Uuid,
    pub kind: TrustTransitionKind,
    pub sequence: u64,
    pub digest: [u8; 32],
    pub previous_digest: Option<[u8; 32]>,
    pub activation_at: i64,
    pub snapshot: TrustListSnapshotV1,
    pub activated: bool,
}

/// The reconstructed accepted chain, ordered by sequence starting at 1.
#[derive(Debug, Clone, Default)]
pub struct AcceptedChain {
    pub links: Vec<AcceptedLink>,
}

impl AcceptedChain {
    /// The accepted tip — the snapshot new transitions are authorized under
    /// (ADR-0041 §2's "currently accepted snapshot"), Active or not.
    pub fn tip(&self) -> Option<&AcceptedLink> {
        self.links.last()
    }

    /// Number of activated links. The loader guarantees activation is a
    /// prefix of the chain, so this doubles as the index of the next link
    /// eligible for activation.
    pub fn active_len(&self) -> usize {
        self.links.iter().take_while(|l| l.activated).count()
    }

    /// The current Active snapshot: the last link of the activated prefix.
    pub fn active(&self) -> Option<&AcceptedLink> {
        match self.active_len() {
            0 => None,
            n => Some(&self.links[n - 1]),
        }
    }
}

/// ADR-0041 §2: the wire tag of the first *active* role governed by a
/// `local_only` rotation policy in `snapshot`, if any. Production refuses to
/// operate under such a role — a locally-verified policy has no quorum peers
/// to catch a compromised or careless single operator. Shared by every
/// checkpoint that must enforce this in production: candidate validation
/// ([`validate_transition`]), activation ([`activate_transition`]), and
/// startup reconciliation's final judgment of an already-Active snapshot
/// ([`super::reconcile::reconcile_at_startup`]) — the three checkpoints
/// together cover a role that starts, stays, or is discovered LocalOnly,
/// since none of them re-runs another's work.
pub(crate) fn local_only_active_role(snapshot: &TrustListSnapshotV1) -> Option<&'static str> {
    snapshot
        .rotation_policies
        .iter()
        .find_map(|(role, policy)| {
            (snapshot.active_roles.contains(role)
                && policy.profile == RotationPolicyProfile::LocalOnly)
                .then(|| role.wire_tag())
        })
}

fn hex_digest(digest: &[u8; 32]) -> String {
    hex::encode(digest)
}

fn sequence_to_db(sequence: u64) -> Result<i64, TrustTransitionError> {
    i64::try_from(sequence).map_err(|_| TrustTransitionError::SequenceOutOfRange(sequence))
}

fn approvals_to_collected(approvals: &[TrustApprovalWire]) -> Vec<CollectedSignature> {
    approvals
        .iter()
        .map(|a| CollectedSignature {
            signer: QuorumSigner {
                x: a.x.clone(),
                y: a.y.clone(),
            },
            r8x: a.r8x.clone(),
            r8y: a.r8y.clone(),
            s: a.s.clone(),
        })
        .collect()
}

// ── Pure validation core ──────────────────────────────────────────────────

/// The prior policies a rotation must satisfy, per the rules in the module
/// docs: every affected role's prior policy; widened to every prior active
/// role's policy for role introductions and envelope-only rotations.
fn required_rotation_policies<'prev>(
    prev: &'prev TrustListSnapshotV1,
    next: &TrustListSnapshotV1,
) -> Result<BTreeMap<TrustRole, &'prev RotationPolicy>, TrustTransitionError> {
    let affected: Vec<TrustRole> = TrustRole::ALL
        .into_iter()
        .filter(|role| project_role(prev, *role) != project_role(next, *role))
        .collect();

    let mut require_full_prior_set = affected.is_empty();
    let mut required: BTreeMap<TrustRole, &RotationPolicy> = BTreeMap::new();
    for role in &affected {
        match prev.rotation_policies.get(role) {
            Some(policy) => {
                required.insert(*role, policy);
            }
            None => require_full_prior_set = true,
        }
    }
    if require_full_prior_set {
        if prev.active_roles.is_empty() {
            return Err(TrustTransitionError::RotationHasNoAuthorizingPolicy);
        }
        for role in &prev.active_roles {
            // A validated snapshot pins a policy for every active role; a
            // missing one here means the prior snapshot itself is broken.
            let policy = prev
                .rotation_policies
                .get(role)
                .ok_or(TrustListError::RoleMissingPolicy(role.wire_tag()))?;
            required.insert(*role, policy);
        }
    }
    Ok(required)
}

/// Successor-shape checks shared by rotation and recovery (ADR-0041 §1/§3/§4).
fn check_successor_shape(
    tip: &AcceptedLink,
    next: &TrustListSnapshotV1,
) -> Result<(), TrustTransitionError> {
    if next.sequence == tip.sequence {
        // An identical digest would be a byte-identical re-submission of the
        // accepted transition; the acceptance path reports that as
        // already-accepted/superseded with a winner reference. Here the
        // *snapshot content* differs at an accepted sequence — equivocation.
        if snapshot_digest(next) != tip.digest {
            return Err(TrustTransitionError::SameSequenceEquivocation {
                sequence: next.sequence,
            });
        }
        return Err(TrustTransitionError::RollbackToOlderSequence {
            candidate: next.sequence,
            accepted: tip.sequence,
        });
    }
    if next.sequence < tip.sequence {
        return Err(TrustTransitionError::RollbackToOlderSequence {
            candidate: next.sequence,
            accepted: tip.sequence,
        });
    }
    if next.sequence > tip.sequence + 1 {
        return Err(TrustTransitionError::SkippedSequence {
            candidate: next.sequence,
            accepted: tip.sequence,
        });
    }
    if next.previous_snapshot_digest != Some(tip.digest) {
        return Err(TrustTransitionError::WrongPredecessorDigest {
            expected: hex_digest(&tip.digest),
            named: next.previous_snapshot_digest.as_ref().map(hex_digest),
        });
    }
    if next.activation_at < tip.activation_at {
        return Err(TrustTransitionError::DecreasingActivationTime {
            predecessor: tip.activation_at,
            candidate: next.activation_at,
        });
    }
    Ok(())
}

/// What a successful validation pins for the immutable candidate row:
/// the recomputed digest, plus the authorization context and verification
/// result JSON (ADR-0041 §6's required record fields).
struct ValidatedTransition {
    digest: [u8; 32],
    authorization_json: serde_json::Value,
    verification_json: serde_json::Value,
}

/// Validate `file` as a transition on top of `tip` (ADR-0041 §1–§8). Pure
/// with respect to the database — callers pass the tip they are validating
/// against, which is what makes acceptance's under-lock re-validation the
/// same code path as staging's advisory check.
fn validate_transition(
    tip: Option<&AcceptedLink>,
    file: &TrustTransitionFile,
    now: i64,
    config: &TrustFreshnessConfig,
    is_prod: bool,
) -> Result<ValidatedTransition, TrustTransitionError> {
    let snapshot = &file.snapshot;
    snapshot.validate(config.max_lifetime.seconds())?;
    if let Some(violation) = snapshot_freshness_violation(snapshot, now, config) {
        return Err(violation.into());
    }
    if is_prod {
        // ADR-0041 §2: production rejects any *active* role governed by a
        // local_only policy. (The separately named local-only deployment
        // mode does not exist yet; when the genesis CLI lands it will thread
        // an explicit override here rather than weakening this default.)
        if let Some(role) = local_only_active_role(snapshot) {
            return Err(TrustTransitionError::LocalOnlyPolicyInProduction { role });
        }
    }

    let digest = snapshot_digest(snapshot);
    let collected = approvals_to_collected(&file.approvals);

    match file.kind {
        TrustTransitionKind::Genesis => {
            if let Some(tip) = tip {
                return Err(TrustTransitionError::GenesisAlreadyExists {
                    accepted_sequence: tip.sequence,
                });
            }
            if snapshot.sequence != 1 {
                return Err(TrustTransitionError::GenesisSequenceNotOne {
                    sequence: snapshot.sequence,
                });
            }
            let policy = file
                .genesis_approval_policy
                .as_ref()
                .ok_or(TrustTransitionError::MissingGenesisApprovalPolicy)?;
            if is_prod && policy.profile == RotationPolicyProfile::LocalOnly {
                return Err(TrustTransitionError::LocalOnlyGenesisPolicyInProduction);
            }
            let (status, valid_signer_ids) =
                verify_trust_genesis_approval_with_identities(policy, snapshot, &collected)?;
            if !status.satisfied {
                return Err(TrustTransitionError::InsufficientGenesisApprovals {
                    valid: status.valid_signatures,
                    required: status.threshold,
                });
            }
            Ok(ValidatedTransition {
                digest,
                authorization_json: serde_json::json!({
                    "genesis_approval_policy": ThresholdPolicyWire::from_genesis_policy(policy),
                }),
                // ADR-0041 §6: the candidate record must name the submitted
                // signatures AND the valid signer identities, not merely a
                // count — `valid_signer_ids` is the exact `(x, y)` set
                // `verify_trust_genesis_approval_with_identities` counted.
                verification_json: serde_json::json!({
                    "genesis": { "status": status, "valid_signer_ids": valid_signer_ids },
                }),
            })
        }
        TrustTransitionKind::Rotation => {
            let tip = tip.ok_or(TrustTransitionError::NoAcceptedGenesis)?;
            check_successor_shape(tip, snapshot)?;
            let required = required_rotation_policies(&tip.snapshot, snapshot)?;
            let mut statuses = Vec::with_capacity(required.len());
            for (role, policy) in &required {
                let (status, valid_signer_ids) = verify_trust_rotation_approval_with_identities(
                    policy,
                    &tip.digest,
                    &digest,
                    tip.sequence,
                    snapshot.sequence,
                    snapshot.activation_at,
                    &collected,
                )?;
                if !status.satisfied {
                    return Err(TrustTransitionError::InsufficientRoleApprovals {
                        role: role.wire_tag(),
                        valid: status.valid_signatures,
                        required: status.threshold,
                    });
                }
                statuses.push(serde_json::json!({
                    "role": role.wire_tag(),
                    "status": status,
                    "valid_signer_ids": valid_signer_ids,
                }));
            }
            Ok(ValidatedTransition {
                digest,
                authorization_json: serde_json::json!({
                    "previous_sequence": tip.sequence,
                    "previous_snapshot_digest": hex_digest(&tip.digest),
                    "required_policies": required
                        .iter()
                        .map(|(role, policy)| serde_json::json!({
                            "role": role.wire_tag(),
                            "policy": ThresholdPolicyWire::from_rotation_policy(policy),
                        }))
                        .collect::<Vec<_>>(),
                }),
                verification_json: serde_json::json!({ "rotation": statuses }),
            })
        }
        TrustTransitionKind::Recovery => {
            let tip = tip.ok_or(TrustTransitionError::NoAcceptedGenesis)?;
            check_successor_shape(tip, snapshot)?;
            let (role, reason) = file
                .recovery
                .ok_or(TrustTransitionError::MissingRecoveryFields)?;
            // ADR-0041 §7: a role-specific recovery key may modify only the
            // recovering role's canonical effective projection.
            for unrelated in TrustRole::ALL {
                if unrelated == role {
                    continue;
                }
                if project_role(&tip.snapshot, unrelated) != project_role(snapshot, unrelated) {
                    return Err(TrustTransitionError::RecoveryScopeViolation {
                        recovering: role.wire_tag(),
                        modified: unrelated.wire_tag(),
                    });
                }
            }
            let pinned = tip.snapshot.recovery_keys.get(&role).ok_or(
                TrustTransitionError::RecoveryKeyNotPinned {
                    role: role.wire_tag(),
                },
            )?;
            let (status, valid_signer_ids) = verify_trust_recovery_approval_with_identities(
                pinned,
                role,
                &tip.digest,
                &digest,
                tip.sequence,
                snapshot.sequence,
                reason,
                snapshot.activation_at,
                &collected,
            )?;
            if !status.satisfied {
                return Err(TrustTransitionError::InsufficientRecoveryApproval {
                    role: role.wire_tag(),
                });
            }
            Ok(ValidatedTransition {
                digest,
                authorization_json: serde_json::json!({
                    "previous_sequence": tip.sequence,
                    "previous_snapshot_digest": hex_digest(&tip.digest),
                    "recovery_role": role.wire_tag(),
                    "recovery_reason": reason.wire_tag(),
                    "recovery_key": olympus_crypto::trust_wire::TrustPubKeyWire::from_key(pinned),
                }),
                verification_json: serde_json::json!({
                    "recovery": { "status": status, "valid_signer_ids": valid_signer_ids },
                }),
            })
        }
    }
}

// ── Candidate rows ────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct CandidateRow {
    candidate_id: Uuid,
    kind: String,
    next_sequence: i64,
    next_snapshot_digest: String,
    snapshot_json: serde_json::Value,
    approvals_json: serde_json::Value,
    authorization_json: serde_json::Value,
    recovery_role: Option<String>,
    recovery_reason: Option<String>,
}

impl CandidateRow {
    /// Rehydrate the transition file from the immutable row, recomputing the
    /// snapshot digest from the decoded canonical body and refusing a row
    /// whose stored digest disagrees (storage corruption / tamper).
    fn decode(&self) -> Result<(TrustTransitionFile, [u8; 32]), TrustTransitionError> {
        let kind = TrustTransitionKind::from_wire_tag(&self.kind)
            .ok_or_else(|| TrustWireError::UnknownKindTag(self.kind.clone()))?;
        let snapshot_wire: TrustSnapshotWireV1 =
            serde_json::from_value(self.snapshot_json.clone())?;
        let snapshot = snapshot_wire.try_into_snapshot()?;
        let approvals: Vec<TrustApprovalWire> =
            serde_json::from_value(self.approvals_json.clone())?;
        let recovery = match (kind, &self.recovery_role, &self.recovery_reason) {
            (TrustTransitionKind::Recovery, Some(role), Some(reason)) => Some((
                TrustRole::from_wire_tag(role)
                    .ok_or_else(|| TrustWireError::UnknownRoleTag(role.clone()))?,
                olympus_crypto::trust_list::RecoveryReason::from_wire_tag(reason)
                    .ok_or_else(|| TrustWireError::UnknownReasonTag(reason.clone()))?,
            )),
            (TrustTransitionKind::Recovery, _, _) => {
                return Err(TrustTransitionError::MissingRecoveryFields)
            }
            _ => None,
        };
        let genesis_approval_policy = match kind {
            TrustTransitionKind::Genesis => Some(
                serde_json::from_value::<ThresholdPolicyWire>(
                    self.authorization_json
                        .get("genesis_approval_policy")
                        .cloned()
                        .ok_or(TrustTransitionError::MissingGenesisApprovalPolicy)?,
                )?
                .try_into_genesis_policy()?,
            ),
            _ => None,
        };

        let digest = snapshot_digest(&snapshot);
        if hex_digest(&digest) != self.next_snapshot_digest {
            return Err(TrustTransitionError::CandidateDigestMismatch {
                candidate_id: self.candidate_id,
                stored: self.next_snapshot_digest.clone(),
                recomputed: hex_digest(&digest),
            });
        }
        // No unsigned column may override a signed value (ADR-0041 §3) — the
        // same rule `load_accepted_chain_conn` applies to accepted rows.
        // `accept_candidate` probes the successor slot with this unsigned
        // `next_sequence` column but inserts the signed `snapshot.sequence`;
        // if they disagreed, the slot probe would read the wrong slot and
        // surface as an untyped DB unique-constraint error instead of this
        // typed one.
        if u64::try_from(self.next_sequence).ok() != Some(snapshot.sequence) {
            return Err(TrustTransitionError::ChainRowDisagreesWithSignedSnapshot {
                sequence: snapshot.sequence,
                field: "next_sequence",
            });
        }

        Ok((
            TrustTransitionFile {
                kind,
                snapshot,
                approvals,
                recovery,
                genesis_approval_policy,
            },
            digest,
        ))
    }
}

async fn fetch_candidate(
    conn: &mut PgConnection,
    candidate_id: Uuid,
) -> Result<CandidateRow, TrustTransitionError> {
    let row: Option<CandidateRow> = sqlx::query_as(
        "SELECT candidate_id, kind, next_sequence, next_snapshot_digest,
                snapshot_json, approvals_json, authorization_json,
                recovery_role, recovery_reason
           FROM trust_transition_candidates
          WHERE candidate_id = $1",
    )
    .bind(candidate_id)
    .fetch_optional(&mut *conn)
    .await?;
    row.ok_or(TrustTransitionError::CandidateNotFound(candidate_id))
}

async fn append_event(
    conn: &mut PgConnection,
    candidate_id: Uuid,
    event_kind: &str,
    reason: Option<&str>,
    winning_candidate_id: Option<Uuid>,
) -> Result<(), TrustTransitionError> {
    sqlx::query(
        "INSERT INTO trust_candidate_events
             (event_id, candidate_id, event_kind, reason, winning_candidate_id)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(candidate_id)
    .bind(event_kind)
    .bind(reason)
    .bind(winning_candidate_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

// ── Chain loading / reconstruction ────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct AcceptedRow {
    candidate_id: Uuid,
    kind: String,
    next_sequence: i64,
    next_snapshot_digest: String,
    previous_snapshot_digest: Option<String>,
    activation_at: i64,
    snapshot_json: serde_json::Value,
    approvals_json: serde_json::Value,
    authorization_json: serde_json::Value,
    recovery_role: Option<String>,
    recovery_reason: Option<String>,
    activated: bool,
}

/// Reconstruct and fully re-verify the accepted chain from the immutable
/// rows (security invariant 14). See the module docs for everything this
/// checks; the returned links are safe to authorize against.
pub async fn load_accepted_chain(pool: &PgPool) -> Result<AcceptedChain, TrustTransitionError> {
    let mut conn = pool.acquire().await?;
    load_accepted_chain_conn(&mut conn).await
}

async fn load_accepted_chain_conn(
    conn: &mut PgConnection,
) -> Result<AcceptedChain, TrustTransitionError> {
    let rows: Vec<AcceptedRow> = sqlx::query_as(
        "SELECT a.candidate_id, c.kind, a.next_sequence, a.next_snapshot_digest,
                a.previous_snapshot_digest, a.activation_at,
                c.snapshot_json, c.approvals_json, c.authorization_json,
                c.recovery_role, c.recovery_reason,
                EXISTS(
                    SELECT 1 FROM trust_candidate_events e
                     WHERE e.candidate_id = a.candidate_id
                       AND e.event_kind = 'activated'
                ) AS activated
           FROM trust_accepted_transitions a
           JOIN trust_transition_candidates c USING (candidate_id)
          ORDER BY a.next_sequence ASC",
    )
    .fetch_all(&mut *conn)
    .await?;

    let mut links: Vec<AcceptedLink> = Vec::with_capacity(rows.len());
    for row in rows {
        let candidate = CandidateRow {
            candidate_id: row.candidate_id,
            kind: row.kind.clone(),
            next_sequence: row.next_sequence,
            next_snapshot_digest: row.next_snapshot_digest.clone(),
            snapshot_json: row.snapshot_json.clone(),
            approvals_json: row.approvals_json.clone(),
            authorization_json: row.authorization_json.clone(),
            recovery_role: row.recovery_role.clone(),
            recovery_reason: row.recovery_reason.clone(),
        };
        // Decode + digest recomputation (never trust stored bytes).
        let (file, digest) = candidate.decode()?;
        let snapshot = file.snapshot.clone();
        let sequence = snapshot.sequence;

        // The accepted row's own columns must agree with the signed snapshot
        // — an unsigned column can never override a signed value (ADR-0041 §3).
        let row_sequence = u64::try_from(row.next_sequence)
            .map_err(|_| TrustTransitionError::SequenceOutOfRange(0))?;
        if row_sequence != sequence {
            return Err(TrustTransitionError::ChainRowDisagreesWithSignedSnapshot {
                sequence,
                field: "next_sequence",
            });
        }
        if row.activation_at != snapshot.activation_at {
            return Err(TrustTransitionError::ChainRowDisagreesWithSignedSnapshot {
                sequence,
                field: "activation_at",
            });
        }
        if row.previous_snapshot_digest
            != snapshot.previous_snapshot_digest.as_ref().map(hex_digest)
        {
            return Err(TrustTransitionError::ChainRowDisagreesWithSignedSnapshot {
                sequence,
                field: "previous_snapshot_digest",
            });
        }

        // Historical snapshots must still be self-consistent. Freshness is
        // deliberately NOT checked here — a superseded link being old is the
        // normal case; only the Active snapshot is freshness-gated (by the
        // resolver and reconciliation).
        snapshot
            .validate(None)
            .map_err(TrustTransitionError::SnapshotInvalid)?;

        // Chain shape.
        match links.last() {
            None => {
                if sequence != 1 || file.kind != TrustTransitionKind::Genesis {
                    return Err(TrustTransitionError::ChainMissingGenesis { first: sequence });
                }
            }
            Some(prev) => {
                if sequence != prev.sequence + 1 {
                    return Err(TrustTransitionError::ChainSequenceGap {
                        expected: prev.sequence + 1,
                        found: sequence,
                    });
                }
                if snapshot.previous_snapshot_digest != Some(prev.digest) {
                    return Err(TrustTransitionError::ChainLinkageBroken { sequence });
                }
                if snapshot.activation_at < prev.activation_at {
                    return Err(TrustTransitionError::ChainActivationOrderViolation { sequence });
                }
                if row.activated && !prev.activated {
                    return Err(TrustTransitionError::ChainActivationGap { sequence });
                }
            }
        }

        // Authorization re-verification under the predecessor (or the pinned
        // genesis policy). This is what makes reconstruction trustworthy
        // rather than merely well-formed.
        let auth_error =
            |reason: String| TrustTransitionError::ChainAuthorizationInvalid { sequence, reason };
        let collected = approvals_to_collected(&file.approvals);
        match file.kind {
            TrustTransitionKind::Genesis => {
                let policy = file
                    .genesis_approval_policy
                    .as_ref()
                    .ok_or_else(|| auth_error("missing genesis approval policy".into()))?;
                let status = verify_trust_genesis_approval(policy, &snapshot, &collected)
                    .map_err(|e| auth_error(e.to_string()))?;
                if !status.satisfied {
                    return Err(auth_error(format!(
                        "genesis approvals: {} of {} required",
                        status.valid_signatures, status.threshold
                    )));
                }
            }
            TrustTransitionKind::Rotation => {
                let prev = links.last().expect("chain shape checked above");
                let required = required_rotation_policies(&prev.snapshot, &snapshot)?;
                for (role, policy) in &required {
                    let status = verify_trust_rotation_approval(
                        policy,
                        &prev.digest,
                        &digest,
                        prev.sequence,
                        sequence,
                        snapshot.activation_at,
                        &collected,
                    )
                    .map_err(|e| auth_error(e.to_string()))?;
                    if !status.satisfied {
                        return Err(auth_error(format!(
                            "role {}: {} of {} required",
                            role.wire_tag(),
                            status.valid_signatures,
                            status.threshold
                        )));
                    }
                }
            }
            TrustTransitionKind::Recovery => {
                let prev = links.last().expect("chain shape checked above");
                let (role, reason) = file
                    .recovery
                    .ok_or_else(|| auth_error("missing recovery role/reason".into()))?;
                for unrelated in TrustRole::ALL {
                    if unrelated != role
                        && project_role(&prev.snapshot, unrelated)
                            != project_role(&snapshot, unrelated)
                    {
                        return Err(auth_error(format!(
                            "recovery for {} modified unrelated role {}",
                            role.wire_tag(),
                            unrelated.wire_tag()
                        )));
                    }
                }
                let pinned = prev
                    .snapshot
                    .recovery_keys
                    .get(&role)
                    .ok_or_else(|| auth_error("predecessor pins no recovery key".into()))?;
                let status = verify_trust_recovery_approval(
                    pinned,
                    role,
                    &prev.digest,
                    &digest,
                    prev.sequence,
                    sequence,
                    reason,
                    snapshot.activation_at,
                    &collected,
                )
                .map_err(|e| auth_error(e.to_string()))?;
                if !status.satisfied {
                    return Err(auth_error("recovery approval unsatisfied".into()));
                }
            }
        }

        links.push(AcceptedLink {
            candidate_id: row.candidate_id,
            kind: file.kind,
            sequence,
            digest,
            previous_digest: snapshot.previous_snapshot_digest,
            activation_at: snapshot.activation_at,
            snapshot,
            activated: row.activated,
        });
    }
    Ok(AcceptedChain { links })
}

// ── Staging ───────────────────────────────────────────────────────────────

/// Validate a signed transition file and persist it as one immutable Staged
/// candidate (ADR-0041 §3/§6). Reserves no sequence slot; the advisory tip
/// read here is unlocked because acceptance re-validates under the lock.
pub async fn stage_candidate(
    pool: &PgPool,
    file: &TrustTransitionFile,
    now: i64,
    config: &TrustFreshnessConfig,
    is_prod: bool,
) -> Result<StagedCandidate, TrustTransitionError> {
    let chain = load_accepted_chain(pool).await?;
    let validated = validate_transition(chain.tip(), file, now, config, is_prod)?;

    let candidate_id = Uuid::new_v4();
    let snapshot = &file.snapshot;
    let next_sequence = sequence_to_db(snapshot.sequence)?;
    let previous_sequence = match snapshot.sequence {
        1 => None,
        s => Some(sequence_to_db(s - 1)?),
    };
    sqlx::query(
        "INSERT INTO trust_transition_candidates
             (candidate_id, kind, previous_sequence, next_sequence,
              previous_snapshot_digest, next_snapshot_digest,
              snapshot_json, approvals_json, authorization_json, verification_json,
              recovery_role, recovery_reason, activation_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(candidate_id)
    .bind(file.kind.wire_tag())
    .bind(previous_sequence)
    .bind(next_sequence)
    .bind(snapshot.previous_snapshot_digest.as_ref().map(hex_digest))
    .bind(hex_digest(&validated.digest))
    .bind(serde_json::to_value(TrustSnapshotWireV1::from_snapshot(
        snapshot,
    ))?)
    .bind(serde_json::to_value(&file.approvals)?)
    .bind(&validated.authorization_json)
    .bind(&validated.verification_json)
    .bind(file.recovery.map(|(role, _)| role.wire_tag()))
    .bind(file.recovery.map(|(_, reason)| reason.wire_tag()))
    .bind(snapshot.activation_at)
    .execute(pool)
    .await?;

    Ok(StagedCandidate {
        candidate_id,
        next_sequence: snapshot.sequence,
        next_snapshot_digest: validated.digest,
    })
}

// ── Acceptance ────────────────────────────────────────────────────────────

/// Open the serialised trust-lifecycle transaction: `READ COMMITTED` pinned
/// (the advisory wait must not snapshot early — H-4's reasoning verbatim),
/// bounded `lock_timeout`, transaction-scoped advisory lock so commit,
/// rollback, cancellation, and process death all release it.
async fn begin_locked(
    pool: &PgPool,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, TrustTransitionError> {
    let mut tx = pool
        .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
        .await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(TRUST_ACCEPT_LOCK_KEY)
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// Atomically accept a staged candidate (ADR-0041 §6).
///
/// Under the advisory lock, in one transaction: re-decode the immutable
/// candidate (digest recomputation included), re-validate authorization
/// against the chain tip *as of now* — the tip may have advanced past the
/// staging-time tip — then insert the accepted row (acquiring the successor
/// uniqueness constraints) and append the `accepted` event.
///
/// On failure the candidate row is never mutated; the outcome is recorded as
/// an appended terminal event: `superseded` (a competing candidate already
/// owns the slot — the event references the winner) or `rejected` (the
/// re-validation failed — the event carries the typed reason's rendering).
/// The corresponding typed error is returned either way.
pub async fn accept_candidate(
    pool: &PgPool,
    candidate_id: Uuid,
    now: i64,
    config: &TrustFreshnessConfig,
    is_prod: bool,
) -> Result<AcceptedLink, TrustTransitionError> {
    let mut tx = begin_locked(pool).await?;

    let row = fetch_candidate(&mut tx, candidate_id).await?;
    let (file, digest) = row.decode()?;

    // A rejected/superseded event is terminal for the candidate (ADR-0041
    // §6). Whatever failed is recorded immutably; a retry means staging a
    // fresh candidate, so the event history reads as one attempt per row.
    let terminal: Option<(String,)> = sqlx::query_as(
        "SELECT event_kind FROM trust_candidate_events
          WHERE candidate_id = $1 AND event_kind IN ('rejected', 'superseded')
          LIMIT 1",
    )
    .bind(candidate_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((event_kind,)) = terminal {
        tx.rollback().await?;
        return Err(TrustTransitionError::CandidateTerminal {
            candidate_id,
            event_kind,
        });
    }

    // Slot ownership next: a candidate whose successor slot is already
    // owned is superseded regardless of how its own validation would fare.
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT candidate_id FROM trust_accepted_transitions WHERE next_sequence = $1",
    )
    .bind(row.next_sequence)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((winner,)) = existing {
        if winner == candidate_id {
            tx.rollback().await?;
            return Err(TrustTransitionError::CandidateAlreadyAccepted { candidate_id });
        }
        let sequence = file.snapshot.sequence;
        append_event(
            &mut tx,
            candidate_id,
            "superseded",
            Some("successor slot already owned by an accepted candidate"),
            Some(winner),
        )
        .await?;
        tx.commit().await?;
        return Err(TrustTransitionError::SupersededByAcceptedWinner { winner, sequence });
    }

    let chain = load_accepted_chain_conn(&mut tx).await?;
    match validate_transition(chain.tip(), &file, now, config, is_prod) {
        Err(error) => {
            // Record the rejection against the immutable candidate, keep the
            // candidate itself untouched, and surface the typed error.
            append_event(
                &mut tx,
                candidate_id,
                "rejected",
                Some(&error.to_string()),
                None,
            )
            .await?;
            tx.commit().await?;
            Err(error)
        }
        Ok(validated) => {
            debug_assert_eq!(validated.digest, digest);
            let snapshot = &file.snapshot;
            sqlx::query(
                "INSERT INTO trust_accepted_transitions
                     (accepted_id, candidate_id, next_sequence, next_snapshot_digest,
                      previous_snapshot_digest, activation_at)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(Uuid::new_v4())
            .bind(candidate_id)
            .bind(sequence_to_db(snapshot.sequence)?)
            .bind(hex_digest(&digest))
            .bind(snapshot.previous_snapshot_digest.as_ref().map(hex_digest))
            .bind(snapshot.activation_at)
            .execute(&mut *tx)
            .await?;
            append_event(&mut tx, candidate_id, "accepted", None, None).await?;
            tx.commit().await?;
            Ok(AcceptedLink {
                candidate_id,
                kind: file.kind,
                sequence: snapshot.sequence,
                digest,
                previous_digest: snapshot.previous_snapshot_digest,
                activation_at: snapshot.activation_at,
                snapshot: snapshot.clone(),
                activated: false,
            })
        }
    }
}

// ── Activation ────────────────────────────────────────────────────────────

/// Activate an accepted transition by appending its `activated` event, only
/// when ADR-0041 §3's six preconditions hold at `now`:
///
/// 1. its predecessor is the current Active snapshot (genesis: nothing is
///    Active yet);
/// 2. its sequence is exactly predecessor + 1;
/// 3. its `previous_snapshot_digest` matches the predecessor digest;
/// 4. its signed `activation_at` is `>=` the predecessor's;
/// 5. the decision-time clock has reached the signed `activation_at`;
/// 6. freshness, coverage, and authorization checks still pass.
///
/// 2–4 and the authorization half of 6 are enforced by
/// [`load_accepted_chain`]'s integrity re-verification (a chain violating
/// them refuses to load at all); 1, 5, and the freshness/coverage half of 6
/// are evaluated here against `now`. Runs under the same advisory lock as
/// acceptance so activation is one atomic state change.
pub async fn activate_transition(
    pool: &PgPool,
    candidate_id: Uuid,
    now: i64,
    config: &TrustFreshnessConfig,
    is_prod: bool,
) -> Result<(), TrustTransitionError> {
    let mut tx = begin_locked(pool).await?;
    let chain = load_accepted_chain_conn(&mut tx).await?;
    let index = chain
        .links
        .iter()
        .position(|link| link.candidate_id == candidate_id)
        .ok_or(TrustTransitionError::NotAccepted { candidate_id })?;
    let link = &chain.links[index];
    if link.activated {
        tx.rollback().await?;
        return Err(TrustTransitionError::AlreadyActivated { candidate_id });
    }
    // Precondition 1. The loader guarantees the activated links form a
    // prefix, so "predecessor is the current Active snapshot" is exactly
    // "this link is the first non-activated link".
    if index != chain.active_len() {
        let predecessor_sequence = chain.links[index - 1].sequence;
        tx.rollback().await?;
        return Err(TrustTransitionError::PredecessorNotActive {
            predecessor_sequence,
        });
    }
    // Precondition 5.
    if now < link.activation_at {
        let activation_at = link.activation_at;
        tx.rollback().await?;
        return Err(TrustTransitionError::ActivationTimeNotReached { activation_at, now });
    }
    // Precondition 6 (freshness + coverage; authorization was re-verified by
    // the loader). Coverage-at-activation is part of `validate`, re-run here
    // with the current lifetime bound.
    if let Some(violation) = snapshot_freshness_violation(&link.snapshot, now, config) {
        tx.rollback().await?;
        return Err(violation.into());
    }
    link.snapshot.validate(config.max_lifetime.seconds())?;
    if is_prod {
        if let Some(role) = local_only_active_role(&link.snapshot) {
            tx.rollback().await?;
            return Err(TrustTransitionError::LocalOnlyPolicyInProduction { role });
        }
    }

    append_event(&mut tx, candidate_id, "activated", None, None).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quorum::trust::{
        approve_trust_genesis, approve_trust_recovery, approve_trust_rotation,
    };
    use crate::trust::config::FreshnessLimit;
    use olympus_crypto::trust_list::{GenesisApprovalPolicy, RecoveryReason, TrustedIssuerEntry};
    use std::collections::BTreeSet;

    fn trust_key_for(priv_key: &[u8; 32]) -> olympus_crypto::trust_list::TrustPubKey {
        use ark_ff::{BigInteger, PrimeField};
        let pk = crate::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(priv_key)
            .expect("pubkey");
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&pk.x.into_bigint().to_bytes_be());
        y.copy_from_slice(&pk.y.into_bigint().to_bytes_be());
        olympus_crypto::trust_list::TrustPubKey::new(x, y)
    }

    fn sorted_keys(seeds: &[[u8; 32]]) -> Vec<olympus_crypto::trust_list::TrustPubKey> {
        let mut keys: Vec<_> = seeds.iter().map(trust_key_for).collect();
        keys.sort_unstable();
        keys
    }

    const ROT1: [u8; 32] = [10u8; 32];
    const ROT2: [u8; 32] = [11u8; 32];
    const RECOVERY: [u8; 32] = [200u8; 32];
    const GEN1: [u8; 32] = [20u8; 32];
    const GEN2: [u8; 32] = [21u8; 32];

    fn base_snapshot(sequence: u64, previous: Option<[u8; 32]>) -> TrustListSnapshotV1 {
        let role = TrustRole::CredentialAuthority;
        let issued_at = 1_700_000_000 + (sequence as i64 - 1) * 1_000;
        TrustListSnapshotV1 {
            format_version: 1,
            sequence,
            issued_at,
            expires_at: issued_at + 90_000,
            activation_at: issued_at + 500,
            previous_snapshot_digest: previous,
            active_roles: BTreeSet::from([role]),
            entries: vec![TrustedIssuerEntry {
                pubkey: trust_key_for(&[1u8; 32]),
                roles: BTreeSet::from([role]),
                valid_from: issued_at + 100,
                valid_until: issued_at + 80_000,
            }],
            rotation_policies: BTreeMap::from([(
                role,
                RotationPolicy {
                    profile: RotationPolicyProfile::Production,
                    signers: sorted_keys(&[ROT1, ROT2]),
                    threshold: 2,
                },
            )]),
            recovery_keys: BTreeMap::from([(role, trust_key_for(&RECOVERY))]),
        }
    }

    fn genesis_policy() -> GenesisApprovalPolicy {
        GenesisApprovalPolicy {
            profile: RotationPolicyProfile::Production,
            signers: sorted_keys(&[GEN1, GEN2]),
            threshold: 2,
        }
    }

    fn approval_wire(sig: CollectedSignature) -> TrustApprovalWire {
        TrustApprovalWire {
            x: sig.signer.x,
            y: sig.signer.y,
            r8x: sig.r8x,
            r8y: sig.r8y,
            s: sig.s,
        }
    }

    fn genesis_file() -> TrustTransitionFile {
        let snapshot = base_snapshot(1, None);
        let policy = genesis_policy();
        let approvals = [GEN1, GEN2]
            .iter()
            .map(|key| approval_wire(approve_trust_genesis(key, &snapshot, &policy).expect("sign")))
            .collect();
        TrustTransitionFile {
            kind: TrustTransitionKind::Genesis,
            snapshot,
            approvals,
            recovery: None,
            genesis_approval_policy: Some(policy),
        }
    }

    fn genesis_link() -> AcceptedLink {
        let file = genesis_file();
        let digest = snapshot_digest(&file.snapshot);
        AcceptedLink {
            candidate_id: Uuid::new_v4(),
            kind: TrustTransitionKind::Genesis,
            sequence: 1,
            digest,
            previous_digest: None,
            activation_at: file.snapshot.activation_at,
            snapshot: file.snapshot,
            activated: true,
        }
    }

    fn rotation_file_on(
        tip: &AcceptedLink,
        mutate: impl FnOnce(&mut TrustListSnapshotV1),
    ) -> TrustTransitionFile {
        let mut snapshot = base_snapshot(tip.sequence + 1, Some(tip.digest));
        mutate(&mut snapshot);
        let digest = snapshot_digest(&snapshot);
        let approvals = [ROT1, ROT2]
            .iter()
            .map(|key| {
                approval_wire(
                    approve_trust_rotation(
                        key,
                        &tip.digest,
                        &digest,
                        tip.sequence,
                        snapshot.sequence,
                        snapshot.activation_at,
                    )
                    .expect("sign"),
                )
            })
            .collect();
        TrustTransitionFile {
            kind: TrustTransitionKind::Rotation,
            snapshot,
            approvals,
            recovery: None,
            genesis_approval_policy: None,
        }
    }

    /// Build a role-scoped recovery transition file on `tip`, signed by
    /// `signer` under the recovery domain (`OLY:TRUST:RECOVER:V1`). Only the
    /// recovering role's rotation policy is changed (fresh signers), so the
    /// ADR-0041 §7 scope check on every other role's projection passes
    /// trivially — `base_snapshot` has exactly one active role.
    fn recovery_file_on(
        tip: &AcceptedLink,
        role: TrustRole,
        reason: RecoveryReason,
        signer: &[u8; 32],
    ) -> TrustTransitionFile {
        let mut snapshot = tip.snapshot.clone();
        snapshot.sequence = tip.sequence + 1;
        snapshot.previous_snapshot_digest = Some(tip.digest);
        snapshot.activation_at = tip.activation_at + 100;
        snapshot.rotation_policies.insert(
            role,
            RotationPolicy {
                profile: RotationPolicyProfile::Production,
                signers: sorted_keys(&[[50u8; 32], [51u8; 32]]),
                threshold: 2,
            },
        );
        let digest = snapshot_digest(&snapshot);
        let approval = approve_trust_recovery(
            signer,
            role,
            &tip.digest,
            &digest,
            tip.sequence,
            snapshot.sequence,
            reason,
            snapshot.activation_at,
        )
        .expect("sign");
        TrustTransitionFile {
            kind: TrustTransitionKind::Recovery,
            snapshot,
            approvals: vec![approval_wire(approval)],
            recovery: Some((role, reason)),
            genesis_approval_policy: None,
        }
    }

    fn dev_config() -> TrustFreshnessConfig {
        TrustFreshnessConfig {
            max_age: FreshnessLimit::Unset,
            max_lifetime: FreshnessLimit::Unset,
        }
    }

    /// Late enough that both a sequence-1 snapshot (issued 1_700_000_000)
    /// and a sequence-2 snapshot (issued 1_700_001_000, per `base_snapshot`)
    /// are within their freshness windows.
    const NOW: i64 = 1_700_002_000;

    #[test]
    fn genesis_validates_and_pins_its_policy() {
        let validated =
            validate_transition(None, &genesis_file(), NOW, &dev_config(), false).expect("valid");
        assert_eq!(
            hex::encode(validated.digest),
            hex::encode(snapshot_digest(&genesis_file().snapshot))
        );
        assert!(validated.authorization_json["genesis_approval_policy"].is_object());
    }

    #[test]
    fn genesis_on_an_existing_chain_is_rejected_as_genesis_already_exists() {
        let tip = genesis_link();
        let result = validate_transition(Some(&tip), &genesis_file(), NOW, &dev_config(), false);
        assert!(matches!(
            result,
            Err(TrustTransitionError::GenesisAlreadyExists {
                accepted_sequence: 1
            })
        ));
    }

    #[test]
    fn genesis_without_enough_approvals_is_rejected_with_the_counts() {
        let mut file = genesis_file();
        file.approvals.truncate(1);
        let result = validate_transition(None, &file, NOW, &dev_config(), false);
        assert!(matches!(
            result,
            Err(TrustTransitionError::InsufficientGenesisApprovals {
                valid: 1,
                required: 2
            })
        ));
    }

    #[test]
    fn candidate_policy_cannot_self_authorize() {
        // The candidate installs its OWN 1-of-1 policy under an attacker key
        // and is signed only by that key. Authorization must be evaluated
        // under the PRIOR snapshot's 2-of-2 (ADR-0041 §2), so this fails on
        // insufficient approvals for the affected role — the candidate's own
        // policy is never consulted.
        let tip = genesis_link();
        let attacker = [66u8; 32];
        let mut snapshot = base_snapshot(2, Some(tip.digest));
        snapshot.rotation_policies.insert(
            TrustRole::CredentialAuthority,
            RotationPolicy {
                profile: RotationPolicyProfile::LocalOnly,
                signers: vec![trust_key_for(&attacker)],
                threshold: 1,
            },
        );
        let digest = snapshot_digest(&snapshot);
        let approvals = vec![approval_wire(
            approve_trust_rotation(
                &attacker,
                &tip.digest,
                &digest,
                1,
                2,
                snapshot.activation_at,
            )
            .expect("sign"),
        )];
        let file = TrustTransitionFile {
            kind: TrustTransitionKind::Rotation,
            snapshot,
            approvals,
            recovery: None,
            genesis_approval_policy: None,
        };
        let result = validate_transition(Some(&tip), &file, NOW, &dev_config(), false);
        assert!(matches!(
            result,
            Err(TrustTransitionError::InsufficientRoleApprovals {
                role: "credential_authority",
                valid: 0,
                required: 2
            })
        ));
    }

    #[test]
    fn successor_shape_rejections_are_typed() {
        let tip = genesis_link();

        // Rollback (sequence 1 against accepted 1 with different content).
        let mut rollback = rotation_file_on(&tip, |_| {});
        rollback.snapshot.sequence = 1;
        rollback.snapshot.previous_snapshot_digest = None;
        rollback.snapshot.issued_at += 1; // different content at the accepted sequence
        assert!(matches!(
            validate_transition(Some(&tip), &rollback, NOW, &dev_config(), false),
            Err(TrustTransitionError::SameSequenceEquivocation { sequence: 1 })
        ));

        // True rollback: a candidate whose sequence is strictly behind the
        // accepted tip. Build a sequence-2 tip so sequence 1 is "older".
        let seq2_tip = {
            let file = rotation_file_on(&tip, |_| {});
            AcceptedLink {
                candidate_id: Uuid::new_v4(),
                kind: TrustTransitionKind::Rotation,
                sequence: 2,
                digest: snapshot_digest(&file.snapshot),
                previous_digest: Some(tip.digest),
                activation_at: file.snapshot.activation_at,
                snapshot: file.snapshot,
                activated: true,
            }
        };
        let old = genesis_file(); // sequence 1 against an accepted tip at 2
        let mut old_rotation = rotation_file_on(&tip, |_| {});
        old_rotation.snapshot = old.snapshot;
        old_rotation.kind = TrustTransitionKind::Rotation;
        assert!(matches!(
            validate_transition(Some(&seq2_tip), &old_rotation, NOW, &dev_config(), false),
            Err(TrustTransitionError::RollbackToOlderSequence {
                candidate: 1,
                accepted: 2
            })
        ));

        // Skipped sequence.
        let mut skipped = rotation_file_on(&tip, |_| {});
        skipped.snapshot.sequence = 3;
        assert!(matches!(
            validate_transition(Some(&tip), &skipped, NOW, &dev_config(), false),
            Err(TrustTransitionError::SkippedSequence {
                candidate: 3,
                accepted: 1
            })
        ));

        // Wrong predecessor digest.
        let mut wrong_pred = rotation_file_on(&tip, |_| {});
        wrong_pred.snapshot.previous_snapshot_digest = Some([9u8; 32]);
        assert!(matches!(
            validate_transition(Some(&tip), &wrong_pred, NOW, &dev_config(), false),
            Err(TrustTransitionError::WrongPredecessorDigest { .. })
        ));

        // Decreasing signed activation_at.
        let decreasing = rotation_file_on(&tip, |s| {
            s.issued_at = tip.snapshot.issued_at - 10_000;
            s.activation_at = tip.activation_at - 1;
            s.expires_at = tip.snapshot.expires_at;
            // keep issuer windows inside the shifted envelope
            s.entries[0].valid_from = s.issued_at + 1;
            s.entries[0].valid_until = s.expires_at - 1;
        });
        assert!(matches!(
            validate_transition(Some(&tip), &decreasing, NOW, &dev_config(), false),
            Err(TrustTransitionError::DecreasingActivationTime { .. })
        ));
    }

    #[test]
    fn rotation_without_an_accepted_genesis_is_rejected() {
        let tip = genesis_link();
        let file = rotation_file_on(&tip, |_| {});
        assert!(matches!(
            validate_transition(None, &file, NOW, &dev_config(), false),
            Err(TrustTransitionError::NoAcceptedGenesis)
        ));
    }

    #[test]
    fn expired_and_future_dated_snapshots_are_rejected() {
        let file = genesis_file();
        let expired_now = file.snapshot.expires_at;
        assert!(matches!(
            validate_transition(None, &file, expired_now, &dev_config(), false),
            Err(TrustTransitionError::SnapshotNotFresh(
                FreshnessViolation::Expired { .. }
            ))
        ));
        let long_before = file.snapshot.issued_at - 10_000;
        assert!(matches!(
            validate_transition(None, &file, long_before, &dev_config(), false),
            Err(TrustTransitionError::SnapshotNotFresh(
                FreshnessViolation::FutureDated { .. }
            ))
        ));
    }

    #[test]
    fn production_rejects_local_only_policies() {
        // Active role under a local_only rotation policy.
        let mut file = genesis_file();
        file.snapshot
            .rotation_policies
            .get_mut(&TrustRole::CredentialAuthority)
            .unwrap()
            .profile = RotationPolicyProfile::LocalOnly;
        // (Re-signing is unnecessary: the profile check fires before
        // signature verification.)
        assert!(matches!(
            validate_transition(None, &file, NOW, &dev_config(), true),
            Err(TrustTransitionError::LocalOnlyPolicyInProduction {
                role: "credential_authority"
            })
        ));
        // ...but the same snapshot is fine in dev IF correctly signed — here
        // signatures no longer match the mutated body, so assert only that
        // the production gate is what fired above, not signature validity.

        // local_only genesis approval policy.
        let mut file = genesis_file();
        file.genesis_approval_policy.as_mut().unwrap().profile = RotationPolicyProfile::LocalOnly;
        assert!(matches!(
            validate_transition(None, &file, NOW, &dev_config(), true),
            Err(TrustTransitionError::LocalOnlyGenesisPolicyInProduction)
        ));
    }

    #[test]
    fn recovery_scope_violation_is_detected_before_signature_checking() {
        // Build a 2-role genesis so a recovery for one role can illegally
        // touch the other.
        let extra_role = TrustRole::CheckpointAuthority;
        let mut genesis = base_snapshot(1, None);
        genesis.active_roles.insert(extra_role);
        genesis.entries.push(TrustedIssuerEntry {
            pubkey: trust_key_for(&[2u8; 32]),
            roles: BTreeSet::from([extra_role]),
            valid_from: genesis.issued_at + 100,
            valid_until: genesis.issued_at + 80_000,
        });
        genesis.rotation_policies.insert(
            extra_role,
            RotationPolicy {
                profile: RotationPolicyProfile::Production,
                signers: sorted_keys(&[[30u8; 32], [31u8; 32]]),
                threshold: 2,
            },
        );
        genesis
            .recovery_keys
            .insert(extra_role, trust_key_for(&[201u8; 32]));
        let tip = AcceptedLink {
            candidate_id: Uuid::new_v4(),
            kind: TrustTransitionKind::Genesis,
            sequence: 1,
            digest: snapshot_digest(&genesis),
            previous_digest: None,
            activation_at: genesis.activation_at,
            snapshot: genesis.clone(),
            activated: true,
        };

        // Recovery for CredentialAuthority that ALSO swaps the checkpoint
        // role's recovery key — an unrelated-projection change.
        let mut recovery_snapshot = genesis.clone();
        recovery_snapshot.sequence = 2;
        recovery_snapshot.previous_snapshot_digest = Some(tip.digest);
        recovery_snapshot.rotation_policies.insert(
            TrustRole::CredentialAuthority,
            RotationPolicy {
                profile: RotationPolicyProfile::Production,
                signers: sorted_keys(&[[40u8; 32], [41u8; 32]]),
                threshold: 2,
            },
        );
        recovery_snapshot
            .recovery_keys
            .insert(extra_role, trust_key_for(&[99u8; 32]));
        let file = TrustTransitionFile {
            kind: TrustTransitionKind::Recovery,
            snapshot: recovery_snapshot,
            approvals: Vec::new(),
            recovery: Some((
                TrustRole::CredentialAuthority,
                RecoveryReason::QuorumCompromise,
            )),
            genesis_approval_policy: None,
        };
        assert!(matches!(
            validate_transition(Some(&tip), &file, NOW, &dev_config(), false),
            Err(TrustTransitionError::RecoveryScopeViolation {
                recovering: "credential_authority",
                modified: "checkpoint_authority"
            })
        ));
    }

    // ── tsc-2: the pinned-recovery-key signature gate must be provably
    // enforced in both directions — a regression that inverts or deletes it
    // (store.rs's `!status.satisfied` check in the Recovery arm) would leave
    // every OTHER trust test green, since none of them exercises this path.

    #[test]
    fn recovery_signed_by_the_pinned_key_is_accepted() {
        let tip = genesis_link();
        let file = recovery_file_on(
            &tip,
            TrustRole::CredentialAuthority,
            RecoveryReason::QuorumCompromise,
            &RECOVERY,
        );
        let validated = validate_transition(Some(&tip), &file, NOW, &dev_config(), false)
            .expect("pinned-key recovery must be accepted");
        assert_eq!(
            hex::encode(validated.digest),
            hex::encode(snapshot_digest(&file.snapshot))
        );
        assert_eq!(
            validated.authorization_json["recovery_role"],
            "credential_authority"
        );
    }

    #[test]
    fn recovery_signed_by_the_routine_rotation_quorum_is_rejected() {
        // ROT1/ROT2 are the role's ordinary 2-of-2 rotation signers, not the
        // pinned recovery key. Security invariant 12 (ADR-0041 §7): a quorum
        // of routine signers must never substitute for offline recovery.
        let tip = genesis_link();
        let mut file = recovery_file_on(
            &tip,
            TrustRole::CredentialAuthority,
            RecoveryReason::QuorumCompromise,
            &RECOVERY,
        );
        file.approvals = [ROT1, ROT2]
            .iter()
            .map(|key| {
                approval_wire(
                    approve_trust_recovery(
                        key,
                        TrustRole::CredentialAuthority,
                        &tip.digest,
                        &snapshot_digest(&file.snapshot),
                        tip.sequence,
                        file.snapshot.sequence,
                        RecoveryReason::QuorumCompromise,
                        file.snapshot.activation_at,
                    )
                    .expect("sign"),
                )
            })
            .collect();
        assert!(matches!(
            validate_transition(Some(&tip), &file, NOW, &dev_config(), false),
            Err(TrustTransitionError::InsufficientRecoveryApproval {
                role: "credential_authority"
            })
        ));
    }

    #[test]
    fn recovery_for_a_role_with_no_pinned_recovery_key_is_rejected() {
        // `TrustListSnapshotV1::validate` unconditionally requires every
        // *active* role to carry a recovery key (crypto's
        // `RoleMissingRecoveryKey`), so a role that could reach this store-level
        // `RecoveryKeyNotPinned` check must be one that was never configured on
        // the tip snapshot at all — not merely stripped of its key. `base_snapshot`
        // only defines `CredentialAuthority`; recovering the never-configured
        // `CheckpointAuthority` hits `tip.snapshot.recovery_keys.get(&role) ==
        // None` the moment it's consulted, before any signature is checked.
        let tip = genesis_link();
        let role = TrustRole::CheckpointAuthority;
        let mut snapshot = tip.snapshot.clone();
        snapshot.sequence = tip.sequence + 1;
        snapshot.previous_snapshot_digest = Some(tip.digest);
        snapshot.activation_at = tip.activation_at + 100;
        let file = TrustTransitionFile {
            kind: TrustTransitionKind::Recovery,
            snapshot,
            approvals: Vec::new(),
            recovery: Some((role, RecoveryReason::QuorumCompromise)),
            genesis_approval_policy: None,
        };
        let result = validate_transition(Some(&tip), &file, NOW, &dev_config(), false);
        let debug = result.as_ref().map(|_| ()).map_err(ToString::to_string);
        assert!(
            matches!(
                result,
                Err(TrustTransitionError::RecoveryKeyNotPinned {
                    role: "checkpoint_authority"
                })
            ),
            "{debug:?}"
        );
    }

    #[test]
    fn envelope_only_rotation_requires_every_prior_active_policy() {
        // A rotation that only extends expiry affects no role projection.
        // The resolved rule (module docs): it still requires every prior
        // active role's policy — unsigned freshness resets are not a thing.
        let tip = genesis_link();
        let mut file = rotation_file_on(&tip, |s| {
            // Same projections as the predecessor: copy issuer windows,
            // policies, recovery keys from the tip snapshot verbatim.
            s.entries = tip.snapshot.entries.clone();
            s.rotation_policies = tip.snapshot.rotation_policies.clone();
            s.recovery_keys = tip.snapshot.recovery_keys.clone();
            s.issued_at = tip.snapshot.issued_at;
            s.expires_at = tip.snapshot.expires_at + 10_000;
            s.activation_at = tip.snapshot.activation_at + 1_000;
        });
        assert!(
            validate_transition(Some(&tip), &file, NOW, &dev_config(), false).is_ok(),
            "fully quorum-signed envelope-only rotation must pass"
        );

        // With zero approvals it must fail on the credential role's policy —
        // not pass vacuously.
        file.approvals.clear();
        assert!(matches!(
            validate_transition(Some(&tip), &file, NOW, &dev_config(), false),
            Err(TrustTransitionError::InsufficientRoleApprovals {
                role: "credential_authority",
                valid: 0,
                required: 2
            })
        ));
    }
}
