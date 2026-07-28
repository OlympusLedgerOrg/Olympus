// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! ADR-0041 role-separated trust-list types + canonical encoders.
//!
//! Scope: steps 1–2 of the ADR's implementation plan — the protocol data
//! model, its machine-checkable invariants, and the normative deterministic
//! encoders. **Nothing here is wired into runtime trust decisions yet**; the
//! `TrustResolver` API, persistence, quorum verification, activation
//! scheduling, and genesis CLI are later steps.
//!
//! ## Why the encoders live here
//!
//! ADR-0041 §1: "It uses one normative deterministic encoder with published
//! test vectors. Default Serde JSON output is not itself a protocol
//! encoding." Canonical encoding is a security-critical protocol surface —
//! every conforming implementation must compute identical digests (security
//! invariant 15) — so it belongs in `olympus-crypto` alongside the other
//! domain-separated message constructors, not in a consumer crate. This
//! module deliberately pulls **no new dependencies**: encoding is BLAKE3 over
//! length-prefixed bytes, and public keys are carried as canonical
//! big-endian coordinate pairs rather than a curve type, so offline verifiers
//! can reproduce a digest without an arkworks/BJJ stack.
//!
//! ## Encoding rules
//!
//! Every field is wrapped in [`length_prefixed`] (ADR-0005 `lp`), including
//! fixed-width integers. Uniform framing means a later field addition cannot
//! retroactively make two different snapshots encode identically, and it
//! matches the framing the ADR spells out for the rotation and recovery
//! messages. Composite values (role sets, issuer lists, policies) are encoded
//! into a buffer that is itself `lp`-wrapped by its parent, so nesting is
//! unambiguous at every level.
//!
//! Optional values encode as `lp(<empty>)` when absent. This is unambiguous
//! because every present encoding is non-empty (a digest is 32 bytes; a
//! policy always carries at least its profile tag).

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::length_prefixed;

/// Domain prefix for the canonical trust-list snapshot digest (ADR-0041 §1).
pub const TRUST_SNAPSHOT_V1_PREFIX: &[u8] = b"OLY:TRUST:SNAPSHOT:V1";
/// Domain prefix for a routine trust-rotation approval (ADR-0041 §5).
pub const TRUST_ROTATE_V1_PREFIX: &[u8] = b"OLY:TRUST:ROTATE:V1";
/// Domain prefix for an offline role-scoped recovery approval (ADR-0041 §5/§7).
pub const TRUST_RECOVER_V1_PREFIX: &[u8] = b"OLY:TRUST:RECOVER:V1";
/// Domain prefix for a genesis approval (ADR-0041 §8).
pub const TRUST_GENESIS_V1_PREFIX: &[u8] = b"OLY:TRUST:GENESIS:V1";

/// The only snapshot format version this module encodes or validates.
pub const TRUST_SNAPSHOT_FORMAT_VERSION: u16 = 1;

// ── Roles ─────────────────────────────────────────────────────────────────

/// A trust role (ADR-0041 §1). Authority for one role never implies authority
/// for another (security invariant 1).
///
/// Discriminants are **explicit and frozen**: `Ord` derives from them and the
/// canonical encoding orders role sets by `Ord`, so reordering the variants
/// must not be able to silently change a digest. New roles append new codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TrustRole {
    CredentialAuthority = 1,
    RevocationAuthority = 2,
    CheckpointAuthority = 3,
    FederationAuthority = 4,
    CeremonyCoordinator = 5,
    /// Reserved for ADR-0042. Grants nothing until a consumer explicitly
    /// requests this role (ADR-0041 §1).
    RealmAuthority = 6,
}

impl TrustRole {
    /// Every defined protocol role, in canonical order.
    pub const ALL: [TrustRole; 6] = [
        TrustRole::CredentialAuthority,
        TrustRole::RevocationAuthority,
        TrustRole::CheckpointAuthority,
        TrustRole::FederationAuthority,
        TrustRole::CeremonyCoordinator,
        TrustRole::RealmAuthority,
    ];

    /// Stable wire tag. Frozen — it is covered by the snapshot digest.
    pub fn wire_tag(self) -> &'static str {
        match self {
            TrustRole::CredentialAuthority => "credential_authority",
            TrustRole::RevocationAuthority => "revocation_authority",
            TrustRole::CheckpointAuthority => "checkpoint_authority",
            TrustRole::FederationAuthority => "federation_authority",
            TrustRole::CeremonyCoordinator => "ceremony_coordinator",
            TrustRole::RealmAuthority => "realm_authority",
        }
    }

    /// Parse a wire tag. Fail-closed: an unknown tag is `None`, never a
    /// default role.
    pub fn from_wire_tag(tag: &str) -> Option<Self> {
        TrustRole::ALL.into_iter().find(|r| r.wire_tag() == tag)
    }
}

// ── Public keys ───────────────────────────────────────────────────────────

/// A Baby Jubjub public key as canonical 32-byte big-endian coordinates.
///
/// Carrying bytes rather than a curve point keeps this module dependency-free
/// and lets an offline verifier recompute a digest without a field
/// implementation. Curve-membership validation is the consumer's job (the
/// existing BJJ validation in `src-tauri`) and is deliberately not duplicated
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustPubKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl TrustPubKey {
    pub fn new(x: [u8; 32], y: [u8; 32]) -> Self {
        Self { x, y }
    }
}

// ── Policies ──────────────────────────────────────────────────────────────

/// Intended enforcement mode for a role's rotation policy (ADR-0041 §2).
///
/// The profile records intent; it "does not prove signer independence,
/// separate custody, or that two listed public keys are controlled by
/// different people or devices."
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RotationPolicyProfile {
    Production = 1,
    LocalOnly = 2,
}

impl RotationPolicyProfile {
    pub fn wire_tag(self) -> &'static str {
        match self {
            RotationPolicyProfile::Production => "production",
            RotationPolicyProfile::LocalOnly => "local_only",
        }
    }

    pub fn from_wire_tag(tag: &str) -> Option<Self> {
        match tag {
            "production" => Some(RotationPolicyProfile::Production),
            "local_only" => Some(RotationPolicyProfile::LocalOnly),
            _ => None,
        }
    }

    /// True when a node may only honour this profile in the separately named
    /// local-only deployment mode (ADR-0041 §2).
    pub fn requires_local_only_deployment(self) -> bool {
        matches!(self, RotationPolicyProfile::LocalOnly)
    }
}

/// An M-of-N approval policy for one role's routine rotations (ADR-0041 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationPolicy {
    pub profile: RotationPolicyProfile,
    pub signers: Vec<TrustPubKey>,
    pub threshold: u16,
}

/// Threshold approval policy for production genesis (ADR-0041 §8). Structurally
/// identical to [`RotationPolicy`] but a distinct type: it is supplied to
/// `init-genesis` and covered by a different domain-separated message, and
/// conflating the two would let a genesis approval be read as a rotation policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisApprovalPolicy {
    pub profile: RotationPolicyProfile,
    pub signers: Vec<TrustPubKey>,
    pub threshold: u16,
}

fn validate_threshold_policy(
    profile: RotationPolicyProfile,
    signers: &[TrustPubKey],
    threshold: u16,
) -> Result<(), TrustListError> {
    if signers.is_empty() {
        return Err(TrustListError::EmptySignerSet);
    }
    if !signers.windows(2).all(|w| w[0] < w[1]) {
        // Strict `<` rejects both unsorted and duplicate signers in one pass.
        return Err(TrustListError::SignersNotCanonicallyOrdered);
    }
    if threshold < 1 || usize::from(threshold) > signers.len() {
        return Err(TrustListError::ThresholdOutOfRange {
            threshold,
            signers: signers.len(),
        });
    }
    if profile == RotationPolicyProfile::Production && threshold < 2 {
        return Err(TrustListError::ProductionThresholdTooLow { threshold });
    }
    Ok(())
}

impl RotationPolicy {
    /// Machine-checkable policy validation (ADR-0041 §2).
    pub fn validate(&self) -> Result<(), TrustListError> {
        validate_threshold_policy(self.profile, &self.signers, self.threshold)
    }
}

impl GenesisApprovalPolicy {
    /// Same machine-checkable rules as a rotation policy (ADR-0041 §8).
    pub fn validate(&self) -> Result<(), TrustListError> {
        validate_threshold_policy(self.profile, &self.signers, self.threshold)
    }
}

// ── Issuers + snapshot ────────────────────────────────────────────────────

/// One trusted issuer with its explicit role grants and mandatory validity
/// window (ADR-0041 §1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIssuerEntry {
    pub pubkey: TrustPubKey,
    pub roles: BTreeSet<TrustRole>,
    pub valid_from: i64,
    pub valid_until: i64,
}

/// A signed, versioned trust-list snapshot (ADR-0041 §1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustListSnapshotV1 {
    pub format_version: u16,
    pub sequence: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub activation_at: i64,
    /// `None` only for genesis (`sequence == 1`).
    pub previous_snapshot_digest: Option<[u8; 32]>,
    pub active_roles: BTreeSet<TrustRole>,
    pub entries: Vec<TrustedIssuerEntry>,
    pub rotation_policies: BTreeMap<TrustRole, RotationPolicy>,
    pub recovery_keys: BTreeMap<TrustRole, TrustPubKey>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustListError {
    #[error("unsupported snapshot format_version {0} (expected {TRUST_SNAPSHOT_FORMAT_VERSION})")]
    UnsupportedFormatVersion(u16),
    #[error("snapshot sequence must be >= 1")]
    ZeroSequence,
    #[error("genesis (sequence 1) must not name a previous snapshot digest")]
    GenesisHasPredecessor,
    #[error("non-genesis snapshot (sequence {0}) must name a previous snapshot digest")]
    MissingPredecessor(u64),
    #[error("snapshot timestamps must satisfy issued_at <= activation_at < expires_at")]
    TimestampsOutOfOrder,
    #[error("snapshot lifetime {lifetime}s exceeds the configured maximum {max}s")]
    LifetimeTooLong { lifetime: i64, max: i64 },
    #[error("issuer role set must be non-empty")]
    IssuerWithoutRoles,
    #[error(
        "issuer validity must satisfy snapshot.issued_at <= valid_from < valid_until <= snapshot.expires_at"
    )]
    IssuerWindowOutOfBounds,
    #[error("duplicate issuer public key with conflicting non-role metadata is ambiguous")]
    AmbiguousDuplicateIssuer,
    #[error("active role {0} has no issuer whose validity window covers activation_at")]
    RoleNotCovered(&'static str),
    #[error("active role {0} has no rotation policy")]
    RoleMissingPolicy(&'static str),
    #[error("active role {0} has no recovery key")]
    RoleMissingRecoveryKey(&'static str),
    #[error("a role's recovery key must not be a member of that role's routine quorum")]
    RecoveryKeyInRoutineQuorum(&'static str),
    #[error("policy signer set must be non-empty")]
    EmptySignerSet,
    #[error("policy signers must be unique and canonically ordered")]
    SignersNotCanonicallyOrdered,
    #[error("threshold {threshold} out of range for {signers} signer(s)")]
    ThresholdOutOfRange { threshold: u16, signers: usize },
    #[error("production profile requires threshold >= 2 (got {threshold})")]
    ProductionThresholdTooLow { threshold: u16 },
}

impl TrustListSnapshotV1 {
    /// Validate every machine-checkable snapshot invariant from ADR-0041 §1–2.
    ///
    /// `max_lifetime_secs` is the operator's
    /// `OLYMPUS_TRUST_LIST_MAX_LIFETIME_SECS`; `None` skips only that bound.
    /// Time-relative freshness (`now - issued_at <= MAX_AGE`) is deliberately
    /// **not** checked here — it is a continuous decision-time check
    /// (ADR-0041 §4, security invariant 18), not a property of the snapshot.
    pub fn validate(&self, max_lifetime_secs: Option<i64>) -> Result<(), TrustListError> {
        if self.format_version != TRUST_SNAPSHOT_FORMAT_VERSION {
            return Err(TrustListError::UnsupportedFormatVersion(
                self.format_version,
            ));
        }
        if self.sequence == 0 {
            return Err(TrustListError::ZeroSequence);
        }
        match (self.sequence, self.previous_snapshot_digest) {
            (1, Some(_)) => return Err(TrustListError::GenesisHasPredecessor),
            (s, None) if s > 1 => return Err(TrustListError::MissingPredecessor(s)),
            _ => {}
        }
        if !(self.issued_at <= self.activation_at && self.activation_at < self.expires_at) {
            return Err(TrustListError::TimestampsOutOfOrder);
        }
        if let Some(max) = max_lifetime_secs {
            let lifetime = self.expires_at.saturating_sub(self.issued_at);
            if lifetime > max {
                return Err(TrustListError::LifetimeTooLong { lifetime, max });
            }
        }

        for entry in &self.entries {
            if entry.roles.is_empty() {
                return Err(TrustListError::IssuerWithoutRoles);
            }
            if !(self.issued_at <= entry.valid_from
                && entry.valid_from < entry.valid_until
                && entry.valid_until <= self.expires_at)
            {
                return Err(TrustListError::IssuerWindowOutOfBounds);
            }
        }

        // Duplicate public keys merge only when all non-role metadata is
        // identical; otherwise parsing fails as ambiguous (ADR-0041 §1).
        let mut by_key: BTreeMap<TrustPubKey, (i64, i64)> = BTreeMap::new();
        for entry in &self.entries {
            let window = (entry.valid_from, entry.valid_until);
            match by_key.get(&entry.pubkey) {
                Some(seen) if *seen != window => {
                    return Err(TrustListError::AmbiguousDuplicateIssuer)
                }
                _ => {
                    by_key.insert(entry.pubkey, window);
                }
            }
        }

        for role in &self.active_roles {
            let covered = self.entries.iter().any(|e| {
                e.roles.contains(role)
                    && e.valid_from <= self.activation_at
                    && self.activation_at < e.valid_until
            });
            if !covered {
                return Err(TrustListError::RoleNotCovered(role.wire_tag()));
            }
            let policy = self
                .rotation_policies
                .get(role)
                .ok_or(TrustListError::RoleMissingPolicy(role.wire_tag()))?;
            policy.validate()?;
            let recovery = self
                .recovery_keys
                .get(role)
                .ok_or(TrustListError::RoleMissingRecoveryKey(role.wire_tag()))?;
            // ADR-0041 §7: "Each role has one pinned offline recovery key that
            // is not a member of that role's routine quorum." Without this,
            // the routine quorum could invoke recovery (security invariant 12).
            if policy.signers.contains(recovery) {
                return Err(TrustListError::RecoveryKeyInRoutineQuorum(role.wire_tag()));
            }
        }

        Ok(())
    }

    /// Issuers granting `role`, in canonical order, as the projection tuples
    /// ADR-0041 §7 defines: `(pubkey, valid_from, valid_until)` — deliberately
    /// **excluding** the issuer's full role set, so changing an unrelated
    /// role's grant on a shared entry does not perturb this role's projection.
    fn projected_issuers(&self, role: TrustRole) -> Vec<(TrustPubKey, i64, i64)> {
        let mut out: Vec<(TrustPubKey, i64, i64)> = self
            .entries
            .iter()
            .filter(|e| e.roles.contains(&role))
            .map(|e| (e.pubkey, e.valid_from, e.valid_until))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

// ── Canonical encoding ────────────────────────────────────────────────────

fn enc_u16(v: u16) -> Vec<u8> {
    length_prefixed(&v.to_be_bytes())
}
fn enc_u64(v: u64) -> Vec<u8> {
    length_prefixed(&v.to_be_bytes())
}
fn enc_i64(v: i64) -> Vec<u8> {
    length_prefixed(&v.to_be_bytes())
}
fn enc_bytes(v: &[u8]) -> Vec<u8> {
    length_prefixed(v)
}

fn enc_pubkey(k: &TrustPubKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(72);
    out.extend_from_slice(&enc_bytes(&k.x));
    out.extend_from_slice(&enc_bytes(&k.y));
    out
}

fn enc_roles(roles: &BTreeSet<TrustRole>) -> Vec<u8> {
    let mut out = enc_u64(roles.len() as u64);
    for role in roles {
        out.extend_from_slice(&enc_bytes(role.wire_tag().as_bytes()));
    }
    out
}

fn enc_policy_fields(
    profile: RotationPolicyProfile,
    signers: &[TrustPubKey],
    threshold: u16,
) -> Vec<u8> {
    let mut out = enc_bytes(profile.wire_tag().as_bytes());
    out.extend_from_slice(&enc_u64(signers.len() as u64));
    for signer in signers {
        out.extend_from_slice(&enc_bytes(&enc_pubkey(signer)));
    }
    out.extend_from_slice(&enc_u16(threshold));
    out
}

/// Canonical encoding of a [`GenesisApprovalPolicy`] (ADR-0041 §8's
/// `canonical_genesis_approval_policy`).
pub fn canonical_genesis_approval_policy(policy: &GenesisApprovalPolicy) -> Vec<u8> {
    enc_policy_fields(policy.profile, &policy.signers, policy.threshold)
}

fn enc_rotation_policy(policy: &RotationPolicy) -> Vec<u8> {
    enc_policy_fields(policy.profile, &policy.signers, policy.threshold)
}

fn enc_entry(entry: &TrustedIssuerEntry) -> Vec<u8> {
    let mut out = enc_bytes(&enc_pubkey(&entry.pubkey));
    out.extend_from_slice(&enc_bytes(&enc_roles(&entry.roles)));
    out.extend_from_slice(&enc_i64(entry.valid_from));
    out.extend_from_slice(&enc_i64(entry.valid_until));
    out
}

/// The normative `canonical_snapshot_body` (ADR-0041 §1).
///
/// Covers `activation_at`, `active_roles`, role-scoped policies, recovery
/// keys, and every issuer field. Issuer entries are emitted in canonical
/// (sorted) order rather than declaration order, so two snapshots that differ
/// only in entry ordering produce the same digest — ordering is not protocol
/// content, and requiring callers to pre-sort would make the digest depend on
/// an unsigned property.
pub fn canonical_snapshot_body(snapshot: &TrustListSnapshotV1) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&enc_u16(snapshot.format_version));
    out.extend_from_slice(&enc_u64(snapshot.sequence));
    out.extend_from_slice(&enc_i64(snapshot.issued_at));
    out.extend_from_slice(&enc_i64(snapshot.expires_at));
    out.extend_from_slice(&enc_i64(snapshot.activation_at));
    out.extend_from_slice(&enc_bytes(
        snapshot
            .previous_snapshot_digest
            .as_ref()
            .map_or(&[][..], |d| &d[..]),
    ));
    out.extend_from_slice(&enc_bytes(&enc_roles(&snapshot.active_roles)));

    let mut entries: Vec<&TrustedIssuerEntry> = snapshot.entries.iter().collect();
    entries.sort_unstable_by(|a, b| {
        a.pubkey
            .cmp(&b.pubkey)
            .then(a.valid_from.cmp(&b.valid_from))
            .then(a.valid_until.cmp(&b.valid_until))
            .then_with(|| a.roles.iter().cmp(b.roles.iter()))
    });
    let mut entries_buf = enc_u64(entries.len() as u64);
    for entry in entries {
        entries_buf.extend_from_slice(&enc_bytes(&enc_entry(entry)));
    }
    out.extend_from_slice(&enc_bytes(&entries_buf));

    let mut policies_buf = enc_u64(snapshot.rotation_policies.len() as u64);
    for (role, policy) in &snapshot.rotation_policies {
        policies_buf.extend_from_slice(&enc_bytes(role.wire_tag().as_bytes()));
        policies_buf.extend_from_slice(&enc_bytes(&enc_rotation_policy(policy)));
    }
    out.extend_from_slice(&enc_bytes(&policies_buf));

    let mut recovery_buf = enc_u64(snapshot.recovery_keys.len() as u64);
    for (role, key) in &snapshot.recovery_keys {
        recovery_buf.extend_from_slice(&enc_bytes(role.wire_tag().as_bytes()));
        recovery_buf.extend_from_slice(&enc_bytes(&enc_pubkey(key)));
    }
    out.extend_from_slice(&enc_bytes(&recovery_buf));

    out
}

/// The canonical snapshot digest (ADR-0041 §1):
/// `BLAKE3("OLY:TRUST:SNAPSHOT:V1" || canonical_snapshot_body)`.
pub fn snapshot_digest(snapshot: &TrustListSnapshotV1) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TRUST_SNAPSHOT_V1_PREFIX);
    hasher.update(&canonical_snapshot_body(snapshot));
    *hasher.finalize().as_bytes()
}

/// The canonical per-role projection `project(S, r)` (ADR-0041 §7).
///
/// Role-scoped recovery requires `project(previous, u) == project(recovery, u)`
/// for every unrelated role `u`. Implementations must compare these canonical
/// projections, **not** serialized whole-entry bytes.
pub fn project_role(snapshot: &TrustListSnapshotV1, role: TrustRole) -> Vec<u8> {
    let mut out = enc_bytes(&[u8::from(snapshot.active_roles.contains(&role))]);

    let issuers = snapshot.projected_issuers(role);
    let mut issuers_buf = enc_u64(issuers.len() as u64);
    for (pubkey, valid_from, valid_until) in &issuers {
        let mut tuple = enc_bytes(&enc_pubkey(pubkey));
        tuple.extend_from_slice(&enc_i64(*valid_from));
        tuple.extend_from_slice(&enc_i64(*valid_until));
        issuers_buf.extend_from_slice(&enc_bytes(&tuple));
    }
    out.extend_from_slice(&enc_bytes(&issuers_buf));

    out.extend_from_slice(&enc_bytes(
        &snapshot
            .rotation_policies
            .get(&role)
            .map(enc_rotation_policy)
            .unwrap_or_default(),
    ));
    out.extend_from_slice(&enc_bytes(
        &snapshot
            .recovery_keys
            .get(&role)
            .map(enc_pubkey)
            .unwrap_or_default(),
    ));
    out
}

/// The genesis approval message (ADR-0041 §8).
///
/// ```text
/// BLAKE3(
///   OLY:TRUST:GENESIS:V1 ||
///   lp(snapshot_digest) ||
///   lp(canonical_snapshot_body) ||
///   lp(canonical_genesis_approval_policy)
/// )
/// ```
///
/// Binding the full body *and* the approval policy is what makes an approval
/// non-replayable onto another payload, signer set, profile, or threshold.
pub fn genesis_approval_message(
    snapshot: &TrustListSnapshotV1,
    approval_policy: &GenesisApprovalPolicy,
) -> [u8; 32] {
    let body = canonical_snapshot_body(snapshot);
    let digest = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(TRUST_SNAPSHOT_V1_PREFIX);
        hasher.update(&body);
        *hasher.finalize().as_bytes()
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(TRUST_GENESIS_V1_PREFIX);
    hasher.update(&length_prefixed(&digest));
    hasher.update(&length_prefixed(&body));
    hasher.update(&length_prefixed(&canonical_genesis_approval_policy(
        approval_policy,
    )));
    *hasher.finalize().as_bytes()
}

/// The routine rotation approval message (ADR-0041 §5).
///
/// ```text
/// BLAKE3(
///   OLY:TRUST:ROTATE:V1 ||
///   lp(previous_snapshot_digest) || lp(next_snapshot_digest) ||
///   lp(previous_sequence_be64) || lp(next_sequence_be64) ||
///   lp(activation_at_be64)
/// )
/// ```
///
/// Signatures bind the complete predecessor→successor transition (security
/// invariant 5), so an approval cannot be replayed onto a different successor
/// or a different activation time.
pub fn trust_rotation_message(
    previous_snapshot_digest: &[u8; 32],
    next_snapshot_digest: &[u8; 32],
    previous_sequence: u64,
    next_sequence: u64,
    activation_at: i64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TRUST_ROTATE_V1_PREFIX);
    hasher.update(&length_prefixed(previous_snapshot_digest));
    hasher.update(&length_prefixed(next_snapshot_digest));
    hasher.update(&enc_u64(previous_sequence));
    hasher.update(&enc_u64(next_sequence));
    hasher.update(&enc_i64(activation_at));
    *hasher.finalize().as_bytes()
}

/// Why a role's offline recovery key was used (ADR-0041 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RecoveryReason {
    QuorumCompromise = 1,
    QuorumUnavailable = 2,
    KeyLoss = 3,
    EmergencyRevocation = 4,
    OperatorDirectedTest = 5,
}

impl RecoveryReason {
    /// Stable reason code. Frozen — it is covered by the recovery message.
    pub fn wire_tag(self) -> &'static str {
        match self {
            RecoveryReason::QuorumCompromise => "quorum_compromise",
            RecoveryReason::QuorumUnavailable => "quorum_unavailable",
            RecoveryReason::KeyLoss => "key_loss",
            RecoveryReason::EmergencyRevocation => "emergency_revocation",
            RecoveryReason::OperatorDirectedTest => "operator_directed_test",
        }
    }

    pub fn from_wire_tag(tag: &str) -> Option<Self> {
        [
            RecoveryReason::QuorumCompromise,
            RecoveryReason::QuorumUnavailable,
            RecoveryReason::KeyLoss,
            RecoveryReason::EmergencyRevocation,
            RecoveryReason::OperatorDirectedTest,
        ]
        .into_iter()
        .find(|r| r.wire_tag() == tag)
    }
}

/// The offline role-scoped recovery approval message (ADR-0041 §5/§7).
///
/// ```text
/// BLAKE3(
///   OLY:TRUST:RECOVER:V1 ||
///   lp(role) || lp(previous_snapshot_digest) || lp(recovery_snapshot_digest) ||
///   lp(previous_sequence_be64) || lp(next_sequence_be64) ||
///   lp(reason_code) || lp(activation_at_be64)
/// )
/// ```
///
/// A separate domain from [`trust_rotation_message`], so a routine-rotation
/// approval can never be replayed as a recovery (or vice versa) even over the
/// same transition.
pub fn trust_recovery_message(
    role: TrustRole,
    previous_snapshot_digest: &[u8; 32],
    recovery_snapshot_digest: &[u8; 32],
    previous_sequence: u64,
    next_sequence: u64,
    reason: RecoveryReason,
    activation_at: i64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TRUST_RECOVER_V1_PREFIX);
    hasher.update(&length_prefixed(role.wire_tag().as_bytes()));
    hasher.update(&length_prefixed(previous_snapshot_digest));
    hasher.update(&length_prefixed(recovery_snapshot_digest));
    hasher.update(&enc_u64(previous_sequence));
    hasher.update(&enc_u64(next_sequence));
    hasher.update(&length_prefixed(reason.wire_tag().as_bytes()));
    hasher.update(&enc_i64(activation_at));
    *hasher.finalize().as_bytes()
}

// ── Transition + signer lifecycle types ───────────────────────────────────

/// Lifecycle state of a trust transition (ADR-0041 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TrustTransitionState {
    /// Validated but advisory — does **not** reserve a sequence slot.
    Staged = 1,
    /// Durable monotonic commitment to the transition.
    Accepted = 2,
    /// Currently effective for trust decisions.
    Active = 3,
}

/// How a transition came about (ADR-0041 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TrustTransitionKind {
    Genesis = 1,
    Rotation = 2,
    Recovery = 3,
}

/// Append-only lifecycle events on an immutable candidate (ADR-0041 §6).
/// Candidates are never discarded, overwritten, or mutated; every outcome is
/// an appended event referencing the original candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TrustCandidateEventKind {
    Rejected = 1,
    Superseded = 2,
    Accepted = 3,
    Activated = 4,
}

macro_rules! wire_tagged {
    ($ty:ty, $( $variant:path => $tag:literal ),+ $(,)?) => {
        impl $ty {
            /// Stable wire tag (persisted; frozen).
            pub fn wire_tag(self) -> &'static str {
                match self { $( $variant => $tag, )+ }
            }
            /// Parse a persisted tag. Fail-closed on an unknown value.
            pub fn from_wire_tag(tag: &str) -> Option<Self> {
                match tag { $( $tag => Some($variant), )+ _ => None }
            }
        }
    };
}

wire_tagged!(TrustTransitionState,
    TrustTransitionState::Staged => "staged",
    TrustTransitionState::Accepted => "accepted",
    TrustTransitionState::Active => "active",
);
wire_tagged!(TrustTransitionKind,
    TrustTransitionKind::Genesis => "genesis",
    TrustTransitionKind::Rotation => "rotation",
    TrustTransitionKind::Recovery => "recovery",
);
wire_tagged!(TrustCandidateEventKind,
    TrustCandidateEventKind::Rejected => "rejected",
    TrustCandidateEventKind::Superseded => "superseded",
    TrustCandidateEventKind::Accepted => "accepted",
    TrustCandidateEventKind::Activated => "activated",
);

/// What a locally held private key is currently used for (ADR-0041 §10).
///
/// The trust list defines *who is authorized*; this defines *which authorized
/// private key this node uses*. Sequencing is independent per purpose — there
/// is no shared global signer-activation sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SigningPurpose {
    CredentialIssuance = 1,
    Revocation = 2,
    CheckpointSigning = 3,
    FederationCosigning = 4,
}

wire_tagged!(SigningPurpose,
    SigningPurpose::CredentialIssuance => "credential_issuance",
    SigningPurpose::Revocation => "revocation",
    SigningPurpose::CheckpointSigning => "checkpoint_signing",
    SigningPurpose::FederationCosigning => "federation_cosigning",
);

impl SigningPurpose {
    /// The trust role a key must hold to be activated for this purpose.
    pub fn required_trust_role(self) -> TrustRole {
        match self {
            SigningPurpose::CredentialIssuance => TrustRole::CredentialAuthority,
            SigningPurpose::Revocation => TrustRole::RevocationAuthority,
            SigningPurpose::CheckpointSigning => TrustRole::CheckpointAuthority,
            SigningPurpose::FederationCosigning => TrustRole::FederationAuthority,
        }
    }
}

/// One append-only local signer activation (ADR-0041 §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerActivationRecord {
    pub sequence: u64,
    pub purpose: SigningPurpose,
    pub previous_pubkey: Option<TrustPubKey>,
    pub next_pubkey: TrustPubKey,
    pub trust_snapshot_sequence: u64,
    pub trust_snapshot_digest: [u8; 32],
    pub activated_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> TrustPubKey {
        TrustPubKey::new([seed; 32], [seed.wrapping_add(0x80); 32])
    }

    fn roles(list: &[TrustRole]) -> BTreeSet<TrustRole> {
        list.iter().copied().collect()
    }

    /// A minimal valid single-role snapshot: production policy (2-of-2), a
    /// distinct recovery key, one covering issuer.
    fn snapshot() -> TrustListSnapshotV1 {
        let role = TrustRole::CredentialAuthority;
        TrustListSnapshotV1 {
            format_version: 1,
            sequence: 1,
            issued_at: 1_700_000_000,
            expires_at: 1_700_090_000,
            activation_at: 1_700_000_500,
            previous_snapshot_digest: None,
            active_roles: roles(&[role]),
            entries: vec![TrustedIssuerEntry {
                pubkey: key(1),
                roles: roles(&[role]),
                valid_from: 1_700_000_100,
                valid_until: 1_700_080_000,
            }],
            rotation_policies: BTreeMap::from([(
                role,
                RotationPolicy {
                    profile: RotationPolicyProfile::Production,
                    signers: {
                        let mut s = vec![key(10), key(11)];
                        s.sort_unstable();
                        s
                    },
                    threshold: 2,
                },
            )]),
            recovery_keys: BTreeMap::from([(role, key(200))]),
        }
    }

    // ── pinned vectors ────────────────────────────────────────────────────
    //
    // These pin the wire format. A change here is a protocol change: it must
    // move every conforming implementation together (security invariant 15).

    #[test]
    fn snapshot_digest_is_pinned() {
        assert_eq!(
            hex::encode(snapshot_digest(&snapshot())),
            "b001dd192a052a36d1331d027a27ea277c7c3f555d2e096314f7733a41c59d80"
        );
    }

    #[test]
    fn domain_prefixes_are_pinned() {
        assert_eq!(TRUST_SNAPSHOT_V1_PREFIX, b"OLY:TRUST:SNAPSHOT:V1");
        assert_eq!(TRUST_ROTATE_V1_PREFIX, b"OLY:TRUST:ROTATE:V1");
        assert_eq!(TRUST_RECOVER_V1_PREFIX, b"OLY:TRUST:RECOVER:V1");
        assert_eq!(TRUST_GENESIS_V1_PREFIX, b"OLY:TRUST:GENESIS:V1");
    }

    #[test]
    fn role_and_reason_wire_tags_roundtrip() {
        for role in TrustRole::ALL {
            assert_eq!(TrustRole::from_wire_tag(role.wire_tag()), Some(role));
        }
        assert_eq!(TrustRole::from_wire_tag("not_a_role"), None);
        for reason in [
            RecoveryReason::QuorumCompromise,
            RecoveryReason::QuorumUnavailable,
            RecoveryReason::KeyLoss,
            RecoveryReason::EmergencyRevocation,
            RecoveryReason::OperatorDirectedTest,
        ] {
            assert_eq!(
                RecoveryReason::from_wire_tag(reason.wire_tag()),
                Some(reason)
            );
        }
        for state in [
            TrustTransitionState::Staged,
            TrustTransitionState::Accepted,
            TrustTransitionState::Active,
        ] {
            assert_eq!(
                TrustTransitionState::from_wire_tag(state.wire_tag()),
                Some(state)
            );
        }
        assert_eq!(TrustTransitionState::from_wire_tag("bogus"), None);
        for purpose in [
            SigningPurpose::CredentialIssuance,
            SigningPurpose::Revocation,
            SigningPurpose::CheckpointSigning,
            SigningPurpose::FederationCosigning,
        ] {
            assert_eq!(
                SigningPurpose::from_wire_tag(purpose.wire_tag()),
                Some(purpose)
            );
        }
    }

    #[test]
    fn signing_purpose_maps_to_its_required_role() {
        assert_eq!(
            SigningPurpose::CredentialIssuance.required_trust_role(),
            TrustRole::CredentialAuthority
        );
        assert_eq!(
            SigningPurpose::Revocation.required_trust_role(),
            TrustRole::RevocationAuthority
        );
        assert_eq!(
            SigningPurpose::CheckpointSigning.required_trust_role(),
            TrustRole::CheckpointAuthority
        );
        assert_eq!(
            SigningPurpose::FederationCosigning.required_trust_role(),
            TrustRole::FederationAuthority
        );
    }

    // ── digest binds every field ──────────────────────────────────────────

    #[test]
    fn snapshot_digest_binds_every_envelope_field() {
        let base = snapshot_digest(&snapshot());
        let mutate = |f: &dyn Fn(&mut TrustListSnapshotV1)| {
            let mut s = snapshot();
            f(&mut s);
            snapshot_digest(&s)
        };
        assert_ne!(base, mutate(&|s| s.sequence = 2));
        assert_ne!(base, mutate(&|s| s.issued_at += 1));
        assert_ne!(base, mutate(&|s| s.expires_at += 1));
        assert_ne!(base, mutate(&|s| s.activation_at += 1));
        assert_ne!(
            base,
            mutate(&|s| s.previous_snapshot_digest = Some([7; 32]))
        );
        assert_ne!(
            base,
            mutate(&|s| {
                s.active_roles.insert(TrustRole::RealmAuthority);
            })
        );
        assert_ne!(base, mutate(&|s| s.entries[0].valid_until -= 1));
        assert_ne!(base, mutate(&|s| s.entries[0].pubkey = key(9)));
        assert_ne!(
            base,
            mutate(&|s| {
                s.entries[0].roles.insert(TrustRole::CeremonyCoordinator);
            })
        );
        assert_ne!(
            base,
            mutate(&|s| {
                s.rotation_policies
                    .get_mut(&TrustRole::CredentialAuthority)
                    .unwrap()
                    .threshold = 1;
            })
        );
        assert_ne!(
            base,
            mutate(&|s| {
                s.rotation_policies
                    .get_mut(&TrustRole::CredentialAuthority)
                    .unwrap()
                    .profile = RotationPolicyProfile::LocalOnly;
            })
        );
        assert_ne!(
            base,
            mutate(&|s| {
                s.recovery_keys
                    .insert(TrustRole::CredentialAuthority, key(9));
            })
        );
    }

    #[test]
    fn snapshot_digest_ignores_issuer_declaration_order() {
        // Entry ordering is not protocol content — the encoder sorts.
        let role = TrustRole::CredentialAuthority;
        let mut a = snapshot();
        a.entries.push(TrustedIssuerEntry {
            pubkey: key(2),
            roles: roles(&[role]),
            valid_from: 1_700_000_100,
            valid_until: 1_700_080_000,
        });
        let mut b = a.clone();
        b.entries.reverse();
        assert_eq!(snapshot_digest(&a), snapshot_digest(&b));
    }

    #[test]
    fn genesis_none_digest_differs_from_empty_like_predecessor() {
        // `None` must not collide with any present digest.
        let mut with_pred = snapshot();
        with_pred.previous_snapshot_digest = Some([0u8; 32]);
        assert_ne!(snapshot_digest(&snapshot()), snapshot_digest(&with_pred));
    }

    // ── per-role projection (ADR-0041 §7) ─────────────────────────────────

    #[test]
    fn projection_is_stable_when_an_unrelated_role_changes_on_a_shared_entry() {
        // The load-bearing property: a shared entry gaining/losing an
        // unrelated role must NOT perturb this role's projection, or recovery
        // would falsely report an unrelated role as modified.
        let credential = TrustRole::CredentialAuthority;
        let before = snapshot();
        let mut after = snapshot();
        after.entries[0]
            .roles
            .insert(TrustRole::CheckpointAuthority);

        assert_eq!(
            project_role(&before, credential),
            project_role(&after, credential),
            "unrelated role grant must not change the credential projection"
        );
        // ...while the snapshot digest DOES change (it covers full role sets).
        assert_ne!(snapshot_digest(&before), snapshot_digest(&after));
    }

    #[test]
    fn projection_changes_when_the_role_itself_changes() {
        let role = TrustRole::CredentialAuthority;
        let base = project_role(&snapshot(), role);

        let mut window = snapshot();
        window.entries[0].valid_until -= 1;
        assert_ne!(base, project_role(&window, role));

        let mut policy = snapshot();
        policy.rotation_policies.get_mut(&role).unwrap().threshold = 1;
        assert_ne!(base, project_role(&policy, role));

        let mut recovery = snapshot();
        recovery.recovery_keys.insert(role, key(201));
        assert_ne!(base, project_role(&recovery, role));

        let mut deactivated = snapshot();
        deactivated.active_roles.remove(&role);
        assert_ne!(base, project_role(&deactivated, role));

        let mut dropped = snapshot();
        dropped.entries[0].roles.remove(&role);
        assert_ne!(base, project_role(&dropped, role));
    }

    #[test]
    fn projection_of_an_absent_role_is_stable_and_distinct() {
        let a = project_role(&snapshot(), TrustRole::RealmAuthority);
        let b = project_role(&snapshot(), TrustRole::FederationAuthority);
        assert_eq!(a, b, "two absent roles project identically (both empty)");
        assert_ne!(a, project_role(&snapshot(), TrustRole::CredentialAuthority));
    }

    // ── transition + genesis messages ─────────────────────────────────────

    #[test]
    fn rotation_message_is_pinned_and_binds_the_whole_transition() {
        let prev = [0x11u8; 32];
        let next = [0x22u8; 32];
        let base = trust_rotation_message(&prev, &next, 4, 5, 1_700_000_000);
        assert_eq!(
            hex::encode(base),
            "28c24a9f51411e98c62561d5a0c694231fa475972ec84ec43f86302ecc3428b4"
        );
        assert_ne!(
            base,
            trust_rotation_message(&[0x99; 32], &next, 4, 5, 1_700_000_000)
        );
        assert_ne!(
            base,
            trust_rotation_message(&prev, &[0x99; 32], 4, 5, 1_700_000_000)
        );
        assert_ne!(
            base,
            trust_rotation_message(&prev, &next, 3, 5, 1_700_000_000)
        );
        assert_ne!(
            base,
            trust_rotation_message(&prev, &next, 4, 6, 1_700_000_000)
        );
        assert_ne!(
            base,
            trust_rotation_message(&prev, &next, 4, 5, 1_700_000_001)
        );
    }

    #[test]
    fn recovery_message_is_domain_separated_from_rotation() {
        let prev = [0x11u8; 32];
        let next = [0x22u8; 32];
        let rotate = trust_rotation_message(&prev, &next, 4, 5, 1_700_000_000);
        let recover = trust_recovery_message(
            TrustRole::CredentialAuthority,
            &prev,
            &next,
            4,
            5,
            RecoveryReason::QuorumCompromise,
            1_700_000_000,
        );
        assert_ne!(
            rotate, recover,
            "a rotation approval must never verify as a recovery over the same transition"
        );
    }

    #[test]
    fn recovery_message_binds_role_and_reason() {
        let prev = [0x11u8; 32];
        let next = [0x22u8; 32];
        let msg =
            |role, reason| trust_recovery_message(role, &prev, &next, 4, 5, reason, 1_700_000_000);
        let base = msg(
            TrustRole::CredentialAuthority,
            RecoveryReason::QuorumCompromise,
        );
        assert_ne!(
            base,
            msg(
                TrustRole::CheckpointAuthority,
                RecoveryReason::QuorumCompromise
            ),
            "a recovery approval for one role must not authorize another"
        );
        assert_ne!(
            base,
            msg(TrustRole::CredentialAuthority, RecoveryReason::KeyLoss)
        );
    }

    #[test]
    fn genesis_approval_binds_snapshot_body_and_approval_policy() {
        let policy = GenesisApprovalPolicy {
            profile: RotationPolicyProfile::Production,
            signers: {
                let mut s = vec![key(20), key(21)];
                s.sort_unstable();
                s
            },
            threshold: 2,
        };
        let base = genesis_approval_message(&snapshot(), &policy);

        // A changed snapshot body invalidates the approval.
        let mut other_snapshot = snapshot();
        other_snapshot.activation_at += 1;
        assert_ne!(base, genesis_approval_message(&other_snapshot, &policy));

        // ...as does a changed threshold, profile, or signer set.
        let mut lower = policy.clone();
        lower.threshold = 1;
        assert_ne!(base, genesis_approval_message(&snapshot(), &lower));

        let mut profile = policy.clone();
        profile.profile = RotationPolicyProfile::LocalOnly;
        assert_ne!(base, genesis_approval_message(&snapshot(), &profile));

        let mut signers = policy.clone();
        signers.signers = {
            let mut s = vec![key(20), key(99)];
            s.sort_unstable();
            s
        };
        assert_ne!(base, genesis_approval_message(&snapshot(), &signers));
    }

    // ── snapshot validation (ADR-0041 §1–2) ───────────────────────────────

    #[test]
    fn valid_snapshot_passes() {
        assert_eq!(snapshot().validate(None), Ok(()));
        assert_eq!(snapshot().validate(Some(90_000)), Ok(()));
    }

    #[test]
    fn rejects_wrong_format_version() {
        let mut s = snapshot();
        s.format_version = 2;
        assert_eq!(
            s.validate(None),
            Err(TrustListError::UnsupportedFormatVersion(2))
        );
    }

    #[test]
    fn genesis_predecessor_rules() {
        let mut s = snapshot();
        s.previous_snapshot_digest = Some([1; 32]);
        assert_eq!(s.validate(None), Err(TrustListError::GenesisHasPredecessor));

        let mut s = snapshot();
        s.sequence = 2;
        assert_eq!(s.validate(None), Err(TrustListError::MissingPredecessor(2)));

        let mut s = snapshot();
        s.sequence = 0;
        assert_eq!(s.validate(None), Err(TrustListError::ZeroSequence));

        // sequence 2 WITH a predecessor is fine.
        let mut s = snapshot();
        s.sequence = 2;
        s.previous_snapshot_digest = Some([1; 32]);
        assert_eq!(s.validate(None), Ok(()));
    }

    #[test]
    fn rejects_out_of_order_timestamps() {
        let mut s = snapshot();
        s.activation_at = s.expires_at;
        assert_eq!(s.validate(None), Err(TrustListError::TimestampsOutOfOrder));

        let mut s = snapshot();
        s.activation_at = s.issued_at - 1;
        assert_eq!(s.validate(None), Err(TrustListError::TimestampsOutOfOrder));
    }

    #[test]
    fn rejects_lifetime_over_the_configured_maximum() {
        let s = snapshot();
        let lifetime = s.expires_at - s.issued_at;
        assert!(matches!(
            s.validate(Some(lifetime - 1)),
            Err(TrustListError::LifetimeTooLong { .. })
        ));
        assert_eq!(s.validate(Some(lifetime)), Ok(()));
    }

    #[test]
    fn rejects_issuer_without_roles_or_outside_snapshot_bounds() {
        let mut s = snapshot();
        s.entries[0].roles.clear();
        assert_eq!(s.validate(None), Err(TrustListError::IssuerWithoutRoles));

        let mut s = snapshot();
        s.entries[0].valid_from = s.issued_at - 1;
        assert_eq!(
            s.validate(None),
            Err(TrustListError::IssuerWindowOutOfBounds)
        );

        let mut s = snapshot();
        s.entries[0].valid_until = s.expires_at + 1;
        assert_eq!(
            s.validate(None),
            Err(TrustListError::IssuerWindowOutOfBounds)
        );

        let mut s = snapshot();
        s.entries[0].valid_until = s.entries[0].valid_from;
        assert_eq!(
            s.validate(None),
            Err(TrustListError::IssuerWindowOutOfBounds)
        );
    }

    #[test]
    fn duplicate_key_merges_only_with_identical_metadata() {
        // Same key, same window, different roles → merges (allowed).
        let mut ok = snapshot();
        let mut twin = ok.entries[0].clone();
        twin.roles = roles(&[TrustRole::CeremonyCoordinator]);
        ok.entries.push(twin);
        assert_eq!(ok.validate(None), Ok(()));

        // Same key, DIFFERENT window → ambiguous.
        let mut bad = snapshot();
        let mut twin = bad.entries[0].clone();
        twin.valid_until -= 1;
        bad.entries.push(twin);
        assert_eq!(
            bad.validate(None),
            Err(TrustListError::AmbiguousDuplicateIssuer)
        );
    }

    #[test]
    fn rejects_active_role_without_coverage_policy_or_recovery_key() {
        // Active role whose only issuer's window misses activation_at.
        let mut s = snapshot();
        s.entries[0].valid_from = s.activation_at + 1;
        s.entries[0].valid_until = s.activation_at + 2;
        assert_eq!(
            s.validate(None),
            Err(TrustListError::RoleNotCovered("credential_authority"))
        );

        let mut s = snapshot();
        s.rotation_policies.clear();
        assert_eq!(
            s.validate(None),
            Err(TrustListError::RoleMissingPolicy("credential_authority"))
        );

        let mut s = snapshot();
        s.recovery_keys.clear();
        assert_eq!(
            s.validate(None),
            Err(TrustListError::RoleMissingRecoveryKey(
                "credential_authority"
            ))
        );
    }

    #[test]
    fn inactive_role_grants_nothing_and_needs_no_policy() {
        // Staged migration: an entry may name a role that is not active, and
        // that role needs no policy/recovery key (ADR-0041 §1).
        let mut s = snapshot();
        s.entries[0].roles.insert(TrustRole::RealmAuthority);
        assert_eq!(s.validate(None), Ok(()));
        assert!(!s.active_roles.contains(&TrustRole::RealmAuthority));
    }

    #[test]
    fn rejects_recovery_key_inside_the_routine_quorum() {
        // Security invariant 12: routine quorum members alone must not be
        // able to invoke recovery.
        let role = TrustRole::CredentialAuthority;
        let mut s = snapshot();
        let quorum_member = s.rotation_policies[&role].signers[0];
        s.recovery_keys.insert(role, quorum_member);
        assert_eq!(
            s.validate(None),
            Err(TrustListError::RecoveryKeyInRoutineQuorum(
                "credential_authority"
            ))
        );
    }

    // ── policy validation (ADR-0041 §2) ───────────────────────────────────

    #[test]
    fn policy_rejects_bad_thresholds_and_signer_sets() {
        let two = {
            let mut s = vec![key(10), key(11)];
            s.sort_unstable();
            s
        };
        let policy = |profile, signers: Vec<TrustPubKey>, threshold| RotationPolicy {
            profile,
            signers,
            threshold,
        };

        assert_eq!(
            policy(RotationPolicyProfile::Production, vec![], 1).validate(),
            Err(TrustListError::EmptySignerSet)
        );
        assert!(matches!(
            policy(RotationPolicyProfile::Production, two.clone(), 3).validate(),
            Err(TrustListError::ThresholdOutOfRange { .. })
        ));
        assert!(matches!(
            policy(RotationPolicyProfile::Production, two.clone(), 0).validate(),
            Err(TrustListError::ThresholdOutOfRange { .. })
        ));
        // Production demands >= 2 even though 1 is "in range".
        assert!(matches!(
            policy(RotationPolicyProfile::Production, two.clone(), 1).validate(),
            Err(TrustListError::ProductionThresholdTooLow { threshold: 1 })
        ));
        // LocalOnly may use 1.
        assert_eq!(
            policy(RotationPolicyProfile::LocalOnly, two.clone(), 1).validate(),
            Ok(())
        );

        // Unsorted and duplicate signer sets are both rejected.
        let mut unsorted = two.clone();
        unsorted.reverse();
        assert_eq!(
            policy(RotationPolicyProfile::Production, unsorted, 2).validate(),
            Err(TrustListError::SignersNotCanonicallyOrdered)
        );
        assert_eq!(
            policy(RotationPolicyProfile::Production, vec![key(10), key(10)], 2).validate(),
            Err(TrustListError::SignersNotCanonicallyOrdered)
        );
    }

    #[test]
    fn genesis_policy_uses_the_same_rules() {
        let policy = GenesisApprovalPolicy {
            profile: RotationPolicyProfile::Production,
            signers: vec![key(20)],
            threshold: 1,
        };
        assert!(matches!(
            policy.validate(),
            Err(TrustListError::ProductionThresholdTooLow { threshold: 1 })
        ));
    }

    #[test]
    fn local_only_profile_is_flagged_as_deployment_restricted() {
        assert!(RotationPolicyProfile::LocalOnly.requires_local_only_deployment());
        assert!(!RotationPolicyProfile::Production.requires_local_only_deployment());
    }
}
