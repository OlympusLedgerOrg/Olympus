// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! ADR-0041 serde JSON **storage** representation for trust-list snapshots
//! and signed transition files.
//!
//! # JSON is STORAGE ONLY — it is never a protocol encoding
//!
//! ADR-0041 §1: "It uses one normative deterministic encoder with published
//! test vectors. Default Serde JSON output is not itself a protocol
//! encoding." The digest of a snapshot is **always** recomputed from
//! [`canonical_snapshot_body`] over the *decoded* value — never from JSON
//! bytes, a stored digest column, or any other serialized form. Two JSON
//! documents that differ in key order, whitespace, or field ordering decode
//! to the same snapshot and therefore the same digest; a JSON document whose
//! *content* was tampered with decodes to a different snapshot whose
//! recomputed digest no longer matches whatever approval signatures or
//! stored digest accompanied it.
//!
//! Every load MUST round-trip through [`TrustListSnapshotV1::validate`] and a
//! digest recomputation before the decoded value is trusted for anything.
//! [`TrustSnapshotWireV1::try_into_snapshot`] deliberately returns the bare
//! snapshot rather than a "validated" wrapper so the caller's validate +
//! digest-check step stays visible at the call site (and testable against
//! tampered inputs).
//!
//! # Field encodings
//!
//! * Snapshot public keys and digests are **64-char lowercase hex** of the
//!   canonical 32-byte big-endian protocol bytes. Uppercase or odd-length
//!   hex is rejected rather than normalised: a storage layer that accepted
//!   two spellings of one key would let one snapshot exist as two unequal
//!   JSON files, defeating losslessness.
//! * Enum-valued fields carry the frozen `wire_tag` strings from
//!   [`trust_list`](crate::trust_list) (`"credential_authority"`,
//!   `"production"`, `"rotation"`, …). Unknown tags are typed errors, never
//!   defaults (fail closed).
//! * Approval signatures ([`TrustApprovalWire`]) carry BJJ coordinates as
//!   **canonical decimal** `Fr` strings — the exact shape the desktop
//!   quorum verifier's `CollectedSignature` serialises to — so a transition
//!   file's `approvals` array can be handed to the quorum layer without a
//!   re-encoding step that could silently normalise a non-canonical value.
//!   This module treats them as opaque strings: parsing/validating decimals
//!   needs a field stack this crate deliberately does not have.
//!
//! # Losslessness
//!
//! Maps are stored as arrays of `{role, …}` objects rather than JSON
//! objects, and duplicates (roles, issuer roles) are rejected instead of
//! being last-write-wins merged — a duplicate key silently collapsing would
//! make decode(encode(x)) ≠ x for no observable reason. Unknown JSON fields
//! are rejected (`deny_unknown_fields`): a typo'd optional field must fail
//! loudly, not be dropped.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

use crate::trust_list::{
    GenesisApprovalPolicy, RecoveryReason, RotationPolicy, RotationPolicyProfile,
    TrustListSnapshotV1, TrustPubKey, TrustRole, TrustTransitionKind, TrustedIssuerEntry,
};

/// The only transition-file format version this module encodes or decodes.
pub const TRUST_TRANSITION_FILE_FORMAT_VERSION: u16 = 1;

/// Decode failures for the storage representation. Every variant is a
/// fail-closed rejection — there are no lossy fallbacks.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustWireError {
    #[error(
        "unsupported transition file format_version {0} \
         (expected {TRUST_TRANSITION_FILE_FORMAT_VERSION})"
    )]
    UnsupportedFileFormatVersion(u16),
    #[error("{field} is not 64-char lowercase hex of 32 bytes")]
    InvalidHex32 { field: &'static str },
    #[error("unknown trust role tag {0:?}")]
    UnknownRoleTag(String),
    #[error("duplicate trust role tag {0:?} (a duplicate would silently merge on decode)")]
    DuplicateRoleTag(String),
    #[error("unknown rotation policy profile tag {0:?}")]
    UnknownProfileTag(String),
    #[error("unknown transition kind tag {0:?}")]
    UnknownKindTag(String),
    #[error("unknown recovery reason tag {0:?}")]
    UnknownReasonTag(String),
    #[error("transition kind {kind:?} requires recovery_role and recovery_reason")]
    MissingRecoveryFields { kind: &'static str },
    #[error("transition kind {kind:?} must not carry recovery_role/recovery_reason")]
    UnexpectedRecoveryFields { kind: &'static str },
    #[error("genesis transition requires genesis_approval_policy")]
    MissingGenesisApprovalPolicy,
    #[error("transition kind {kind:?} must not carry genesis_approval_policy")]
    UnexpectedGenesisApprovalPolicy { kind: &'static str },
}

fn hex32_encode(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

/// Strict decode: exactly 64 lowercase hex chars. `hex::decode` alone would
/// also accept uppercase, which would let one key exist as two unequal
/// storage spellings.
fn hex32_decode(s: &str, field: &'static str) -> Result<[u8; 32], TrustWireError> {
    let err = || TrustWireError::InvalidHex32 { field };
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(err());
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| err())?;
    Ok(out)
}

fn role_from_tag(tag: &str) -> Result<TrustRole, TrustWireError> {
    TrustRole::from_wire_tag(tag).ok_or_else(|| TrustWireError::UnknownRoleTag(tag.to_owned()))
}

fn roles_from_tags(tags: &[String]) -> Result<BTreeSet<TrustRole>, TrustWireError> {
    let mut out = BTreeSet::new();
    for tag in tags {
        let role = role_from_tag(tag)?;
        if !out.insert(role) {
            return Err(TrustWireError::DuplicateRoleTag(tag.clone()));
        }
    }
    Ok(out)
}

fn roles_to_tags(roles: &BTreeSet<TrustRole>) -> Vec<String> {
    roles.iter().map(|r| r.wire_tag().to_owned()).collect()
}

// ── Wire shapes ───────────────────────────────────────────────────────────

/// A Baby Jubjub public key as 64-char lowercase hex of the canonical
/// 32-byte big-endian coordinates (the [`TrustPubKey`] protocol bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPubKeyWire {
    pub x: String,
    pub y: String,
}

impl TrustPubKeyWire {
    pub fn from_key(key: &TrustPubKey) -> Self {
        Self {
            x: hex32_encode(&key.x),
            y: hex32_encode(&key.y),
        }
    }

    pub fn try_into_key(&self) -> Result<TrustPubKey, TrustWireError> {
        Ok(TrustPubKey::new(
            hex32_decode(&self.x, "pubkey.x")?,
            hex32_decode(&self.y, "pubkey.y")?,
        ))
    }
}

/// One trusted issuer entry (ADR-0041 §1) in storage form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedIssuerEntryWire {
    pub pubkey: TrustPubKeyWire,
    pub roles: Vec<String>,
    pub valid_from: i64,
    pub valid_until: i64,
}

/// An M-of-N approval policy in storage form. Shared by role rotation
/// policies and the genesis approval policy — the two are distinguished by
/// where they appear, exactly as the protocol types are distinct Rust types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdPolicyWire {
    pub profile: String,
    pub signers: Vec<TrustPubKeyWire>,
    pub threshold: u16,
}

impl ThresholdPolicyWire {
    fn from_parts(profile: RotationPolicyProfile, signers: &[TrustPubKey], threshold: u16) -> Self {
        Self {
            profile: profile.wire_tag().to_owned(),
            signers: signers.iter().map(TrustPubKeyWire::from_key).collect(),
            threshold,
        }
    }

    fn try_into_parts(
        &self,
    ) -> Result<(RotationPolicyProfile, Vec<TrustPubKey>, u16), TrustWireError> {
        let profile = RotationPolicyProfile::from_wire_tag(&self.profile)
            .ok_or_else(|| TrustWireError::UnknownProfileTag(self.profile.clone()))?;
        let signers = self
            .signers
            .iter()
            .map(TrustPubKeyWire::try_into_key)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((profile, signers, self.threshold))
    }

    pub fn from_rotation_policy(policy: &RotationPolicy) -> Self {
        Self::from_parts(policy.profile, &policy.signers, policy.threshold)
    }

    pub fn try_into_rotation_policy(&self) -> Result<RotationPolicy, TrustWireError> {
        let (profile, signers, threshold) = self.try_into_parts()?;
        Ok(RotationPolicy {
            profile,
            signers,
            threshold,
        })
    }

    pub fn from_genesis_policy(policy: &GenesisApprovalPolicy) -> Self {
        Self::from_parts(policy.profile, &policy.signers, policy.threshold)
    }

    pub fn try_into_genesis_policy(&self) -> Result<GenesisApprovalPolicy, TrustWireError> {
        let (profile, signers, threshold) = self.try_into_parts()?;
        Ok(GenesisApprovalPolicy {
            profile,
            signers,
            threshold,
        })
    }
}

/// A `role → rotation policy` binding. Stored as an array element rather
/// than a JSON-object key so a duplicate role is a typed error instead of a
/// silent last-write-wins merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolePolicyWire {
    pub role: String,
    pub policy: ThresholdPolicyWire,
}

/// A `role → recovery key` binding (same array-not-object reasoning).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleRecoveryKeyWire {
    pub role: String,
    pub key: TrustPubKeyWire,
}

/// Lossless storage form of [`TrustListSnapshotV1`].
///
/// See the module docs: this shape is never hashed or signed. The digest is
/// recomputed from [`canonical_snapshot_body`] over the decoded snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustSnapshotWireV1 {
    pub format_version: u16,
    pub sequence: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub activation_at: i64,
    /// 64-char lowercase hex; absent (never `null`-with-meaning) for genesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_snapshot_digest: Option<String>,
    pub active_roles: Vec<String>,
    pub entries: Vec<TrustedIssuerEntryWire>,
    pub rotation_policies: Vec<RolePolicyWire>,
    pub recovery_keys: Vec<RoleRecoveryKeyWire>,
}

impl TrustSnapshotWireV1 {
    /// Encode a protocol snapshot for storage. Infallible: every protocol
    /// value has exactly one storage spelling.
    pub fn from_snapshot(snapshot: &TrustListSnapshotV1) -> Self {
        Self {
            format_version: snapshot.format_version,
            sequence: snapshot.sequence,
            issued_at: snapshot.issued_at,
            expires_at: snapshot.expires_at,
            activation_at: snapshot.activation_at,
            previous_snapshot_digest: snapshot.previous_snapshot_digest.as_ref().map(hex32_encode),
            active_roles: roles_to_tags(&snapshot.active_roles),
            entries: snapshot
                .entries
                .iter()
                .map(|e| TrustedIssuerEntryWire {
                    pubkey: TrustPubKeyWire::from_key(&e.pubkey),
                    roles: roles_to_tags(&e.roles),
                    valid_from: e.valid_from,
                    valid_until: e.valid_until,
                })
                .collect(),
            rotation_policies: snapshot
                .rotation_policies
                .iter()
                .map(|(role, policy)| RolePolicyWire {
                    role: role.wire_tag().to_owned(),
                    policy: ThresholdPolicyWire::from_rotation_policy(policy),
                })
                .collect(),
            recovery_keys: snapshot
                .recovery_keys
                .iter()
                .map(|(role, key)| RoleRecoveryKeyWire {
                    role: role.wire_tag().to_owned(),
                    key: TrustPubKeyWire::from_key(key),
                })
                .collect(),
        }
    }

    /// Decode back to the protocol snapshot.
    ///
    /// This checks only *storage-shape* validity (hex, tags, duplicates).
    /// The caller MUST still run [`TrustListSnapshotV1::validate`] and
    /// recompute the digest via
    /// [`snapshot_digest`](crate::trust_list::snapshot_digest) — see the
    /// module docs.
    pub fn try_into_snapshot(&self) -> Result<TrustListSnapshotV1, TrustWireError> {
        let previous_snapshot_digest = self
            .previous_snapshot_digest
            .as_deref()
            .map(|s| hex32_decode(s, "previous_snapshot_digest"))
            .transpose()?;

        let mut rotation_policies: BTreeMap<TrustRole, RotationPolicy> = BTreeMap::new();
        for entry in &self.rotation_policies {
            let role = role_from_tag(&entry.role)?;
            if rotation_policies
                .insert(role, entry.policy.try_into_rotation_policy()?)
                .is_some()
            {
                return Err(TrustWireError::DuplicateRoleTag(entry.role.clone()));
            }
        }
        let mut recovery_keys: BTreeMap<TrustRole, TrustPubKey> = BTreeMap::new();
        for entry in &self.recovery_keys {
            let role = role_from_tag(&entry.role)?;
            if recovery_keys
                .insert(role, entry.key.try_into_key()?)
                .is_some()
            {
                return Err(TrustWireError::DuplicateRoleTag(entry.role.clone()));
            }
        }

        Ok(TrustListSnapshotV1 {
            format_version: self.format_version,
            sequence: self.sequence,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            activation_at: self.activation_at,
            previous_snapshot_digest,
            active_roles: roles_from_tags(&self.active_roles)?,
            entries: self
                .entries
                .iter()
                .map(|e| {
                    Ok(TrustedIssuerEntry {
                        pubkey: e.pubkey.try_into_key()?,
                        roles: roles_from_tags(&e.roles)?,
                        valid_from: e.valid_from,
                        valid_until: e.valid_until,
                    })
                })
                .collect::<Result<Vec<_>, TrustWireError>>()?,
            rotation_policies,
            recovery_keys,
        })
    }
}

/// One collected BJJ-EdDSA approval signature over a domain-separated trust
/// message (rotation, recovery, or genesis — the file's `kind` says which).
///
/// Coordinates and signature components are **canonical decimal** `Fr`
/// strings — deliberately the serialized shape of the desktop quorum
/// verifier's `CollectedSignature` (signer `x`/`y` flattened beside
/// `r8x`/`r8y`/`s`), so the desktop can deserialize `approvals` directly
/// into its quorum types. Opaque at this layer; the quorum verifier is
/// where canonical-decimal parsing (and therefore rejection of `"007"`-style
/// aliases) happens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustApprovalWire {
    pub x: String,
    pub y: String,
    pub r8x: String,
    pub r8y: String,
    pub s: String,
}

/// Storage form of a signed transition file: a candidate snapshot plus the
/// approval signatures collected for it (ADR-0041 §5–§8). This is the file
/// the future genesis/rotation/recovery CLIs exchange and the shape the
/// transition-candidate store persists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustTransitionFileWireV1 {
    /// Always [`TRUST_TRANSITION_FILE_FORMAT_VERSION`].
    pub format_version: u16,
    /// [`TrustTransitionKind`] wire tag.
    pub kind: String,
    pub snapshot: TrustSnapshotWireV1,
    pub approvals: Vec<TrustApprovalWire>,
    /// Recovery only: the [`TrustRole`] wire tag of the recovering role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_role: Option<String>,
    /// Recovery only: the [`RecoveryReason`] wire tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_reason: Option<String>,
    /// Genesis only: the explicit approval policy the genesis approvals were
    /// verified against (ADR-0041 §8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_approval_policy: Option<ThresholdPolicyWire>,
}

/// Decoded, shape-checked transition file. Approvals stay in wire form (this
/// crate has no field stack to parse them); everything else is protocol-typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustTransitionFile {
    pub kind: TrustTransitionKind,
    pub snapshot: TrustListSnapshotV1,
    pub approvals: Vec<TrustApprovalWire>,
    /// `Some` iff `kind == Recovery`.
    pub recovery: Option<(TrustRole, RecoveryReason)>,
    /// `Some` iff `kind == Genesis`.
    pub genesis_approval_policy: Option<GenesisApprovalPolicy>,
}

impl TrustTransitionFileWireV1 {
    /// Encode a decoded transition file for storage.
    pub fn from_file(file: &TrustTransitionFile) -> Self {
        Self {
            format_version: TRUST_TRANSITION_FILE_FORMAT_VERSION,
            kind: file.kind.wire_tag().to_owned(),
            snapshot: TrustSnapshotWireV1::from_snapshot(&file.snapshot),
            approvals: file.approvals.clone(),
            recovery_role: file
                .recovery
                .as_ref()
                .map(|(role, _)| role.wire_tag().to_owned()),
            recovery_reason: file
                .recovery
                .as_ref()
                .map(|(_, reason)| reason.wire_tag().to_owned()),
            genesis_approval_policy: file
                .genesis_approval_policy
                .as_ref()
                .map(ThresholdPolicyWire::from_genesis_policy),
        }
    }

    /// Decode and enforce per-kind shape consistency: recovery fields appear
    /// exactly on recovery files, the genesis approval policy exactly on
    /// genesis files. A file that mixes kinds is rejected — accepting it
    /// would leave a persisted candidate whose authorization inputs are
    /// ambiguous.
    pub fn try_into_file(&self) -> Result<TrustTransitionFile, TrustWireError> {
        if self.format_version != TRUST_TRANSITION_FILE_FORMAT_VERSION {
            return Err(TrustWireError::UnsupportedFileFormatVersion(
                self.format_version,
            ));
        }
        let kind = TrustTransitionKind::from_wire_tag(&self.kind)
            .ok_or_else(|| TrustWireError::UnknownKindTag(self.kind.clone()))?;
        let kind_tag = kind.wire_tag();

        let recovery = match (kind, &self.recovery_role, &self.recovery_reason) {
            (TrustTransitionKind::Recovery, Some(role), Some(reason)) => Some((
                role_from_tag(role)?,
                RecoveryReason::from_wire_tag(reason)
                    .ok_or_else(|| TrustWireError::UnknownReasonTag(reason.clone()))?,
            )),
            (TrustTransitionKind::Recovery, _, _) => {
                return Err(TrustWireError::MissingRecoveryFields { kind: kind_tag })
            }
            (_, None, None) => None,
            (_, _, _) => return Err(TrustWireError::UnexpectedRecoveryFields { kind: kind_tag }),
        };
        let genesis_approval_policy = match (kind, &self.genesis_approval_policy) {
            (TrustTransitionKind::Genesis, Some(policy)) => Some(policy.try_into_genesis_policy()?),
            (TrustTransitionKind::Genesis, None) => {
                return Err(TrustWireError::MissingGenesisApprovalPolicy)
            }
            (_, None) => None,
            (_, Some(_)) => {
                return Err(TrustWireError::UnexpectedGenesisApprovalPolicy { kind: kind_tag })
            }
        };

        Ok(TrustTransitionFile {
            kind,
            snapshot: self.snapshot.try_into_snapshot()?,
            approvals: self.approvals.clone(),
            recovery,
            genesis_approval_policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_list::snapshot_digest;

    fn key(seed: u8) -> TrustPubKey {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x[30] = 0xA1;
        x[31] = seed;
        y[30] = 0xB2;
        y[31] = seed;
        TrustPubKey::new(x, y)
    }

    fn roles(list: &[TrustRole]) -> BTreeSet<TrustRole> {
        list.iter().copied().collect()
    }

    /// The same minimal valid snapshot `trust_list`'s tests pin vectors
    /// against, so wire round-trips are exercised on a `validate`-clean value.
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
                roles: roles(&[role, TrustRole::CeremonyCoordinator]),
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

    fn transition_file(kind: TrustTransitionKind) -> TrustTransitionFile {
        TrustTransitionFile {
            kind,
            snapshot: snapshot(),
            approvals: vec![TrustApprovalWire {
                x: "7".into(),
                y: "8".into(),
                r8x: "1".into(),
                r8y: "2".into(),
                s: "3".into(),
            }],
            recovery: (kind == TrustTransitionKind::Recovery).then_some((
                TrustRole::CredentialAuthority,
                RecoveryReason::QuorumCompromise,
            )),
            genesis_approval_policy: (kind == TrustTransitionKind::Genesis).then(|| {
                GenesisApprovalPolicy {
                    profile: RotationPolicyProfile::Production,
                    signers: {
                        let mut s = vec![key(20), key(21)];
                        s.sort_unstable();
                        s
                    },
                    threshold: 2,
                }
            }),
        }
    }

    #[test]
    fn snapshot_round_trips_losslessly_through_json() {
        let original = snapshot();
        let wire = TrustSnapshotWireV1::from_snapshot(&original);
        let json = serde_json::to_string(&wire).expect("serialize");
        let parsed: TrustSnapshotWireV1 = serde_json::from_str(&json).expect("deserialize");
        let decoded = parsed.try_into_snapshot().expect("decode");
        assert_eq!(decoded, original, "round-trip must be lossless");
        assert_eq!(
            snapshot_digest(&decoded),
            snapshot_digest(&original),
            "recomputed digest must survive the round-trip"
        );
        assert_eq!(decoded.validate(None), Ok(()));

        // A non-genesis snapshot exercises the Option<digest> arm too.
        let mut successor = original.clone();
        successor.sequence = 2;
        successor.previous_snapshot_digest = Some(snapshot_digest(&original));
        let wire = TrustSnapshotWireV1::from_snapshot(&successor);
        let decoded = serde_json::from_str::<TrustSnapshotWireV1>(
            &serde_json::to_string(&wire).expect("serialize"),
        )
        .expect("deserialize")
        .try_into_snapshot()
        .expect("decode");
        assert_eq!(decoded, successor);
    }

    #[test]
    fn json_field_reordering_does_not_change_the_recomputed_digest() {
        // Serialize, then rebuild the JSON object with every key order
        // reversed (recursively) — a byte-different document that must decode
        // to the same snapshot and therefore the same recomputed digest.
        // This is the module contract: the digest comes from
        // `canonical_snapshot_body`, never from JSON bytes.
        fn reverse_keys(v: &serde_json::Value) -> serde_json::Value {
            match v {
                serde_json::Value::Object(map) => {
                    let mut out = serde_json::Map::new();
                    for (k, v) in map.iter().rev() {
                        out.insert(k.clone(), reverse_keys(v));
                    }
                    serde_json::Value::Object(out)
                }
                serde_json::Value::Array(items) => {
                    serde_json::Value::Array(items.iter().map(reverse_keys).collect())
                }
                other => other.clone(),
            }
        }

        let original = snapshot();
        let straight = serde_json::to_string(&TrustSnapshotWireV1::from_snapshot(&original))
            .expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&straight).expect("parse");
        let reordered = serde_json::to_string(&reverse_keys(&value)).expect("re-serialize");
        assert_ne!(
            straight, reordered,
            "the reordered document must actually differ byte-wise for this test to mean anything"
        );

        let decoded: TrustSnapshotWireV1 = serde_json::from_str(&reordered).expect("deserialize");
        let decoded = decoded.try_into_snapshot().expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(snapshot_digest(&decoded), snapshot_digest(&original));
    }

    #[test]
    fn tampered_json_content_changes_the_recomputed_digest_and_fails_a_stored_digest_check() {
        // The load contract: recompute the digest from the decoded value and
        // compare against the stored/approved digest. Content tampering
        // survives JSON decode but MUST fail that comparison.
        let original = snapshot();
        let stored_digest = snapshot_digest(&original);
        let mut value: serde_json::Value =
            serde_json::to_value(TrustSnapshotWireV1::from_snapshot(&original)).expect("encode");
        value["activation_at"] = serde_json::json!(1_700_000_501);

        let tampered: TrustSnapshotWireV1 =
            serde_json::from_value(value).expect("still well-formed JSON");
        let decoded = tampered.try_into_snapshot().expect("still decodes");
        assert_ne!(
            snapshot_digest(&decoded),
            stored_digest,
            "a tampered activation_at must change the recomputed digest"
        );
    }

    #[test]
    fn tampered_json_shape_fails_decode_with_the_typed_reason() {
        let wire = || TrustSnapshotWireV1::from_snapshot(&snapshot());

        let mut bad_hex = wire();
        bad_hex.entries[0].pubkey.x = "ZZ".repeat(32);
        assert_eq!(
            bad_hex.try_into_snapshot(),
            Err(TrustWireError::InvalidHex32 { field: "pubkey.x" })
        );

        let mut uppercase_hex = wire();
        uppercase_hex.entries[0].pubkey.x = uppercase_hex.entries[0].pubkey.x.to_uppercase();
        assert_eq!(
            uppercase_hex.try_into_snapshot(),
            Err(TrustWireError::InvalidHex32 { field: "pubkey.x" }),
            "uppercase hex is a second spelling of the same key — rejected for losslessness"
        );

        let mut short_digest = wire();
        short_digest.previous_snapshot_digest = Some("abcd".into());
        assert_eq!(
            short_digest.try_into_snapshot(),
            Err(TrustWireError::InvalidHex32 {
                field: "previous_snapshot_digest"
            })
        );

        let mut unknown_role = wire();
        unknown_role.active_roles = vec!["credential-authority".into()];
        assert_eq!(
            unknown_role.try_into_snapshot(),
            Err(TrustWireError::UnknownRoleTag(
                "credential-authority".into()
            ))
        );

        let mut duplicate_role = wire();
        duplicate_role
            .active_roles
            .push("credential_authority".into());
        assert_eq!(
            duplicate_role.try_into_snapshot(),
            Err(TrustWireError::DuplicateRoleTag(
                "credential_authority".into()
            ))
        );

        let mut duplicate_policy = wire();
        let dup = duplicate_policy.rotation_policies[0].clone();
        duplicate_policy.rotation_policies.push(dup);
        assert_eq!(
            duplicate_policy.try_into_snapshot(),
            Err(TrustWireError::DuplicateRoleTag(
                "credential_authority".into()
            ))
        );

        let mut unknown_profile = wire();
        unknown_profile.rotation_policies[0].policy.profile = "Production".into();
        assert_eq!(
            unknown_profile.try_into_snapshot(),
            Err(TrustWireError::UnknownProfileTag("Production".into()))
        );

        // An unknown JSON field is a serde-level rejection (deny_unknown_fields),
        // not a silent drop. Assert the specific rejection reason, not just
        // is_err(), so this doesn't pass on an unrelated parse failure.
        let mut value: serde_json::Value = serde_json::to_value(wire()).expect("encode");
        value["surprise_field"] = serde_json::json!(true);
        let error = serde_json::from_value::<TrustSnapshotWireV1>(value).unwrap_err();
        assert!(
            error.to_string().contains("surprise_field"),
            "expected an unknown-field rejection naming surprise_field, got: {error}"
        );
    }

    #[test]
    fn transition_file_round_trips_for_every_kind() {
        for kind in [
            TrustTransitionKind::Genesis,
            TrustTransitionKind::Rotation,
            TrustTransitionKind::Recovery,
        ] {
            let original = transition_file(kind);
            let wire = TrustTransitionFileWireV1::from_file(&original);
            let json = serde_json::to_string(&wire).expect("serialize");
            let decoded = serde_json::from_str::<TrustTransitionFileWireV1>(&json)
                .expect("deserialize")
                .try_into_file()
                .expect("decode");
            assert_eq!(decoded, original, "{kind:?} file must round-trip");
        }
    }

    #[test]
    fn transition_file_rejects_kind_shape_mismatches() {
        // Rotation carrying recovery fields.
        let mut wire =
            TrustTransitionFileWireV1::from_file(&transition_file(TrustTransitionKind::Rotation));
        wire.recovery_role = Some("credential_authority".into());
        wire.recovery_reason = Some("key_loss".into());
        assert_eq!(
            wire.try_into_file(),
            Err(TrustWireError::UnexpectedRecoveryFields { kind: "rotation" })
        );

        // Recovery missing its reason.
        let mut wire =
            TrustTransitionFileWireV1::from_file(&transition_file(TrustTransitionKind::Recovery));
        wire.recovery_reason = None;
        assert_eq!(
            wire.try_into_file(),
            Err(TrustWireError::MissingRecoveryFields { kind: "recovery" })
        );

        // Recovery with an unknown reason tag.
        let mut wire =
            TrustTransitionFileWireV1::from_file(&transition_file(TrustTransitionKind::Recovery));
        wire.recovery_reason = Some("panic".into());
        assert_eq!(
            wire.try_into_file(),
            Err(TrustWireError::UnknownReasonTag("panic".into()))
        );

        // Genesis without its approval policy.
        let mut wire =
            TrustTransitionFileWireV1::from_file(&transition_file(TrustTransitionKind::Genesis));
        wire.genesis_approval_policy = None;
        assert_eq!(
            wire.try_into_file(),
            Err(TrustWireError::MissingGenesisApprovalPolicy)
        );

        // Rotation carrying a genesis approval policy.
        let mut wire =
            TrustTransitionFileWireV1::from_file(&transition_file(TrustTransitionKind::Rotation));
        wire.genesis_approval_policy = Some(ThresholdPolicyWire {
            profile: "production".into(),
            signers: vec![TrustPubKeyWire::from_key(&key(20))],
            threshold: 1,
        });
        assert_eq!(
            wire.try_into_file(),
            Err(TrustWireError::UnexpectedGenesisApprovalPolicy { kind: "rotation" })
        );

        // Unknown kind and unsupported version.
        let mut wire =
            TrustTransitionFileWireV1::from_file(&transition_file(TrustTransitionKind::Rotation));
        wire.kind = "upgrade".into();
        assert_eq!(
            wire.try_into_file(),
            Err(TrustWireError::UnknownKindTag("upgrade".into()))
        );
        let mut wire =
            TrustTransitionFileWireV1::from_file(&transition_file(TrustTransitionKind::Rotation));
        wire.format_version = 2;
        assert_eq!(
            wire.try_into_file(),
            Err(TrustWireError::UnsupportedFileFormatVersion(2))
        );
    }
}
