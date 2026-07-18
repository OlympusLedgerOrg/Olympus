//! Ceremony manifest — runtime integrity checks for ZK artifacts.
//!
//! See `proofs/CEREMONY_INTEGRITY.md` for the full operational protocol.
//! This module implements the four runtime checks that doc specifies:
//!
//!   1. Compile-time: build.rs asserts `blake3(vkey.json)` matches the
//!      embedded manifest's `artifacts.vkey.blake3`.
//!   2. Runtime: `load_proving_key_with_manifest` hashes the `.ark.zkey`
//!      file before deserialize and rejects on mismatch.
//!   3. Startup: main.rs verifies each manifest's coordinator BJJ-EdDSA
//!      signature against `state.bjj_trusted_issuers` (audit M-3). The
//!      signed message (V2) binds the full artifact map (vkey/zkey/r1cs/
//!      wasm blake3) + circuit + ceremony id + contribution chain, so the
//!      coordinator's signature covers the exact bytes the runtime loads —
//!      not merely the contribution-chain hash (the V1 gap that let a
//!      manifest-editing attacker swap the verification key undetected).
//!   4. Production: under `OLYMPUS_ENV=production`, any failure above
//!      hard-exits with code 2.
//!
//! Why this exists: during the 2026-05-26 audit work, an
//! ark.zkey-from-ceremony-A + vkey-from-ceremony-B mismatch produced a
//! two-hour "proof fails to verify" debugging session. Adding a 30-second
//! blake3 check at startup would have produced an immediate
//! `ManifestMismatch{kind: "ark_zkey", ...}` error instead.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::api::trusted_issuers::TrustedIssuer;
use crate::zk::witness::baby_jubjub::{self, BabyJubJubPubKey, BabyJubJubSignature};

/// Schema version that this Rust deserializer accepts. Bump only with a
/// migration plan that handles older manifests on consumer machines.
///
/// Note: the JSON *schema* is unchanged across the V1→V2 coordinator-signing
/// recipe change (no fields added/removed), so this stays `1`. The recipe
/// change is carried by the domain tag [`MANIFEST_SIG_DOMAIN_V2`] inside the
/// signed message — manifests ship embedded (`include_str!`) alongside the
/// code that verifies them. Version 1 remains parseable as explicit legacy
/// unsigned-contribution history; version 2 authenticates every contribution.
pub const LEGACY_MANIFEST_VERSION: u32 = 1;
pub const MANIFEST_VERSION: u32 = 2;

/// Release-preflight policy containing the independently approved ceremony
/// contributor keys and optional authorization windows.
pub const TRUSTED_CONTRIBUTORS_ENV: &str = "OLYMPUS_CEREMONY_TRUSTED_CONTRIBUTORS_JSON";

/// Domain tag for the coordinator-signature message (V2 binding).
///
/// V1 signed only the contribution-chain hash, leaving the artifact set
/// (vkey/zkey/r1cs/wasm) — the bytes the runtime actually loads — outside
/// the signature. V2 folds the artifacts + circuit + ceremony id into the
/// signed message; see [`CeremonyManifest::coordinator_signing_digest`].
const MANIFEST_SIG_DOMAIN_V2: &[u8] = b"OLY:CEREMONY:MANIFEST:V2";

/// Domain tag for each contributor's signature. Unlike the coordinator's
/// manifest signature, this statement binds the contributor identity and the
/// exact chain position so a coordinator cannot manufacture unsigned rows to
/// satisfy a production contributor threshold.
const CONTRIBUTION_SIG_DOMAIN_V1: &[u8] = b"OLY:CEREMONY:CONTRIBUTION:V1";

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest JSON parse error: {0}")]
    Parse(#[from] serde_json::Error),

    #[error(
        "manifest schema version {got} not supported (this build accepts legacy version 1 and authenticated version {MANIFEST_VERSION})"
    )]
    UnsupportedVersion { got: u32 },

    #[error(
        "manifest circuit name mismatch: manifest claims {claimed}, expected {expected} \
         (wrong manifest embedded against this circuit's vkey/zkey)"
    )]
    CircuitMismatch { claimed: String, expected: String },

    #[error(
        "artifact {kind} blake3 mismatch: manifest says {expected}, computed {computed} \
         (the on-disk file does not come from the same ceremony as the manifest)"
    )]
    ArtifactBlake3Mismatch {
        kind: String,
        expected: String,
        computed: String,
    },

    #[error(
        "manifest has no contributions entries — at minimum the dev contributor must be recorded"
    )]
    NoContributions,

    #[error(
        "contribution chain hash mismatch at index {index}: manifest recorded {recorded}, \
         recomputed {recomputed} (chain has been tampered or reordered)"
    )]
    ChainHashMismatch {
        index: usize,
        recorded: String,
        recomputed: String,
    },

    #[error(
        "manifest coordinator pubkey not in trusted-issuer set (audit M-3); refusing manifest"
    )]
    UntrustedCoordinator,

    #[error(
        "manifest coordinator BJJ-EdDSA signature does not verify over the V2 manifest digest \
         (artifacts + circuit + ceremony id + contribution chain) — manifest is forged, \
         corrupted, or signed by a key that is not in the trusted set"
    )]
    BadCoordinatorSignature,

    #[error(
        "contribution_hash at index {index} is not canonical hex (must be exactly 64 lowercase \
         hex chars decoding to 32 bytes): {value}"
    )]
    InvalidContributionHash { index: usize, value: String },

    #[error("manifest field {field} could not be parsed as a canonical BN254 Fr (audit L-19/L-7)")]
    BadFrField { field: &'static str },

    #[error(
        "manifest artifact {kind} blake3 is not canonical hex (must be exactly 64 lowercase hex \
         chars decoding to 32 bytes): {value} — the coordinator signature binds these digests, so \
         a malformed one cannot be folded into the signed message"
    )]
    InvalidArtifactHash { kind: String, value: String },

    #[error("contribution index mismatch at position {position}: manifest recorded {recorded}")]
    ContributionIndexMismatch { position: usize, recorded: u32 },

    #[error("contributor pubkey at index {index} is not a canonical BabyJubJub subgroup key")]
    InvalidContributorPubkey { index: usize },

    #[error("contribution at index {index} has no contributor signature")]
    MissingContributorSignature { index: usize },

    #[error("contributor signature at index {index} is malformed or does not verify")]
    BadContributorSignature { index: usize },

    #[error(
        "contributor at index {index} is not in the independently configured trusted-contributor set for that timestamp"
    )]
    UntrustedContributor { index: usize },

    #[error(
        "production ceremony requires {required} distinct authenticated contributors, found {found}"
    )]
    InsufficientAuthenticatedContributors { required: usize, found: usize },

    #[error("trusted-contributor policy is invalid: {detail}")]
    InvalidTrustedContributorPolicy { detail: String },
}

/// Canonical reference to a single ceremony output file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// File name relative to the manifest's directory (no path traversal).
    pub name: String,
    /// File size in bytes — informational only, the blake3 is the trust anchor.
    pub size: u64,
    /// Lowercase hex of `blake3(file_bytes)`.
    pub blake3: String,
}

/// Per-circuit artifact bundle. Every ceremony output that the runtime
/// touches has a blake3 entry here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMap {
    pub vkey: ArtifactRef,
    pub ark_zkey: ArtifactRef,
    pub r1cs: ArtifactRef,
    pub wasm: ArtifactRef,
}

/// Reference to the PTAU file (Phase 1 trusted setup) the Phase 2 setup
/// consumed. Pinned so a consumer can independently reproduce the
/// ceremony from the same PTAU bytes if needed.
///
/// The `blake2b` field stores the blake2b-512 hex that
/// `proofs/setup_circuits.sh` already verifies on download (the Hermez
/// PTAU files publish blake2b-512 digests). Tools that don't have
/// blake2b on hand may leave this empty and rely on `file` + `power`
/// as the human-readable identifier; the trust anchor for runtime is
/// the `artifacts.ark_zkey.blake3` field, not the PTAU hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtauRef {
    pub file: String,
    pub power: u32,
    #[serde(default)]
    pub blake2b: String,
}

/// One link in the contribution chain. Each contributor appends an
/// entry. The final entry's `running_chain_hash` is what the coordinator
/// signs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contribution {
    pub index: u32,
    pub contributor_id: String,
    /// Lowercase hex of the snarkjs Phase-2 contribution hash (the
    /// `[INFO] snarkJS: Contribution Hash:` line in setup output).
    pub contribution_hash: String,
    /// Lowercase hex of `blake3(previous_chain_hash || contribution_hash)`.
    /// For `index == 0`, `previous_chain_hash` is 32 zero bytes.
    pub running_chain_hash: String,
    pub timestamp_unix: i64,
    pub bjj_pubkey: BjjPubkeyJson,
    /// BJJ-EdDSA signature over the complete, domain-separated contribution
    /// statement. Optional only for backwards-compatible parsing of historic
    /// development manifests; production threshold verification requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<BjjSignatureJson>,
}

/// JSON-wire form of a BabyJubJub pubkey — decimal strings for both
/// coordinates to match `manifest.json` cross-language readability and
/// the existing `TrustedIssuer.x_dec`/`y_dec` shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BjjPubkeyJson {
    pub x: String,
    pub y: String,
}

/// JSON-wire form of a BabyJubJub-EdDSA signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BjjSignatureJson {
    pub r8x: String,
    pub r8y: String,
    pub s: String,
}

/// The coordinator entry: who signed the final manifest, and the
/// signature itself (over `final_running_chain_hash`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorRef {
    pub id: String,
    pub bjj_pubkey: BjjPubkeyJson,
    pub signature: BjjSignatureJson,
}

/// Top-level manifest as committed to git + embedded via `include_str!`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyManifest {
    pub version: u32,
    pub ceremony_id: String,
    /// Must match `Circuit::name()`; build.rs cross-checks against the
    /// embedding circuit.
    pub circuit: String,
    pub created_unix: i64,
    pub ptau: PtauRef,
    pub artifacts: ArtifactMap,
    pub contributions: Vec<Contribution>,
    pub coordinator: CoordinatorRef,
}

impl CeremonyManifest {
    /// Parse from raw JSON bytes (or `include_str!` output). Rejects
    /// schema versions we don't understand.
    pub fn parse(json: &str) -> Result<Self, ManifestError> {
        let m: Self = serde_json::from_str(json)?;
        if m.version != LEGACY_MANIFEST_VERSION && m.version != MANIFEST_VERSION {
            return Err(ManifestError::UnsupportedVersion { got: m.version });
        }
        if m.contributions.is_empty() {
            return Err(ManifestError::NoContributions);
        }
        if m.version == MANIFEST_VERSION {
            for (index, contribution) in m.contributions.iter().enumerate() {
                if contribution.signature.is_none() {
                    return Err(ManifestError::MissingContributorSignature { index });
                }
            }
        }
        Ok(m)
    }

    pub fn is_legacy_v1(&self) -> bool {
        self.version == LEGACY_MANIFEST_VERSION
    }

    /// True iff `json` is the `{"placeholder": true, ...}` stub that
    /// `build.rs` drops on a fresh checkout that hasn't run
    /// `setup_circuits.sh` yet. Lets callers distinguish "manifest not
    /// generated" (dev-mode pre-setup; warn) from "manifest corrupt"
    /// (real integrity problem; fail).
    pub fn is_placeholder(json: &str) -> bool {
        let trimmed = json.trim_start();
        trimmed.starts_with("{\"placeholder\"") || trimmed.starts_with("{ \"placeholder\"")
    }

    /// Assert the manifest is for the expected circuit. Called by both
    /// build.rs (compile-time) and the runtime startup pass.
    pub fn require_circuit(&self, expected: &str) -> Result<(), ManifestError> {
        if self.circuit != expected {
            return Err(ManifestError::CircuitMismatch {
                claimed: self.circuit.clone(),
                expected: expected.to_owned(),
            });
        }
        Ok(())
    }

    /// Hash `bytes` and assert match against the manifest's record for
    /// `kind`. `kind` is one of `"vkey" | "ark_zkey" | "r1cs" | "wasm"`.
    pub fn check_artifact(&self, kind: ArtifactKind, bytes: &[u8]) -> Result<(), ManifestError> {
        let expected = match kind {
            ArtifactKind::Vkey => &self.artifacts.vkey.blake3,
            ArtifactKind::ArkZkey => &self.artifacts.ark_zkey.blake3,
            ArtifactKind::R1cs => &self.artifacts.r1cs.blake3,
            ArtifactKind::Wasm => &self.artifacts.wasm.blake3,
        };
        let computed = blake3::hash(bytes).to_hex().to_string();
        if computed != *expected {
            return Err(ManifestError::ArtifactBlake3Mismatch {
                kind: kind.as_str().to_owned(),
                expected: expected.clone(),
                computed,
            });
        }
        Ok(())
    }

    /// Recompute the running chain hash from `contributions` and assert
    /// each `running_chain_hash` matches. Returns the final chain hash —
    /// one input to the V2 coordinator-signing digest (see
    /// [`CeremonyManifest::coordinator_signing_digest`]), not the signed
    /// message itself.
    pub fn verify_contribution_chain(&self) -> Result<[u8; 32], ManifestError> {
        let mut prev = [0u8; 32];
        for (i, c) in self.contributions.iter().enumerate() {
            // Strict canonical hex — silently zero-padding/truncating malformed
            // input would let the verifier accept non-canonical encodings of
            // the same chain. The contribution_hash is part of the integrity
            // boundary; reject anything that isn't exactly 32 bytes of hex.
            let contrib_bytes = decode_hash32(&c.contribution_hash).ok_or_else(|| {
                ManifestError::InvalidContributionHash {
                    index: i,
                    value: c.contribution_hash.clone(),
                }
            })?;
            let mut h = blake3::Hasher::new();
            h.update(b"OLY:CEREMONY:CHAIN:V1");
            h.update(&prev);
            h.update(&contrib_bytes);
            let next = *h.finalize().as_bytes();
            let next_hex = hex::encode(next);
            if next_hex != c.running_chain_hash {
                return Err(ManifestError::ChainHashMismatch {
                    index: i,
                    recorded: c.running_chain_hash.clone(),
                    recomputed: next_hex,
                });
            }
            prev = next;
        }
        Ok(prev)
    }

    /// Compute the statement signed by one ceremony contributor.
    ///
    /// Layout (`blake3`):
    /// ```text
    /// "OLY:CEREMONY:CONTRIBUTION:V1"
    ///   || lp(ceremony_id) || lp(circuit)
    ///   || index(u32 LE) || lp(contributor_id)
    ///   || contribution_hash(32) || running_chain_hash(32)
    ///   || timestamp_unix(i64 LE)
    ///   || lp(pubkey_x_decimal) || lp(pubkey_y_decimal)
    /// ```
    ///
    /// The running hash transitively binds every earlier contribution, while
    /// the explicit position, timestamp, identity, and key prevent a valid
    /// signature from being relabelled as a different contributor row.
    pub fn contribution_signing_digest(&self, position: usize) -> Result<[u8; 32], ManifestError> {
        let contribution =
            self.contributions
                .get(position)
                .ok_or(ManifestError::ContributionIndexMismatch {
                    position,
                    recorded: u32::MAX,
                })?;
        if contribution.index as usize != position {
            return Err(ManifestError::ContributionIndexMismatch {
                position,
                recorded: contribution.index,
            });
        }
        let contribution_hash =
            decode_hash32(&contribution.contribution_hash).ok_or_else(|| {
                ManifestError::InvalidContributionHash {
                    index: position,
                    value: contribution.contribution_hash.clone(),
                }
            })?;
        let running_chain_hash =
            decode_hash32(&contribution.running_chain_hash).ok_or_else(|| {
                ManifestError::ChainHashMismatch {
                    index: position,
                    recorded: contribution.running_chain_hash.clone(),
                    recomputed: "canonical 64-character lowercase hex required".to_owned(),
                }
            })?;

        let mut h = blake3::Hasher::new();
        h.update(CONTRIBUTION_SIG_DOMAIN_V1);
        write_length_prefixed(&mut h, self.ceremony_id.as_bytes());
        write_length_prefixed(&mut h, self.circuit.as_bytes());
        h.update(&contribution.index.to_le_bytes());
        write_length_prefixed(&mut h, contribution.contributor_id.as_bytes());
        h.update(&contribution_hash);
        h.update(&running_chain_hash);
        h.update(&contribution.timestamp_unix.to_le_bytes());
        write_length_prefixed(&mut h, contribution.bjj_pubkey.x.as_bytes());
        write_length_prefixed(&mut h, contribution.bjj_pubkey.y.as_bytes());
        Ok(*h.finalize().as_bytes())
    }

    /// Verify every contributor row against an independently configured key
    /// set and require at least `minimum` distinct cryptographic identities.
    /// Repeated contributions by one key remain valid history but count once.
    pub fn verify_authenticated_contributors(
        &self,
        trusted_contributors: &[TrustedIssuer],
        minimum: usize,
    ) -> Result<usize, ManifestError> {
        use std::collections::HashSet;

        self.verify_contribution_chain()?;
        let mut distinct = HashSet::new();
        for (position, contribution) in self.contributions.iter().enumerate() {
            let digest = self.contribution_signing_digest(position)?;
            let x = crate::api::credentials::parse_fr_decimal(&contribution.bjj_pubkey.x)
                .ok_or(ManifestError::InvalidContributorPubkey { index: position })?;
            let y = crate::api::credentials::parse_fr_decimal(&contribution.bjj_pubkey.y)
                .ok_or(ManifestError::InvalidContributorPubkey { index: position })?;
            let pubkey = BabyJubJubPubKey { x, y };
            baby_jubjub::validate_pubkey_subgroup(&pubkey)
                .map_err(|_| ManifestError::InvalidContributorPubkey { index: position })?;

            let trusted = trusted_contributors.iter().find(|candidate| {
                candidate.x_dec == contribution.bjj_pubkey.x
                    && candidate.y_dec == contribution.bjj_pubkey.y
                    // `created_unix` is covered by the coordinator's manifest
                    // signature; the contribution timestamp is signer supplied.
                    && candidate.covers(self.created_unix)
            });
            if trusted.is_none() {
                return Err(ManifestError::UntrustedContributor { index: position });
            }

            let signature = contribution
                .signature
                .as_ref()
                .ok_or(ManifestError::MissingContributorSignature { index: position })?;
            let signature = parse_signature(signature)
                .ok_or(ManifestError::BadContributorSignature { index: position })?;
            if !baby_jubjub::verify_signature(&pubkey, &signature, digest_to_fr(&digest)) {
                return Err(ManifestError::BadContributorSignature { index: position });
            }
            distinct.insert((
                contribution.bjj_pubkey.x.clone(),
                contribution.bjj_pubkey.y.clone(),
            ));
        }

        if distinct.len() < minimum {
            return Err(ManifestError::InsufficientAuthenticatedContributors {
                required: minimum,
                found: distinct.len(),
            });
        }
        Ok(distinct.len())
    }

    /// Compute the message the coordinator BJJ-EdDSA signature is taken
    /// over (the V2 binding).
    ///
    /// **Why V2 binds the artifacts.** The original (V1) recipe signed only
    /// the final contribution-chain hash. That left the *artifact set*
    /// outside the coordinator signature — most consequentially the
    /// `vkey.json` that `/zk/verify` loads to verify every proof. The other
    /// runtime checks (build.rs `blake3(vkey) == manifest.vkey.blake3`,
    /// `load_proving_key_with_manifest` `blake3(ark_zkey) ==
    /// manifest.ark_zkey.blake3`) only assert the on-disk file matches the
    /// digest *recorded in the manifest* — and those recorded digests were
    /// themselves unsigned. An attacker able to edit the manifest could
    /// therefore swap a malicious vkey/zkey, update the recorded blake3s to
    /// match, and the coordinator signature would still verify over the
    /// unchanged chain hash. ("The signed thing isn't the thing that
    /// matters.")
    ///
    /// V2 folds the full artifact map, the circuit name, and the ceremony
    /// id into the signed message, so the signature now binds the exact
    /// bytes the runtime loads. The contribution chain is still included
    /// (it transitively binds every `contribution_hash`).
    ///
    /// Layout (`blake3`):
    /// ```text
    /// "OLY:CEREMONY:MANIFEST:V2"
    ///   || lp(circuit) || lp(ceremony_id)
    ///   || vkey.blake3(32) || ark_zkey.blake3(32) || r1cs.blake3(32) || wasm.blake3(32)
    ///   || final_contribution_chain_hash(32)
    /// ```
    /// where `lp(x) = u64_le(x.len()) || x` (unambiguous framing for the
    /// two variable-length strings) and each `*.blake3(32)` is the strict
    /// 32-byte decode of the recorded lowercase-hex digest.
    pub fn coordinator_signing_digest(&self) -> Result<[u8; 32], ManifestError> {
        // Recompute (and validate) the contribution chain first — this also
        // asserts every recorded intermediate `running_chain_hash`.
        let final_chain = self.verify_contribution_chain()?;

        let mut h = blake3::Hasher::new();
        h.update(MANIFEST_SIG_DOMAIN_V2);
        write_length_prefixed(&mut h, self.circuit.as_bytes());
        write_length_prefixed(&mut h, self.ceremony_id.as_bytes());
        for (kind, art) in [
            (ArtifactKind::Vkey, &self.artifacts.vkey),
            (ArtifactKind::ArkZkey, &self.artifacts.ark_zkey),
            (ArtifactKind::R1cs, &self.artifacts.r1cs),
            (ArtifactKind::Wasm, &self.artifacts.wasm),
        ] {
            let bytes =
                decode_hash32(&art.blake3).ok_or_else(|| ManifestError::InvalidArtifactHash {
                    kind: kind.as_str().to_owned(),
                    value: art.blake3.clone(),
                })?;
            h.update(&bytes);
        }
        h.update(&final_chain);
        Ok(*h.finalize().as_bytes())
    }

    /// Full coordinator-signature check. Requires `trusted_issuers` so
    /// the coordinator pubkey is anchored to the federation's trust
    /// set (audit M-3) rather than self-attesting. Returns the matched
    /// `TrustedIssuer` reference on success so the caller can log
    /// "manifest accepted under issuer X".
    pub fn verify_coordinator_signature<'a>(
        &self,
        trusted_issuers: &'a [TrustedIssuer],
    ) -> Result<&'a TrustedIssuer, ManifestError> {
        // 1. Coordinator pubkey must be in the trusted set, AND authorised
        //    *now*. We window-check against the current wall-clock time, NOT
        //    `self.created_unix`: that field is not covered by the coordinator
        //    signature (the V2 digest binds the artifacts + circuit +
        //    ceremony id + contribution chain, but not `created_unix`), so an
        //    attacker holding any one validly-signed manifest could edit
        //    `created_unix` to slide it inside a retired-but-still-listed
        //    issuer's window.
        //    Checking `now` removes the field from the trust decision entirely.
        //    (For the common single-issuer / unbounded-window case this is a
        //    no-op — `covers` returns true regardless of the timestamp.)
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let issuer = trusted_issuers
            .iter()
            .find(|t| {
                t.x_dec == self.coordinator.bjj_pubkey.x
                    && t.y_dec == self.coordinator.bjj_pubkey.y
                    && t.covers(now_unix)
            })
            .ok_or(ManifestError::UntrustedCoordinator)?;

        // 2. Recompute the V2 signing digest — binds the artifact set
        //    (vkey/zkey/r1cs/wasm), circuit, ceremony id, AND the full
        //    contribution chain (which `coordinator_signing_digest` validates
        //    internally, asserting every intermediate `running_chain_hash`).
        let digest = self.coordinator_signing_digest()?;

        // 3. Reduce the digest into Fr (little-endian, same recipe as
        //    SBT digest derivation) and verify the BJJ signature.
        let msg = digest_to_fr(&digest);
        let pubkey = BabyJubJubPubKey {
            x: issuer.pubkey.x,
            y: issuer.pubkey.y,
        };
        let sig = parse_signature(&self.coordinator.signature)
            .ok_or(ManifestError::BadCoordinatorSignature)?;
        if !baby_jubjub::verify_signature(&pubkey, &sig, msg) {
            return Err(ManifestError::BadCoordinatorSignature);
        }
        Ok(issuer)
    }

    /// Verify that the coordinator signature is cryptographically valid for
    /// the public key declared by this manifest.
    ///
    /// This proves internal integrity only; it deliberately does **not** make
    /// the declared key trusted. Production callers must still use
    /// [`Self::verify_coordinator_signature`] with an independently configured
    /// trusted-issuer set.
    pub fn verify_signature_against_declared_coordinator(&self) -> Result<(), ManifestError> {
        let x = crate::api::credentials::parse_fr_decimal(&self.coordinator.bjj_pubkey.x).ok_or(
            ManifestError::BadFrField {
                field: "coordinator.bjj_pubkey.x",
            },
        )?;
        let y = crate::api::credentials::parse_fr_decimal(&self.coordinator.bjj_pubkey.y).ok_or(
            ManifestError::BadFrField {
                field: "coordinator.bjj_pubkey.y",
            },
        )?;
        let pubkey = BabyJubJubPubKey { x, y };
        let declared = TrustedIssuer {
            pubkey,
            x_dec: self.coordinator.bjj_pubkey.x.clone(),
            y_dec: self.coordinator.bjj_pubkey.y.clone(),
            valid_from: None,
            valid_until: None,
        };
        self.verify_coordinator_signature(std::slice::from_ref(&declared))?;
        Ok(())
    }
}

/// Discriminator for `CeremonyManifest::check_artifact` so callers
/// don't pass a free-form string.
#[derive(Debug, Clone, Copy)]
pub enum ArtifactKind {
    Vkey,
    ArkZkey,
    R1cs,
    Wasm,
}

impl ArtifactKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Vkey => "vkey",
            Self::ArkZkey => "ark_zkey",
            Self::R1cs => "r1cs",
            Self::Wasm => "wasm",
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrustedContributor {
    x: String,
    y: String,
    #[serde(default)]
    valid_from: Option<i64>,
    #[serde(default)]
    valid_until: Option<i64>,
}

/// Strictly parse the independently managed production contributor allowlist.
/// Malformed entries, non-subgroup keys, invalid windows, and duplicate keys
/// are hard failures rather than silently reducing the effective threshold.
pub fn parse_trusted_contributors_json(json: &str) -> Result<Vec<TrustedIssuer>, ManifestError> {
    use std::collections::HashSet;

    let raw: Vec<RawTrustedContributor> = serde_json::from_str(json).map_err(|error| {
        ManifestError::InvalidTrustedContributorPolicy {
            detail: error.to_string(),
        }
    })?;
    let mut seen = HashSet::new();
    let mut trusted = Vec::with_capacity(raw.len());
    for (index, entry) in raw.into_iter().enumerate() {
        if matches!((entry.valid_from, entry.valid_until), (Some(from), Some(until)) if from > until)
        {
            return Err(ManifestError::InvalidTrustedContributorPolicy {
                detail: format!("entry {index} has valid_from after valid_until"),
            });
        }
        let x = crate::api::credentials::parse_fr_decimal(&entry.x).ok_or_else(|| {
            ManifestError::InvalidTrustedContributorPolicy {
                detail: format!("entry {index} has a non-canonical x coordinate"),
            }
        })?;
        let y = crate::api::credentials::parse_fr_decimal(&entry.y).ok_or_else(|| {
            ManifestError::InvalidTrustedContributorPolicy {
                detail: format!("entry {index} has a non-canonical y coordinate"),
            }
        })?;
        let pubkey = BabyJubJubPubKey { x, y };
        baby_jubjub::validate_pubkey_subgroup(&pubkey).map_err(|_| {
            ManifestError::InvalidTrustedContributorPolicy {
                detail: format!("entry {index} is not a BabyJubJub subgroup key"),
            }
        })?;
        if !seen.insert((entry.x.clone(), entry.y.clone())) {
            return Err(ManifestError::InvalidTrustedContributorPolicy {
                detail: format!("entry {index} duplicates an earlier contributor key"),
            });
        }
        trusted.push(TrustedIssuer {
            pubkey,
            x_dec: entry.x,
            y_dec: entry.y,
            valid_from: entry.valid_from,
            valid_until: entry.valid_until,
        });
    }
    Ok(trusted)
}

/// Strict 32-byte hex decode for ceremony chain + artifact digests.
///
/// Returns `None` unless `s` is exactly 64 *lowercase* ASCII-hex chars
/// decoding to 32 bytes. The previous `hex_decode_or_zero` silently
/// zero-padded short inputs and truncated long ones, which let the verifier
/// accept non-canonical encodings of the same chain — a malformed
/// `contribution_hash` would still hash to *some* deterministic value and
/// build a "consistent" chain. Strict parsing forces the issue surface as
/// a hard error.
///
/// The lowercase restriction matters because the digest folds the *decoded
/// bytes*: `hex::decode_to_slice` is case-insensitive, so `"DEAD…"` and
/// `"dead…"` would fold to the same signed message even though they are
/// distinct JSON strings. Pinning the canonical lowercase form (what
/// `blake3::Hash::to_hex` emits, and what the string-comparison checks in
/// `check_artifact` / `verify_contribution_chain` expect) keeps the
/// JSON↔signature mapping one-to-one.
fn decode_hash32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// Length-prefix a variable-length field into the signing hasher so that
/// concatenating multiple variable-length fields is unambiguous (no
/// `"ab"||"c"` vs `"a"||"bc"` collision). `u64` little-endian length, then
/// the raw bytes.
fn write_length_prefixed(h: &mut blake3::Hasher, bytes: &[u8]) {
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

fn digest_to_fr(digest: &[u8; 32]) -> ark_bn254::Fr {
    use ark_ff::PrimeField;
    ark_bn254::Fr::from_le_bytes_mod_order(digest)
}

fn parse_signature(s: &BjjSignatureJson) -> Option<BabyJubJubSignature> {
    Some(BabyJubJubSignature {
        r8x: crate::api::credentials::parse_fr_decimal(&s.r8x)?,
        r8y: crate::api::credentials::parse_fr_decimal(&s.r8y)?,
        s: crate::api::credentials::parse_fr_decimal(&s.s)?,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::witness::baby_jubjub::{sign as bjj_sign, BabyJubJubPubKey};

    use crate::zk::proof::fr_to_decimal;

    fn build_test_manifest(
        circuit: &str,
        bjj_priv: &[u8; 32],
        artifact_bytes: ArtifactBytes,
    ) -> CeremonyManifest {
        let pubkey = BabyJubJubPubKey::from_private(bjj_priv).expect("pubkey derive");
        let pubkey_json = BjjPubkeyJson {
            x: fr_to_decimal(&pubkey.x),
            y: fr_to_decimal(&pubkey.y),
        };

        // Build a single-contribution chain.
        let contribution_hash_bytes = blake3::hash(b"test-contribution-1");
        let contribution_hex = contribution_hash_bytes.to_hex().to_string();
        let mut h = blake3::Hasher::new();
        h.update(b"OLY:CEREMONY:CHAIN:V1");
        h.update(&[0u8; 32]);
        h.update(contribution_hash_bytes.as_bytes());
        let final_chain: [u8; 32] = *h.finalize().as_bytes();
        let final_chain_hex = hex::encode(final_chain);

        // Assemble the manifest with a placeholder signature, then sign the
        // V2 digest computed from that exact struct — this guarantees the
        // test signs the same message `verify_coordinator_signature` checks.
        let mut manifest = CeremonyManifest {
            version: 1,
            ceremony_id: "test-ceremony".into(),
            circuit: circuit.into(),
            created_unix: 1_748_000_000,
            ptau: PtauRef {
                file: "powersOfTau28_hez_final_20.ptau".into(),
                power: 20,
                blake2b: "0".repeat(128),
            },
            artifacts: ArtifactMap {
                vkey: ArtifactRef {
                    name: "vkey.json".into(),
                    size: artifact_bytes.vkey.len() as u64,
                    blake3: blake3::hash(artifact_bytes.vkey).to_hex().to_string(),
                },
                ark_zkey: ArtifactRef {
                    name: "ark.zkey".into(),
                    size: artifact_bytes.ark_zkey.len() as u64,
                    blake3: blake3::hash(artifact_bytes.ark_zkey).to_hex().to_string(),
                },
                r1cs: ArtifactRef {
                    name: "r1cs".into(),
                    size: artifact_bytes.r1cs.len() as u64,
                    blake3: blake3::hash(artifact_bytes.r1cs).to_hex().to_string(),
                },
                wasm: ArtifactRef {
                    name: "wasm".into(),
                    size: artifact_bytes.wasm.len() as u64,
                    blake3: blake3::hash(artifact_bytes.wasm).to_hex().to_string(),
                },
            },
            contributions: vec![Contribution {
                index: 0,
                contributor_id: "test-contributor".into(),
                contribution_hash: contribution_hex,
                running_chain_hash: final_chain_hex,
                timestamp_unix: 1_748_000_000,
                bjj_pubkey: pubkey_json.clone(),
                signature: None,
            }],
            coordinator: CoordinatorRef {
                id: "test-coordinator".into(),
                bjj_pubkey: pubkey_json,
                signature: BjjSignatureJson {
                    r8x: "0".into(),
                    r8y: "0".into(),
                    s: "0".into(),
                },
            },
        };

        let contribution_digest = manifest
            .contribution_signing_digest(0)
            .expect("contribution signing digest");
        let contribution_sig =
            bjj_sign(bjj_priv, digest_to_fr(&contribution_digest)).expect("contribution sign");
        manifest.contributions[0].signature = Some(BjjSignatureJson {
            r8x: fr_to_decimal(&contribution_sig.r8x),
            r8y: fr_to_decimal(&contribution_sig.r8y),
            s: fr_to_decimal(&contribution_sig.s),
        });

        let digest = manifest
            .coordinator_signing_digest()
            .expect("signing digest");
        let sig = bjj_sign(bjj_priv, digest_to_fr(&digest)).expect("sign");
        manifest.coordinator.signature = BjjSignatureJson {
            r8x: fr_to_decimal(&sig.r8x),
            r8y: fr_to_decimal(&sig.r8y),
            s: fr_to_decimal(&sig.s),
        };
        manifest
    }

    struct ArtifactBytes<'a> {
        vkey: &'a [u8],
        ark_zkey: &'a [u8],
        r1cs: &'a [u8],
        wasm: &'a [u8],
    }

    fn trusted_issuer_for(bjj_priv: &[u8; 32]) -> TrustedIssuer {
        let pk = BabyJubJubPubKey::from_private(bjj_priv).expect("pubkey");
        TrustedIssuer {
            pubkey: BabyJubJubPubKey { x: pk.x, y: pk.y },
            x_dec: fr_to_decimal(&pk.x),
            y_dec: fr_to_decimal(&pk.y),
            valid_from: None,
            valid_until: None,
        }
    }

    fn replace_with_signed_contributions(manifest: &mut CeremonyManifest, keys: &[[u8; 32]]) {
        manifest.contributions.clear();
        let mut previous = [0u8; 32];
        for (index, key) in keys.iter().enumerate() {
            let contribution_hash = blake3::hash(format!("contribution-{index}").as_bytes());
            let mut chain = blake3::Hasher::new();
            chain.update(b"OLY:CEREMONY:CHAIN:V1");
            chain.update(&previous);
            chain.update(contribution_hash.as_bytes());
            previous = *chain.finalize().as_bytes();
            let pubkey = BabyJubJubPubKey::from_private(key).expect("pubkey");
            manifest.contributions.push(Contribution {
                index: index as u32,
                contributor_id: format!("contributor-{index}"),
                contribution_hash: contribution_hash.to_hex().to_string(),
                running_chain_hash: hex::encode(previous),
                timestamp_unix: 1_748_000_000 + index as i64,
                bjj_pubkey: BjjPubkeyJson {
                    x: fr_to_decimal(&pubkey.x),
                    y: fr_to_decimal(&pubkey.y),
                },
                signature: None,
            });
            let digest = manifest
                .contribution_signing_digest(index)
                .expect("contribution digest");
            let signature = bjj_sign(key, digest_to_fr(&digest)).expect("contributor sign");
            manifest.contributions[index].signature = Some(BjjSignatureJson {
                r8x: fr_to_decimal(&signature.r8x),
                r8y: fr_to_decimal(&signature.r8y),
                s: fr_to_decimal(&signature.s),
            });
        }
    }

    #[test]
    fn parse_rejects_unsupported_version() {
        let json = r#"{
            "version": 99,
            "ceremony_id": "x",
            "circuit": "document_existence",
            "created_unix": 0,
            "ptau": {"file":"f","power":20,"blake2b":"0"},
            "artifacts": {
                "vkey":{"name":"","size":0,"blake3":""},
                "ark_zkey":{"name":"","size":0,"blake3":""},
                "r1cs":{"name":"","size":0,"blake3":""},
                "wasm":{"name":"","size":0,"blake3":""}
            },
            "contributions": [{"index":0,"contributor_id":"x","contribution_hash":"00","running_chain_hash":"00","timestamp_unix":0,"bjj_pubkey":{"x":"1","y":"1"}}],
            "coordinator": {"id":"x","bjj_pubkey":{"x":"1","y":"1"},"signature":{"r8x":"1","r8y":"1","s":"1"}}
        }"#;
        let err = CeremonyManifest::parse(json).expect_err("must reject");
        assert!(matches!(err, ManifestError::UnsupportedVersion { got: 99 }));
    }

    #[test]
    fn parse_rejects_empty_contributions() {
        let json = r#"{
            "version": 1,
            "ceremony_id": "x",
            "circuit": "document_existence",
            "created_unix": 0,
            "ptau": {"file":"f","power":20,"blake2b":"0"},
            "artifacts": {
                "vkey":{"name":"","size":0,"blake3":""},
                "ark_zkey":{"name":"","size":0,"blake3":""},
                "r1cs":{"name":"","size":0,"blake3":""},
                "wasm":{"name":"","size":0,"blake3":""}
            },
            "contributions": [],
            "coordinator": {"id":"x","bjj_pubkey":{"x":"1","y":"1"},"signature":{"r8x":"1","r8y":"1","s":"1"}}
        }"#;
        let err = CeremonyManifest::parse(json).expect_err("must reject");
        assert!(matches!(err, ManifestError::NoContributions));
    }

    #[test]
    fn check_artifact_accepts_matching_blake3() {
        let priv_key = [0x42u8; 32];
        let artifacts = ArtifactBytes {
            vkey: b"vkey-bytes",
            ark_zkey: b"ark-zkey-bytes",
            r1cs: b"r1cs-bytes",
            wasm: b"wasm-bytes",
        };
        let m = build_test_manifest("document_existence", &priv_key, artifacts);
        assert!(m.check_artifact(ArtifactKind::Vkey, b"vkey-bytes").is_ok());
        assert!(m
            .check_artifact(ArtifactKind::ArkZkey, b"ark-zkey-bytes")
            .is_ok());
    }

    #[test]
    fn check_artifact_rejects_tampered_bytes() {
        let priv_key = [0x42u8; 32];
        let artifacts = ArtifactBytes {
            vkey: b"vkey-bytes",
            ark_zkey: b"ark-zkey-bytes",
            r1cs: b"r1cs-bytes",
            wasm: b"wasm-bytes",
        };
        let m = build_test_manifest("document_existence", &priv_key, artifacts);
        let err = m
            .check_artifact(ArtifactKind::ArkZkey, b"ark-zkey-bytes-TAMPERED")
            .expect_err("must reject");
        match err {
            ManifestError::ArtifactBlake3Mismatch { kind, .. } => assert_eq!(kind, "ark_zkey"),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn require_circuit_rejects_wrong_name() {
        let priv_key = [0x42u8; 32];
        let m = build_test_manifest(
            "document_existence",
            &priv_key,
            ArtifactBytes {
                vkey: b"",
                ark_zkey: b"",
                r1cs: b"",
                wasm: b"",
            },
        );
        let err = m.require_circuit("non_existence").expect_err("must reject");
        assert!(matches!(err, ManifestError::CircuitMismatch { .. }));
    }

    #[test]
    fn verify_coordinator_signature_accepts_valid_dev_manifest() {
        let priv_key = [0x42u8; 32];
        let m = build_test_manifest(
            "document_existence",
            &priv_key,
            ArtifactBytes {
                vkey: b"",
                ark_zkey: b"",
                r1cs: b"",
                wasm: b"",
            },
        );
        let issuers = vec![trusted_issuer_for(&priv_key)];
        let matched = m
            .verify_coordinator_signature(&issuers)
            .expect("valid sig + trusted issuer must pass");
        assert_eq!(matched.x_dec, m.coordinator.bjj_pubkey.x);
        m.verify_signature_against_declared_coordinator()
            .expect("valid signature must match its declared coordinator key");
    }

    #[test]
    fn verify_coordinator_signature_rejects_untrusted_issuer() {
        let priv_key = [0x42u8; 32];
        let m = build_test_manifest(
            "document_existence",
            &priv_key,
            ArtifactBytes {
                vkey: b"",
                ark_zkey: b"",
                r1cs: b"",
                wasm: b"",
            },
        );
        // Empty trusted-issuer set — coordinator pubkey is not in it.
        let err = m
            .verify_coordinator_signature(&[])
            .expect_err("must reject");
        assert!(matches!(err, ManifestError::UntrustedCoordinator));
    }

    #[test]
    fn verify_coordinator_signature_rejects_tampered_chain() {
        let priv_key = [0x42u8; 32];
        let mut m = build_test_manifest(
            "document_existence",
            &priv_key,
            ArtifactBytes {
                vkey: b"",
                ark_zkey: b"",
                r1cs: b"",
                wasm: b"",
            },
        );
        // Tamper the recorded chain hash without re-signing.
        m.contributions[0].running_chain_hash = "0".repeat(64);
        let issuers = vec![trusted_issuer_for(&priv_key)];
        let err = m
            .verify_coordinator_signature(&issuers)
            .expect_err("must reject");
        assert!(matches!(err, ManifestError::ChainHashMismatch { .. }));
    }

    #[test]
    fn verify_coordinator_signature_rejects_tampered_signature() {
        let priv_key = [0x42u8; 32];
        let mut m = build_test_manifest(
            "document_existence",
            &priv_key,
            ArtifactBytes {
                vkey: b"",
                ark_zkey: b"",
                r1cs: b"",
                wasm: b"",
            },
        );
        // Flip the signature's s component.
        m.coordinator.signature.s = "1".into();
        let issuers = vec![trusted_issuer_for(&priv_key)];
        let err = m
            .verify_coordinator_signature(&issuers)
            .expect_err("must reject");
        assert!(matches!(err, ManifestError::BadCoordinatorSignature));
        assert!(matches!(
            m.verify_signature_against_declared_coordinator(),
            Err(ManifestError::BadCoordinatorSignature)
        ));
    }

    #[test]
    fn verify_coordinator_signature_rejects_swapped_vkey_blake3() {
        // The V2 binding's whole point: the coordinator signature now covers
        // the artifact digests. Swapping the recorded vkey blake3 (as an
        // attacker would after substituting a malicious vkey.json + matching
        // its blake3 to pass build.rs) must invalidate the signature even
        // though the contribution chain is untouched. Under V1 this attack
        // verified cleanly.
        let priv_key = [0x42u8; 32];
        let mut m = build_test_manifest(
            "document_existence",
            &priv_key,
            ArtifactBytes {
                vkey: b"honest-vkey",
                ark_zkey: b"",
                r1cs: b"",
                wasm: b"",
            },
        );
        // Substitute the vkey digest with the blake3 of a malicious vkey.
        m.artifacts.vkey.blake3 = blake3::hash(b"malicious-vkey").to_hex().to_string();
        let issuers = vec![trusted_issuer_for(&priv_key)];
        let err = m
            .verify_coordinator_signature(&issuers)
            .expect_err("swapped vkey digest must break the coordinator signature");
        assert!(matches!(err, ManifestError::BadCoordinatorSignature));
    }

    #[test]
    fn verify_coordinator_signature_rejects_swapped_ark_zkey_blake3() {
        // Same binding, the proving key. (ark_zkey is also re-hashed at load
        // time, but binding it in the signature closes the multi-contributor
        // path where contribution_hash is the snarkjs hash, not blake3(zkey).)
        let priv_key = [0x42u8; 32];
        let mut m = build_test_manifest(
            "document_existence",
            &priv_key,
            ArtifactBytes {
                vkey: b"",
                ark_zkey: b"honest-zkey",
                r1cs: b"",
                wasm: b"",
            },
        );
        m.artifacts.ark_zkey.blake3 = blake3::hash(b"malicious-zkey").to_hex().to_string();
        let issuers = vec![trusted_issuer_for(&priv_key)];
        let err = m
            .verify_coordinator_signature(&issuers)
            .expect_err("swapped ark_zkey digest must break the coordinator signature");
        assert!(matches!(err, ManifestError::BadCoordinatorSignature));
    }

    #[test]
    fn coordinator_signing_digest_rejects_noncanonical_artifact_hash() {
        let priv_key = [0x42u8; 32];
        let mut m = build_test_manifest(
            "document_existence",
            &priv_key,
            ArtifactBytes {
                vkey: b"v",
                ark_zkey: b"z",
                r1cs: b"r",
                wasm: b"w",
            },
        );
        // Not 64 hex chars → strict decode must reject rather than fold a
        // truncated/zero-padded digest into the signed message.
        m.artifacts.r1cs.blake3 = "deadbeef".into();
        let err = m
            .coordinator_signing_digest()
            .expect_err("non-canonical artifact hash must be rejected");
        match err {
            ManifestError::InvalidArtifactHash { kind, .. } => assert_eq!(kind, "r1cs"),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn coordinator_signing_digest_rejects_uppercase_artifact_hash() {
        // `hex::decode_to_slice` is case-insensitive, so an uppercase digest
        // would fold to the same bytes as its lowercase form — two distinct
        // JSON manifests mapping to one signed message. `decode_hash32`
        // pins the canonical lowercase form and must reject uppercase.
        let priv_key = [0x42u8; 32];
        let mut m = build_test_manifest(
            "document_existence",
            &priv_key,
            ArtifactBytes {
                vkey: b"v",
                ark_zkey: b"z",
                r1cs: b"r",
                wasm: b"w",
            },
        );
        m.artifacts.r1cs.blake3 = m.artifacts.r1cs.blake3.to_ascii_uppercase();
        let err = m
            .coordinator_signing_digest()
            .expect_err("uppercase artifact hash must be rejected");
        match err {
            ManifestError::InvalidArtifactHash { kind, .. } => assert_eq!(kind, "r1cs"),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn authenticated_threshold_accepts_three_distinct_trusted_signers() {
        let keys = [[0x11; 32], [0x22; 32], [0x33; 32]];
        let mut manifest = build_test_manifest(
            "document_existence",
            &keys[0],
            ArtifactBytes {
                vkey: b"v",
                ark_zkey: b"z",
                r1cs: b"r",
                wasm: b"w",
            },
        );
        replace_with_signed_contributions(&mut manifest, &keys);
        let trusted: Vec<_> = keys.iter().map(trusted_issuer_for).collect();
        assert_eq!(
            manifest
                .verify_authenticated_contributors(&trusted, 3)
                .expect("three authenticated contributors"),
            3
        );
    }

    #[test]
    fn repeated_rows_from_one_identity_count_once() {
        let key = [0x44; 32];
        let keys = [key, key, key];
        let mut manifest = build_test_manifest(
            "document_existence",
            &key,
            ArtifactBytes {
                vkey: b"v",
                ark_zkey: b"z",
                r1cs: b"r",
                wasm: b"w",
            },
        );
        replace_with_signed_contributions(&mut manifest, &keys);
        let err = manifest
            .verify_authenticated_contributors(&[trusted_issuer_for(&key)], 3)
            .expect_err("one key cannot satisfy a three-identity threshold");
        assert!(matches!(
            err,
            ManifestError::InsufficientAuthenticatedContributors {
                required: 3,
                found: 1
            }
        ));
    }

    #[test]
    fn missing_or_forged_contributor_signature_is_rejected() {
        let key = [0x55; 32];
        let trusted = [trusted_issuer_for(&key)];
        let mut manifest = build_test_manifest(
            "document_existence",
            &key,
            ArtifactBytes {
                vkey: b"v",
                ark_zkey: b"z",
                r1cs: b"r",
                wasm: b"w",
            },
        );
        manifest.contributions[0].signature = None;
        assert!(matches!(
            manifest.verify_authenticated_contributors(&trusted, 1),
            Err(ManifestError::MissingContributorSignature { index: 0 })
        ));

        replace_with_signed_contributions(&mut manifest, &[key]);
        manifest.contributions[0]
            .signature
            .as_mut()
            .expect("signature")
            .s = "1".into();
        assert!(matches!(
            manifest.verify_authenticated_contributors(&trusted, 1),
            Err(ManifestError::BadContributorSignature { index: 0 })
        ));
    }

    #[test]
    fn trusted_contributor_policy_rejects_duplicate_keys() {
        let issuer = trusted_issuer_for(&[0x66; 32]);
        let json = format!(
            r#"[{{"x":"{}","y":"{}"}},{{"x":"{}","y":"{}"}}]"#,
            issuer.x_dec, issuer.y_dec, issuer.x_dec, issuer.y_dec
        );
        assert!(matches!(
            parse_trusted_contributors_json(&json),
            Err(ManifestError::InvalidTrustedContributorPolicy { .. })
        ));
    }
}
