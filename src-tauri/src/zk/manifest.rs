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
//!      signature against `state.bjj_trusted_issuers` (audit M-3).
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
pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest JSON parse error: {0}")]
    Parse(#[from] serde_json::Error),

    #[error(
        "manifest schema version {got} not supported (this build accepts version {MANIFEST_VERSION})"
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
        "manifest coordinator BJJ-EdDSA signature does not verify over the final running chain \
         hash — manifest is forged, corrupted, or signed by a key that is not in the trusted set"
    )]
    BadCoordinatorSignature,

    #[error(
        "contribution_hash at index {index} is not canonical hex (must be exactly 64 lowercase \
         hex chars decoding to 32 bytes): {value}"
    )]
    InvalidContributionHash { index: usize, value: String },

    #[error("manifest field {field} could not be parsed as a canonical BN254 Fr (audit L-19/L-7)")]
    BadFrField { field: &'static str },
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
        if m.version != MANIFEST_VERSION {
            return Err(ManifestError::UnsupportedVersion { got: m.version });
        }
        if m.contributions.is_empty() {
            return Err(ManifestError::NoContributions);
        }
        Ok(m)
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
    /// each `running_chain_hash` matches. Returns the final chain hash
    /// (the signed message for the coordinator signature).
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
        //    signature (only the contribution-chain hash is), so an attacker
        //    holding any one validly-signed manifest could edit `created_unix`
        //    to slide it inside a retired-but-still-listed issuer's window.
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

        // 2. Recompute the contribution chain — also asserts every
        //    intermediate hash matches the recorded one.
        let final_chain = self.verify_contribution_chain()?;

        // 3. Reduce final_chain into Fr (little-endian, same recipe as
        //    SBT digest derivation) and verify the BJJ signature.
        let msg = digest_to_fr(&final_chain);
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

/// Strict 32-byte hex decode for ceremony chain digests.
///
/// Returns `None` unless `s` is exactly 64 ASCII-hex chars decoding to 32
/// bytes. The previous `hex_decode_or_zero` silently zero-padded short
/// inputs and truncated long ones, which let the verifier accept
/// non-canonical encodings of the same chain — a malformed
/// `contribution_hash` would still hash to *some* deterministic value and
/// build a "consistent" chain. Strict parsing forces the issue surface as
/// a hard error.
fn decode_hash32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
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

        // Sign the final chain hash.
        let msg = digest_to_fr(&final_chain);
        let sig = bjj_sign(bjj_priv, msg).expect("sign");

        CeremonyManifest {
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
            }],
            coordinator: CoordinatorRef {
                id: "test-coordinator".into(),
                bjj_pubkey: pubkey_json,
                signature: BjjSignatureJson {
                    r8x: fr_to_decimal(&sig.r8x),
                    r8y: fr_to_decimal(&sig.r8y),
                    s: fr_to_decimal(&sig.s),
                },
            },
        }
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
    }
}
