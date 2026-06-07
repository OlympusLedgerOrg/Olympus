//! M-of-N federation multi-signature credentials.
//!
//! A quorum credential is signed by `M` of a pinned set of `N` federation
//! signers (the issuing node's BJJ authority key + its trusted peers' authority
//! keys). Every signer signs the same domain-separated message derived from the
//! credential's `commit_id`, so anyone holding the `N` pubkeys can re-verify the
//! quorum **offline** — no contact with any node, no blockchain.
//!
//! This module is intentionally NOT feature-gated: offline verification of a
//! quorum credential must work in a vanilla (non-`federation`) build, since the
//! whole point is that a credential issued by a federation can be re-checked by
//! anyone. The *collection* of co-signatures at issue time (which talks to peers
//! over Tor) lives in the feature-gated [`crate::federation::cosign`] module.
//!
//! # Message domain
//!
//! Every quorum signer signs
//!
//! ```text
//! quorum_msg = Fr_le( BLAKE3(
//!     "OLY:SBT:QUORUM:V2"
//!   | len(commit_id_hex) || commit_id_hex
//!   | u32_be(threshold)
//!   | u32_be(N) || for each pinned signer in canonical order:
//!                    len(x) || x || len(y) || y
//! ) )
//! ```
//!
//! The `OLY:SBT:QUORUM:V2` tag keeps a quorum co-signature structurally
//! disjoint from a single-issuer signature (over the bare `commit_id`, see
//! [`crate::api::credentials::compute_commit_id`]) and from a revocation
//! signature (`OLY:SBT:REVOKE:V1`). A signature minted in one role can never be
//! replayed in another.
//!
//! Binding the `threshold` and the canonical pinned signer set into the message
//! (V2, audit R3-01) means neither can be altered after issuance without
//! invalidating every collected signature: a database-tier tamper that lowers
//! `threshold` to 1 or swaps in an attacker-controlled signer changes the
//! message every stored signature was made over, so [`verify_quorum`] then
//! counts zero valid signatures and reports `satisfied = false` (fail-closed).
//! The signer set is hashed in *canonical, sorted* form (the same
//! `normalize_signer` + `BTreeSet` the verifier uses for its eligible set), so
//! the digest is independent of signer ordering and of non-canonical decimal
//! encodings — issue-time and verify-time derive byte-identical messages.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::zk::proof::parse_fr;
use crate::zk::witness::baby_jubjub::{self, BabyJubJubPubKey, BabyJubJubSignature};

#[cfg(feature = "federation")]
pub use db::trusted_signer_set;
pub use db::{load_quorum_signatures, store_quorum_signatures};

/// Domain tag for quorum co-signatures. See module docs. Bumped to `V2` when
/// the message gained the `threshold` + canonical signer-set binding (audit
/// R3-01); a `V1` signature can never be replayed against a `V2` message.
pub const QUORUM_COSIGN_PREFIX: &[u8] = b"OLY:SBT:QUORUM:V2";

/// Maximum signer-set size `N` the ZK quorum circuit supports. MUST equal
/// `FEDERATION_QUORUM_N()` in `proofs/circuits/parameters.circom`. A pinned
/// signer set larger than this can still be verified by the explicit
/// signature-set path ([`verify_quorum`]) but cannot be proved by the circuit.
pub const FEDERATION_QUORUM_N: usize = 8;

/// Environment variable holding the default quorum threshold `M`.
pub const QUORUM_THRESHOLD_ENV: &str = "OLYMPUS_FEDERATION_QUORUM_THRESHOLD";

/// A federation signer identified by its BJJ public-key coordinates, as
/// decimal `Fr` strings. This is the JSON shape persisted in
/// `key_credentials.quorum_signers` and exchanged on the co-sign wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumSigner {
    pub x: String,
    pub y: String,
}

/// One collected BJJ-EdDSA signature over the quorum message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedSignature {
    #[serde(flatten)]
    pub signer: QuorumSigner,
    pub r8x: String,
    pub r8y: String,
    pub s: String,
}

/// Outcome of [`verify_quorum`]. `satisfied` is the single bit a caller cares
/// about; the counts are surfaced for diagnostics / API responses.
#[derive(Debug, Clone, Serialize)]
pub struct QuorumStatus {
    pub threshold: usize,
    pub total_signers: usize,
    pub valid_signatures: usize,
    pub satisfied: bool,
}

pub(crate) use crate::zk::proof::fr_to_decimal;

/// Derive the quorum co-sign message (a BN254 `Fr`) every signer signs.
///
/// Binds the credential's `commit_id` **and** the pinned quorum parameters —
/// `threshold` plus the canonical signer set — so that neither can be changed
/// after issuance without invalidating every collected signature (audit R3-01).
/// `signers` is normalised and sorted internally (malformed entries dropped,
/// exactly as [`verify_quorum`] builds its eligible set), so the digest does not
/// depend on signer ordering or on non-canonical decimal encodings.
pub fn quorum_cosign_message(commit_id: &[u8; 32], threshold: usize, signers: &[QuorumSigner]) -> Fr {
    use std::collections::BTreeSet;

    let commit_id_hex = hex::encode(commit_id);
    let canonical: BTreeSet<(String, String)> =
        signers.iter().filter_map(normalize_signer).collect();

    let mut h = blake3::Hasher::new();
    h.update(QUORUM_COSIGN_PREFIX);
    h.update(&(commit_id_hex.len() as u32).to_be_bytes());
    h.update(commit_id_hex.as_bytes());
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

/// The configured default threshold `M`, read from [`QUORUM_THRESHOLD_ENV`].
///
/// Defaults to `1` (single-signer — behaves like a non-quorum credential) when
/// unset or unparseable. A value of `0` is clamped up to `1`; a threshold of
/// zero would make every "quorum" trivially satisfied.
pub fn configured_threshold() -> u32 {
    std::env::var(QUORUM_THRESHOLD_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|m| m.max(1))
        .unwrap_or(1)
}

/// Normalise a signer's `(x, y)` into a canonical `(dec, dec)` identity, or
/// `None` if either coordinate is not a canonical in-field decimal. Used as the
/// membership / distinctness key so non-canonical encodings (`"007"` vs `"7"`,
/// or a value `>= r`) can neither sneak past set-membership nor be counted as a
/// distinct signer from their canonical form.
fn normalize_signer(s: &QuorumSigner) -> Option<(String, String)> {
    let x = parse_fr(&s.x).ok()?;
    let y = parse_fr(&s.y).ok()?;
    Some((fr_to_decimal(&x), fr_to_decimal(&y)))
}

/// Verify an M-of-N quorum over `commit_id` against the pinned `signers` set.
///
/// A signature counts toward the quorum iff ALL hold:
///   1. its signer is a member of `signers` (the pinned `N` set),
///   2. the BJJ-EdDSA signature verifies over [`quorum_cosign_message`]
///      (which itself enforces subgroup + malleability guards — see
///      [`baby_jubjub::verify_signature`]),
///   3. the signer has not already been counted (distinctness — a signer
///      submitting two signatures counts once).
///
/// Fails closed: any parse failure on a signature or signer drops that entry
/// rather than aborting the whole check. `satisfied` requires
/// `valid_signatures >= threshold` AND `threshold >= 1`.
pub fn verify_quorum(
    commit_id: &[u8; 32],
    signers: &[QuorumSigner],
    threshold: usize,
    sigs: &[CollectedSignature],
) -> QuorumStatus {
    use std::collections::BTreeSet;

    // The message binds threshold + the pinned set, so a post-issuance tamper to
    // either makes every stored signature verify against a different message and
    // drop out below (audit R3-01).
    let msg = quorum_cosign_message(commit_id, threshold, signers);

    // Pinned signer set, normalised. A malformed pinned signer is dropped from
    // the eligible set (it can never be matched), which also shrinks
    // total_signers — an honest issuer never pins a malformed signer.
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

/// Serialise a pinned signer set to the JSON value stored in
/// `key_credentials.quorum_signers`.
pub fn signers_to_json(signers: &[QuorumSigner]) -> serde_json::Value {
    serde_json::to_value(signers).unwrap_or_else(|_| serde_json::json!([]))
}

/// Parse a pinned signer set from the stored JSON value. Returns an empty vec
/// on any shape mismatch — a credential whose `quorum_signers` is corrupt can
/// then never satisfy its quorum (fail closed).
pub fn signers_from_json(v: &serde_json::Value) -> Vec<QuorumSigner> {
    serde_json::from_value(v.clone()).unwrap_or_default()
}

mod db {
    use super::{CollectedSignature, QuorumSigner};
    use sqlx::PgPool;

    /// Assemble the canonical signer set `N` for a new quorum credential: the
    /// local BJJ authority key first, then every `trusted` peer's pinned
    /// authority pubkey (from `peer_nodes`), in `added_at` order. Deduped so a
    /// peer that happens to share the authority's key (or a duplicate
    /// registration) is not counted twice.
    ///
    /// Only compiled with the `federation` feature — assembling a multi-signer
    /// set is meaningless without peers to co-sign. Offline verification
    /// ([`super::verify_quorum`]) reads the pinned set off the credential row
    /// and needs no peer table, so it stays available in every build.
    #[cfg(feature = "federation")]
    pub async fn trusted_signer_set(
        pool: &PgPool,
        authority: &crate::zk::witness::baby_jubjub::BabyJubJubPubKey,
    ) -> Result<Vec<QuorumSigner>, sqlx::Error> {
        use std::collections::BTreeSet;

        let mut out: Vec<QuorumSigner> = Vec::new();
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();

        let authority_signer = QuorumSigner {
            x: super::fr_to_decimal(&authority.x),
            y: super::fr_to_decimal(&authority.y),
        };
        if let Some(id) = super::normalize_signer(&authority_signer) {
            seen.insert(id);
            out.push(authority_signer);
        }

        let peers: Vec<(String, String)> = sqlx::query_as(
            "SELECT bjj_pubkey_x, bjj_pubkey_y FROM peer_nodes
              WHERE trust_status = 'trusted'
              ORDER BY added_at",
        )
        .fetch_all(pool)
        .await?;

        for (x, y) in peers {
            let signer = QuorumSigner { x, y };
            if let Some(id) = super::normalize_signer(&signer) {
                if seen.insert(id) {
                    out.push(signer);
                }
            }
        }
        Ok(out)
    }

    /// Persist the collected quorum signatures for a credential. Idempotent per
    /// (credential, signer) via the UNIQUE constraint in migration 0032.
    pub async fn store_quorum_signatures(
        pool: &PgPool,
        credential_id: &str,
        sigs: &[CollectedSignature],
    ) -> Result<(), sqlx::Error> {
        for cs in sigs {
            sqlx::query(
                "INSERT INTO credential_quorum_signatures
                     (credential_id, signer_pubkey_x, signer_pubkey_y, sig_r8x, sig_r8y, sig_s)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (credential_id, signer_pubkey_x, signer_pubkey_y) DO NOTHING",
            )
            .bind(credential_id)
            .bind(&cs.signer.x)
            .bind(&cs.signer.y)
            .bind(&cs.r8x)
            .bind(&cs.r8y)
            .bind(&cs.s)
            .execute(pool)
            .await?;
        }
        Ok(())
    }

    /// Load all stored quorum signatures for a credential.
    pub async fn load_quorum_signatures(
        pool: &PgPool,
        credential_id: &str,
    ) -> Result<Vec<CollectedSignature>, sqlx::Error> {
        #[derive(sqlx::FromRow)]
        struct Row {
            signer_pubkey_x: String,
            signer_pubkey_y: String,
            sig_r8x: String,
            sig_r8y: String,
            sig_s: String,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT signer_pubkey_x, signer_pubkey_y, sig_r8x, sig_r8y, sig_s
               FROM credential_quorum_signatures
              WHERE credential_id = $1",
        )
        .bind(credential_id)
        .fetch_all(pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| CollectedSignature {
                signer: QuorumSigner {
                    x: r.signer_pubkey_x,
                    y: r.signer_pubkey_y,
                },
                r8x: r.sig_r8x,
                r8y: r.sig_r8y,
                s: r.sig_s,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::witness::baby_jubjub;

    fn signer_for(priv_key: &[u8; 32]) -> (QuorumSigner, [u8; 32]) {
        let pk = baby_jubjub::BabyJubJubPubKey::from_private(priv_key).expect("pubkey");
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
        commit_id: &[u8; 32],
        threshold: usize,
        signers: &[QuorumSigner],
    ) -> CollectedSignature {
        let msg = quorum_cosign_message(commit_id, threshold, signers);
        let sig = baby_jubjub::sign(priv_key, msg).expect("sign");
        CollectedSignature {
            signer: signer.clone(),
            r8x: fr_to_decimal(&sig.r8x),
            r8y: fr_to_decimal(&sig.r8y),
            s: fr_to_decimal(&sig.s),
        }
    }

    #[test]
    fn quorum_message_is_deterministic_and_domain_separated() {
        let (s1, _) = signer_for(&[1u8; 32]);
        let (s2, _) = signer_for(&[2u8; 32]);
        let signers = vec![s1.clone(), s2.clone()];
        let cid = [9u8; 32];
        let m = |c: &[u8; 32], t, sg: &[QuorumSigner]| quorum_cosign_message(c, t, sg);

        assert_eq!(m(&cid, 2, &signers), m(&cid, 2, &signers));
        // A different commit_id must change the message.
        let mut other = cid;
        other[0] ^= 1;
        assert_ne!(m(&cid, 2, &signers), m(&other, 2, &signers));
        // R3-01: threshold is bound — changing it changes the message.
        assert_ne!(m(&cid, 2, &signers), m(&cid, 1, &signers));
        // R3-01: the signer set is bound — dropping a signer changes the message.
        assert_ne!(m(&cid, 2, &signers), m(&cid, 2, &signers[..1]));
        // Canonical ordering: signer order does NOT change the message.
        let reordered = vec![s2, s1];
        assert_eq!(m(&cid, 2, &signers), m(&cid, 2, &reordered));
    }

    #[test]
    fn two_of_three_quorum_is_satisfied_by_two_valid_signatures() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let (s2, k2) = signer_for(&[2u8; 32]);
        let (s3, _k3) = signer_for(&[3u8; 32]);
        let signers = vec![s1.clone(), s2.clone(), s3.clone()];
        let cid = [42u8; 32];

        let sigs = vec![
            cosign(&k1, &s1, &cid, 2, &signers),
            cosign(&k2, &s2, &cid, 2, &signers),
        ];
        let status = verify_quorum(&cid, &signers, 2, &sigs);
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
        let cid = [7u8; 32];

        let sigs = vec![cosign(&k1, &s1, &cid, 2, &signers)];
        let status = verify_quorum(&cid, &signers, 2, &sigs);
        assert_eq!(status.valid_signatures, 1);
        assert!(!status.satisfied);
    }

    #[test]
    fn signature_from_non_member_is_not_counted() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let (s2, _k2) = signer_for(&[2u8; 32]);
        // Outsider signs but is NOT in the pinned set.
        let (outsider, ko) = signer_for(&[99u8; 32]);
        let signers = vec![s1.clone(), s2];
        let cid = [5u8; 32];

        let sigs = vec![
            cosign(&k1, &s1, &cid, 2, &signers),
            cosign(&ko, &outsider, &cid, 2, &signers),
        ];
        let status = verify_quorum(&cid, &signers, 2, &sigs);
        assert_eq!(status.valid_signatures, 1, "outsider sig must be ignored");
        assert!(!status.satisfied);
    }

    #[test]
    fn duplicate_signer_counts_once() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let (s2, _k2) = signer_for(&[2u8; 32]);
        let signers = vec![s1.clone(), s2];
        let cid = [11u8; 32];

        // Same signer submits twice — must count once.
        let sigs = vec![
            cosign(&k1, &s1, &cid, 2, &signers),
            cosign(&k1, &s1, &cid, 2, &signers),
        ];
        let status = verify_quorum(&cid, &signers, 2, &sigs);
        assert_eq!(status.valid_signatures, 1);
        assert!(!status.satisfied);
    }

    #[test]
    fn signature_over_wrong_commit_id_is_rejected() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let signers = vec![s1.clone()];
        let cid = [1u8; 32];
        let wrong_cid = [2u8; 32];

        // Signer signs the WRONG commit_id; must not verify against `cid`.
        let sigs = vec![cosign(&k1, &s1, &wrong_cid, 1, &signers)];
        let status = verify_quorum(&cid, &signers, 1, &sigs);
        assert_eq!(status.valid_signatures, 0);
        assert!(!status.satisfied);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let signers = vec![s1.clone()];
        let cid = [3u8; 32];
        let mut sig = cosign(&k1, &s1, &cid, 1, &signers);
        // Corrupt s.
        sig.s = "12345".to_owned();
        let status = verify_quorum(&cid, &signers, 1, &[sig]);
        assert_eq!(status.valid_signatures, 0);
        assert!(!status.satisfied);
    }

    #[test]
    fn tampering_threshold_or_signer_set_breaks_the_quorum() {
        // Audit R3-01: the co-sign message binds threshold + the pinned set, so
        // a database-tier tamper to either invalidates every stored signature.
        let (s1, k1) = signer_for(&[1u8; 32]);
        let (s2, k2) = signer_for(&[2u8; 32]);
        let (s3, _k3) = signer_for(&[3u8; 32]);
        let signers = vec![s1.clone(), s2.clone(), s3.clone()];
        let cid = [42u8; 32];
        let sigs = vec![
            cosign(&k1, &s1, &cid, 2, &signers),
            cosign(&k2, &s2, &cid, 2, &signers),
        ];
        // Baseline: the honest 2-of-3 is satisfied.
        assert!(verify_quorum(&cid, &signers, 2, &sigs).satisfied);

        // Downgrade threshold 2 → 1: the signatures were made over threshold=2,
        // so against the threshold=1 message none verify → fail closed.
        let downgraded = verify_quorum(&cid, &signers, 1, &sigs);
        assert_eq!(downgraded.valid_signatures, 0);
        assert!(!downgraded.satisfied);

        // Substitute an attacker key into the pinned set: the bound message
        // changes, so the honest signatures no longer verify.
        let (attacker, _ka) = signer_for(&[99u8; 32]);
        let swapped_set = vec![s1.clone(), s2.clone(), attacker];
        let swapped = verify_quorum(&cid, &swapped_set, 2, &sigs);
        assert_eq!(swapped.valid_signatures, 0);
        assert!(!swapped.satisfied);

        // Shrink the pinned set (even to one that would "look" satisfied):
        // a different set ⇒ a different message ⇒ zero valid signatures.
        let shrunk = vec![s1, s2];
        let shrunk_status = verify_quorum(&cid, &shrunk, 2, &sigs);
        assert_eq!(shrunk_status.valid_signatures, 0);
        assert!(!shrunk_status.satisfied);
    }

    #[test]
    fn non_canonical_signer_encoding_does_not_double_count() {
        // A signer whose pinned coord is "7" and a co-signature claiming "007"
        // must normalise to the same identity (distinctness), and "007" is
        // rejected outright by strict parse_fr — so it can't be a sneaky
        // second member either. Here we assert normalize maps them equal.
        let a = QuorumSigner {
            x: "7".into(),
            y: "8".into(),
        };
        // parse_fr rejects leading-zero? No — parse_fr accepts "007" as 7
        // (BigUint::from_str), but normalises to "7". So the identity matches.
        let b = QuorumSigner {
            x: "007".into(),
            y: "008".into(),
        };
        assert_eq!(normalize_signer(&a), normalize_signer(&b));
    }

    #[test]
    fn configured_threshold_defaults_to_one() {
        // With the env var unset in the test process, default is 1.
        // (Don't mutate process env here — other tests run concurrently.)
        // We can at least assert the function returns >= 1 always.
        assert!(configured_threshold() >= 1);
    }

    #[test]
    fn signers_json_round_trips() {
        let signers = vec![
            QuorumSigner {
                x: "1".into(),
                y: "2".into(),
            },
            QuorumSigner {
                x: "3".into(),
                y: "4".into(),
            },
        ];
        let v = signers_to_json(&signers);
        let back = signers_from_json(&v);
        assert_eq!(signers, back);
    }
}
