//! Checkpoint-quorum co-signatures: M-of-N over a checkpoint `(chain_id, epoch, root)`.
//!
//! Implements ADR-0033 (`OLY:CHECKPOINT:QUORUM:V2`) — the M-of-N root co-signing
//! chosen in ADR-0032. Where [`super::verify_quorum`] co-signs a credential
//! `commit_id`, this co-signs a **checkpoint** identified by:
//!   * `chain_id`  — the issuing ledger's identity (the node's
//!     `authority_pubkey_hash`, the only per-ledger identifier Olympus has);
//!   * `epoch`     — the checkpoint height (`tree_size`);
//!   * `root`      — the Poseidon `ledger_root`.
//!
//! N pinned federation signers each BJJ-EdDSA-sign the same domain-separated
//! message, and anyone holding the pinned `N` pubkeys can re-verify the M-of-N
//! quorum offline. It reuses the parent module's hardened machinery verbatim
//! (pinned signer set, member-only counting, dedup by normalized key, threshold
//! bound into the signed message, fail-closed); only the **domain tag** and the
//! **bound object** change.
//!
//! Binding `chain_id` + `epoch` (V2) — not just the root (V1, ADR-0033 Phase 1,
//! superseded here before any producer existed) — means a co-signature for one
//! ledger or height can never be replayed onto another.
//!
//! This deliberately does NOT replace the existing single-signer checkpoint
//! signature (`federation::verify::verify_checkpoint_signature`, where one
//! authority signs the bare `ledger_root`). It is the M-of-N extension a peer
//! set co-signs a checkpoint with — the disjoint domain tag keeps the two from
//! ever being confused.
//!
//! Phase 2 PR-1 (this file): the V2 message + verifier, the signing primitive,
//! and the persistence (`store_*`/`load_*`, table in migration 0048). The live
//! producer — collecting peer co-signatures over Tor (the checkpoint analogue of
//! `federation::cosign`) and persisting them in the gossip loop — is PR-2 and is
//! the first non-test caller; until then `#![allow(dead_code)]` keeps the
//! bin-target compilation warning-clean (items are public API on the lib target).
#![allow(dead_code)]

use ark_bn254::Fr;
use ark_ff::PrimeField;
use sqlx::PgPool;
use uuid::Uuid;

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
/// in one of those roles can never verify in another — the prefix enters the
/// BLAKE3 pre-image, so a different role yields a different message field
/// element. `V2` adds the `chain_id` + `epoch` binding over the `V1` (root-only)
/// Phase-1 format, which had no producer and minted no signatures.
pub const CHECKPOINT_QUORUM_PREFIX: &[u8] = b"OLY:CHECKPOINT:QUORUM:V2";

/// Derive the checkpoint-quorum co-sign message (a BN254 `Fr`) every signer
/// signs.
///
/// Binds the checkpoint identity `(chain_id, epoch, root)` **and** the pinned
/// quorum parameters — `threshold` plus the canonical signer set — so none of
/// them can change after the fact without invalidating every collected signature
/// (the same R3-01 binding the SBT quorum uses). `signers` is normalised and
/// sorted internally (malformed entries dropped, exactly as
/// [`verify_checkpoint_quorum`] builds its eligible set), so the digest does not
/// depend on signer ordering or on non-canonical decimal encodings.
///
/// Byte layout (length-prefixed BLAKE3):
///
/// ```text
/// msg = Fr_le( BLAKE3(
///     "OLY:CHECKPOINT:QUORUM:V2"
///   | u32_be(len(chain_id_dec)) || chain_id_dec
///   | i64_be(epoch)
///   | u32_be(len(root_dec)) || root_dec
///   | u32_be(threshold)
///   | u32_be(N) || for each canonical signer: u32_be(len(x))||x||u32_be(len(y))||y
/// ) )
/// ```
///
/// `chain_id_dec`/`root_dec` are `fr_to_decimal(..)` canonical decimals, so
/// `"007"`/`"7"` and any value `>= r` collapse to one representation. `epoch` is
/// a fixed 8-byte big-endian `i64` (the checkpoint `tree_size`). `threshold` is a
/// `u32` (M-of-N with N ≤ 8 leaves ample headroom) so the 4-byte field can never
/// silently truncate.
pub fn checkpoint_quorum_message(
    chain_id: &Fr,
    epoch: i64,
    root: &Fr,
    threshold: u32,
    signers: &[QuorumSigner],
) -> Fr {
    use std::collections::BTreeSet;

    let chain_dec = fr_to_decimal(chain_id);
    let root_dec = fr_to_decimal(root);
    let canonical: BTreeSet<(String, String)> =
        signers.iter().filter_map(normalize_signer).collect();

    let mut h = blake3::Hasher::new();
    h.update(CHECKPOINT_QUORUM_PREFIX);
    h.update(&(chain_dec.len() as u32).to_be_bytes());
    h.update(chain_dec.as_bytes());
    h.update(&epoch.to_be_bytes());
    h.update(&(root_dec.len() as u32).to_be_bytes());
    h.update(root_dec.as_bytes());
    h.update(&threshold.to_be_bytes());
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

/// Verify an M-of-N quorum over a checkpoint `(chain_id, epoch, root)` against
/// the pinned `signers`.
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
    chain_id: &Fr,
    epoch: i64,
    root: &Fr,
    signers: &[QuorumSigner],
    threshold: u32,
    sigs: &[CollectedSignature],
) -> QuorumStatus {
    use std::collections::BTreeSet;

    // The message binds (chain_id, epoch, root) + threshold + the pinned set, so
    // a post-hoc tamper to any of them makes every stored signature verify
    // against a different message and drop out below.
    let msg = checkpoint_quorum_message(chain_id, epoch, root, threshold, signers);

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
        threshold: threshold as usize,
        total_signers: allowed.len(),
        valid_signatures,
        satisfied: threshold >= 1 && valid_signatures >= threshold as usize,
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

/// Co-sign a checkpoint `(chain_id, epoch, root)` under the pinned
/// `(threshold, signers)` with a BJJ private key, returning the wire-shaped
/// [`CollectedSignature`].
///
/// This is the signing primitive a Phase-2 checkpoint co-sign producer calls
/// (the checkpoint analogue of `federation::cosign` for SBT quorums); it also
/// generates the golden vectors. The result verifies through
/// [`verify_checkpoint_quorum`] for the same checkpoint identity + parameters.
pub fn cosign_checkpoint(
    priv_key: &[u8; 32],
    chain_id: &Fr,
    epoch: i64,
    root: &Fr,
    threshold: u32,
    signers: &[QuorumSigner],
) -> Result<CollectedSignature, BabyJubJubError> {
    let signer = signer_from_private(priv_key)?;
    let msg = checkpoint_quorum_message(chain_id, epoch, root, threshold, signers);
    let sig = baby_jubjub::sign(priv_key, msg)?;
    Ok(CollectedSignature {
        signer,
        r8x: fr_to_decimal(&sig.r8x),
        r8y: fr_to_decimal(&sig.r8y),
        s: fr_to_decimal(&sig.s),
    })
}

/// Persist the collected checkpoint-quorum signatures for an `own_checkpoints`
/// row. Idempotent per `(checkpoint, signer)` via the UNIQUE constraint in
/// migration 0048. Mirrors [`super::store_quorum_signatures`] for credentials.
pub async fn store_checkpoint_quorum_signatures(
    pool: &PgPool,
    checkpoint_id: Uuid,
    sigs: &[CollectedSignature],
) -> Result<(), sqlx::Error> {
    for cs in sigs {
        sqlx::query(
            "INSERT INTO checkpoint_quorum_signatures
                 (checkpoint_id, signer_pubkey_x, signer_pubkey_y, sig_r8x, sig_r8y, sig_s)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (checkpoint_id, signer_pubkey_x, signer_pubkey_y) DO NOTHING",
        )
        .bind(checkpoint_id)
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

/// Load all stored checkpoint-quorum signatures for an `own_checkpoints` row.
pub async fn load_checkpoint_quorum_signatures(
    pool: &PgPool,
    checkpoint_id: Uuid,
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
           FROM checkpoint_quorum_signatures
          WHERE checkpoint_id = $1",
    )
    .bind(checkpoint_id)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn signer_for(priv_key: &[u8; 32]) -> (QuorumSigner, [u8; 32]) {
        (signer_from_private(priv_key).expect("pubkey"), *priv_key)
    }

    fn cosign(
        priv_key: &[u8; 32],
        chain_id: &Fr,
        epoch: i64,
        root: &Fr,
        threshold: u32,
        signers: &[QuorumSigner],
    ) -> CollectedSignature {
        cosign_checkpoint(priv_key, chain_id, epoch, root, threshold, signers).expect("sign")
    }

    #[test]
    fn message_is_deterministic_and_binds_every_field() {
        let (s1, _) = signer_for(&[1u8; 32]);
        let (s2, _) = signer_for(&[2u8; 32]);
        let signers = vec![s1.clone(), s2.clone()];
        let cid = Fr::from(7u64);
        let epoch = 42i64;
        let root = Fr::from(123456u64);
        let m = |c: &Fr, e: i64, r: &Fr, t: u32, sg: &[QuorumSigner]| {
            checkpoint_quorum_message(c, e, r, t, sg)
        };

        assert_eq!(
            m(&cid, epoch, &root, 2, &signers),
            m(&cid, epoch, &root, 2, &signers)
        );
        // chain_id is bound.
        assert_ne!(
            m(&cid, epoch, &root, 2, &signers),
            m(&Fr::from(8u64), epoch, &root, 2, &signers)
        );
        // epoch is bound.
        assert_ne!(
            m(&cid, epoch, &root, 2, &signers),
            m(&cid, 43, &root, 2, &signers)
        );
        // root is bound.
        assert_ne!(
            m(&cid, epoch, &root, 2, &signers),
            m(&cid, epoch, &Fr::from(123457u64), 2, &signers)
        );
        // threshold is bound.
        assert_ne!(
            m(&cid, epoch, &root, 2, &signers),
            m(&cid, epoch, &root, 1, &signers)
        );
        // signer set is bound.
        assert_ne!(
            m(&cid, epoch, &root, 2, &signers),
            m(&cid, epoch, &root, 2, &signers[..1])
        );
        // canonical ordering: signer order does NOT change the message.
        let reordered = vec![s2, s1];
        assert_eq!(
            m(&cid, epoch, &root, 2, &signers),
            m(&cid, epoch, &root, 2, &reordered)
        );
    }

    #[test]
    fn message_is_domain_separated_from_sbt_quorum() {
        // The same value bound as a checkpoint root vs. an SBT commit_id must
        // yield different messages — the domain tag (and the framing) differ,
        // both entering the BLAKE3 pre-image. Stops cross-role replay.
        use ark_ff::BigInteger;
        let (s1, _) = signer_for(&[1u8; 32]);
        let signers = vec![s1];
        let root = Fr::from(42u64);
        let mut root_be = [0u8; 32];
        root_be.copy_from_slice(&root.into_bigint().to_bytes_be());

        let cp_msg = checkpoint_quorum_message(&Fr::from(1u64), 1, &root, 1, &signers);
        let sbt_msg = crate::quorum::quorum_cosign_message(&root_be, 1, &signers);
        assert_ne!(cp_msg, sbt_msg);
    }

    #[test]
    fn two_of_three_is_satisfied_by_two_valid_signatures() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let (s2, k2) = signer_for(&[2u8; 32]);
        let (s3, _k3) = signer_for(&[3u8; 32]);
        let signers = vec![s1.clone(), s2.clone(), s3.clone()];
        let (cid, epoch, root) = (Fr::from(7u64), 99i64, Fr::from(99u64));

        let sigs = vec![
            cosign(&k1, &cid, epoch, &root, 2, &signers),
            cosign(&k2, &cid, epoch, &root, 2, &signers),
        ];
        let status = verify_checkpoint_quorum(&cid, epoch, &root, &signers, 2, &sigs);
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
        let (cid, epoch, root) = (Fr::from(7u64), 7i64, Fr::from(7u64));

        let sigs = vec![cosign(&k1, &cid, epoch, &root, 2, &signers)];
        let status = verify_checkpoint_quorum(&cid, epoch, &root, &signers, 2, &sigs);
        assert_eq!(status.valid_signatures, 1);
        assert!(!status.satisfied);
    }

    #[test]
    fn signature_from_non_member_is_not_counted() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let (s2, _k2) = signer_for(&[2u8; 32]);
        let (_outsider, ko) = signer_for(&[99u8; 32]);
        let signers = vec![s1.clone(), s2];
        let (cid, epoch, root) = (Fr::from(7u64), 5i64, Fr::from(5u64));

        // cosign_checkpoint derives the signer pubkey from the key, so this
        // carries the outsider's identity — not in the pinned set.
        let sigs = vec![
            cosign(&k1, &cid, epoch, &root, 2, &signers),
            cosign(&ko, &cid, epoch, &root, 2, &signers),
        ];
        let status = verify_checkpoint_quorum(&cid, epoch, &root, &signers, 2, &sigs);
        assert_eq!(status.valid_signatures, 1, "outsider sig must be ignored");
        assert!(!status.satisfied);
    }

    #[test]
    fn duplicate_signer_counts_once() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let (s2, _k2) = signer_for(&[2u8; 32]);
        let signers = vec![s1.clone(), s2];
        let (cid, epoch, root) = (Fr::from(7u64), 11i64, Fr::from(11u64));

        let sigs = vec![
            cosign(&k1, &cid, epoch, &root, 2, &signers),
            cosign(&k1, &cid, epoch, &root, 2, &signers),
        ];
        let status = verify_checkpoint_quorum(&cid, epoch, &root, &signers, 2, &sigs);
        assert_eq!(status.valid_signatures, 1);
        assert!(!status.satisfied);
    }

    #[test]
    fn signature_over_wrong_identity_is_rejected() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let signers = vec![s1.clone()];
        let (cid, epoch, root) = (Fr::from(1u64), 1i64, Fr::from(1u64));

        // Signed over a different chain_id / epoch / root than verified.
        let wrong_chain = vec![cosign(&k1, &Fr::from(2u64), epoch, &root, 1, &signers)];
        let wrong_epoch = vec![cosign(&k1, &cid, 2, &root, 1, &signers)];
        let wrong_root = vec![cosign(&k1, &cid, epoch, &Fr::from(2u64), 1, &signers)];
        for sigs in [wrong_chain, wrong_epoch, wrong_root] {
            let status = verify_checkpoint_quorum(&cid, epoch, &root, &signers, 1, &sigs);
            assert_eq!(status.valid_signatures, 0);
            assert!(!status.satisfied);
        }
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let signers = vec![s1.clone()];
        let (cid, epoch, root) = (Fr::from(7u64), 3i64, Fr::from(3u64));
        let mut sig = cosign(&k1, &cid, epoch, &root, 1, &signers);
        sig.s = "12345".to_owned();
        let status = verify_checkpoint_quorum(&cid, epoch, &root, &signers, 1, &[sig]);
        assert_eq!(status.valid_signatures, 0);
        assert!(!status.satisfied);
    }

    #[test]
    fn zero_threshold_is_never_vacuously_satisfied() {
        let (s1, k1) = signer_for(&[1u8; 32]);
        let signers = vec![s1.clone()];
        let (cid, epoch, root) = (Fr::from(7u64), 8i64, Fr::from(8u64));
        let sigs = vec![cosign(&k1, &cid, epoch, &root, 0, &signers)];
        let status = verify_checkpoint_quorum(&cid, epoch, &root, &signers, 0, &sigs);
        assert!(!status.satisfied);
    }

    #[test]
    fn golden_vectors_match_committed_file() {
        // Pin the committed golden vector (consumed byte-for-byte by the JS
        // differential verifier, verifiers/javascript/test_checkpoint_quorum.js)
        // against this implementation. Regenerate after an intentional change:
        //   cargo run -p olympus-desktop --example gen_checkpoint_quorum_vectors
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../verifiers/test_vectors/checkpoint_quorum_vectors.json"
        );
        let raw = std::fs::read_to_string(path).expect("read golden vector");
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse golden vector");
        assert_eq!(doc["domain"], "OLY:CHECKPOINT:QUORUM:V2");
        let cases = doc["cases"].as_array().expect("cases array");
        assert!(!cases.is_empty(), "vector must have cases");

        for c in cases {
            let name = c["name"].as_str().unwrap_or("<unnamed>");
            let chain_id = parse_fr(c["chain_id"].as_str().expect("chain_id")).expect("chain_id");
            let epoch = c["epoch"].as_i64().expect("epoch");
            let root = parse_fr(c["root"].as_str().expect("root")).expect("root parses");
            let threshold = u32::try_from(c["threshold"].as_u64().expect("threshold"))
                .expect("threshold fits u32");
            let signers: Vec<QuorumSigner> =
                serde_json::from_value(c["signers"].clone()).expect("signers");
            let cosigs: Vec<CollectedSignature> =
                serde_json::from_value(c["cosignatures"].clone()).expect("cosignatures");

            let status =
                verify_checkpoint_quorum(&chain_id, epoch, &root, &signers, threshold, &cosigs);
            let message = fr_to_decimal(&checkpoint_quorum_message(
                &chain_id, epoch, &root, threshold, &signers,
            ));

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
