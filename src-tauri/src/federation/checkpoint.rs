//! Checkpoint creation, storage, and exchange.
//!
//! A checkpoint bundles this node's latest ledger state with a Groth16 proof
//! and BJJ signature so peers can verify without seeing the data.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Wire format for checkpoint exchange between peers.
///
/// Audit L-F1: carries an explicit [`Self::wire_version`] so future
/// shape changes can be detected at the verify layer instead of being
/// silently misparsed as the current shape. Defaults to the current
/// version on deserialise so checkpoints emitted before the field
/// landed continue to round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCheckpoint {
    /// Wire-format version. See [`super::PEER_CHECKPOINT_WIRE_VERSION`].
    /// `verify_and_store` rejects checkpoints whose version doesn't
    /// match the current constant.
    #[serde(default = "default_wire_version")]
    pub wire_version: u8,
    pub ledger_root: String,
    pub tree_size: i64,
    pub checkpoint_timestamp: i64,
    pub authority_pubkey_hash: String,
    pub groth16_proof: serde_json::Value,
    pub public_signals: Vec<String>,
    pub bjj_signature: Option<BjjSignatureWire>,
}

fn default_wire_version() -> u8 {
    super::PEER_CHECKPOINT_WIRE_VERSION
}

impl PeerCheckpoint {
    /// Current wire-format version. Use when constructing a new
    /// outbound checkpoint so the field is set explicitly rather than
    /// relying on the serde default.
    pub fn current_version() -> u8 {
        super::PEER_CHECKPOINT_WIRE_VERSION
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BjjSignatureWire {
    pub r8x: String,
    pub r8y: String,
    pub s: String,
}

/// Stored checkpoint from a peer.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct StoredCheckpoint {
    pub id: Uuid,
    pub peer_id: Uuid,
    pub ledger_root: String,
    pub tree_size: i64,
    pub checkpoint_timestamp: i64,
    pub authority_pubkey_hash: String,
    pub groth16_proof: serde_json::Value,
    pub public_signals: serde_json::Value,
    pub bjj_signature_r8x: Option<String>,
    pub bjj_signature_r8y: Option<String>,
    pub bjj_signature_s: Option<String>,
    pub verified: bool,
    pub equivocation_detected: bool,
    pub received_at: chrono::NaiveDateTime,
}

pub fn fr_to_decimal(f: &Fr) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

/// Strict canonical-JSON receive gate.
///
/// Re-canonicalises the received bytes and rejects the envelope if the
/// canonical form differs from what was actually transmitted — i.e. the
/// sender used a non-conformant JSON serializer. Then deserialises the
/// canonical bytes into a `PeerCheckpoint`. Pair to
/// [`canonical_checkpoint_bytes`]: producers emit canonical, receivers
/// require canonical, full-stop. Closes the CodeRabbit "JCS on the wire"
/// finding on both sides.
///
/// Rejecting non-canonical envelopes is stricter than necessary for the
/// current downstream code path (which consumes the parsed struct, not
/// the bytes) but matches CLAUDE.md's invariant and prevents a future
/// contributor from accidentally hashing/anchoring/persisting raw wire
/// bytes that aren't byte-identical across federation peers.
pub fn parse_canonical_checkpoint(bytes: &[u8]) -> Result<PeerCheckpoint, String> {
    let canonical = olympus_crypto::canonical::canonicalize_bytes(bytes)
        .map_err(|e| format!("canonicalize received envelope: {e}"))?;
    if canonical != bytes {
        return Err("checkpoint wire bytes are not RFC 8785 / JCS canonical \
             (re-canonicalisation produced different bytes) — rejecting \
             non-canonical envelope"
            .to_owned());
    }
    serde_json::from_slice(&canonical).map_err(|e| format!("parse: {e}"))
}

/// Serialize a `PeerCheckpoint` to JCS / RFC 8785 canonical JSON bytes.
///
/// Used by both federation wire emission paths — gossip push
/// (`gossip::push_checkpoint`) and the GET-latest endpoint
/// (`api::get_latest_checkpoint`) — so that every checkpoint that
/// crosses the federation wire is byte-identical for the same logical
/// content. Enforces the project-wide JCS invariant in `CLAUDE.md`
/// ("Canonical JSON: Always JCS/RFC 8785 raw UTF-8") on this
/// transport. Follows the same pattern as
/// `api::credentials::canonical_details_bytes`.
pub fn canonical_checkpoint_bytes(cp: &PeerCheckpoint) -> Result<Vec<u8>, String> {
    let raw = serde_json::to_vec(cp).map_err(|e| format!("serialize: {e}"))?;
    olympus_crypto::canonical::canonicalize_bytes(&raw).map_err(|e| format!("canonicalize: {e}"))
}

/// Check if a peer's BJJ pubkey matches a given authority_pubkey_hash.
pub fn peer_matches_authority_hash(peer: &super::peer::PeerNode, authority_hash: &str) -> bool {
    use ark_bn254::Fr;
    let Ok(x) = crate::zk::proof::parse_fr(&peer.bjj_pubkey_x) else {
        return false;
    };
    let Ok(y) = crate::zk::proof::parse_fr(&peer.bjj_pubkey_y) else {
        return false;
    };
    let pubkey = crate::zk::witness::baby_jubjub::BabyJubJubPubKey { x, y };
    let Ok(hash) = pubkey.authority_hash() else {
        return false;
    };
    fr_to_decimal(&hash) == authority_hash
}

/// Build this node's latest checkpoint by reading the most recent
/// gossipable row from `own_checkpoints` (red-team PR E).
///
/// Before PR E, this function was the producer: it queried
/// `ingest_records`, built the existence witness, ran `prove_existence`,
/// signed, and emitted directly. The cron path separately built its
/// own checkpoint from a different column (`merkle_root` vs
/// `snapshot_root`) so the two views disagreed on the canonical ledger
/// root — and the anchor receipts had no row to FK back to.
///
/// PR E unifies: the always-built `anchoring::own_checkpoint::build_and_persist`
/// (driven by the anchor cron) is the sole producer. Federation reads
/// the latest row whose Groth16 proof + BJJ signature are both present
/// and wraps it as a `PeerCheckpoint` for the wire.
///
/// Returns `None` if (a) the database has no row in `own_checkpoints`
/// yet — typical on a fresh node before the cron has ticked, or in a
/// build with the federation feature compiled in but `OLYMPUS_ANCHOR_*`
/// unconfigured (no cron to produce rows) — or (b) the latest row
/// lacks a proof/sig (operator hasn't staged the document_existence
/// artifacts). The legacy `_` arguments are retained so the gossip
/// loop's existing call shape doesn't change; they're unused here.
#[allow(unused_variables)]
pub async fn build_own_checkpoint(
    pool: &PgPool,
    bjj_key: &[u8; 32],
    bjj_pubkey: &crate::zk::witness::baby_jubjub::BabyJubJubPubKey,
    proofs_dir: Option<&std::path::Path>,
) -> Result<Option<PeerCheckpoint>, String> {
    let Some(row) = crate::anchoring::own_checkpoint::fetch_latest_gossipable(pool).await? else {
        return Ok(None);
    };

    // The gossipable predicate guarantees the four sig fields and the
    // proof are present; unwrap defensively.
    let (sig_r8x, sig_r8y, sig_s) = match (row.sig_r8x, row.sig_r8y, row.sig_s) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return Ok(None),
    };
    let authority_pubkey_hash = match row.authority_pubkey_hash {
        Some(h) => h,
        None => return Ok(None),
    };
    let groth16_proof = match row.groth16_proof {
        Some(p) => p,
        None => return Ok(None),
    };
    let public_signals = row.public_signals.unwrap_or_default();

    Ok(Some(PeerCheckpoint {
        wire_version: PeerCheckpoint::current_version(),
        ledger_root: row.ledger_root,
        tree_size: row.tree_size,
        checkpoint_timestamp: row.checkpoint_timestamp,
        authority_pubkey_hash,
        groth16_proof,
        public_signals,
        bjj_signature: Some(BjjSignatureWire {
            r8x: sig_r8x,
            r8y: sig_r8y,
            s: sig_s,
        }),
    }))
}

/// Submit a checkpoint to every configured external anchor (RFC 3161 / Rekor
/// / OTS) and persist the resulting receipts linked back to a checkpoint
/// row id. Failure on any single anchor is logged but does not abort —
/// the three are intentionally redundant.
///
/// Call this after `store_peer_checkpoint` (or after `build_own_checkpoint`
/// for the local node's own checkpoint, once it's been persisted with a
/// row id) so the receipts have a stable `checkpoint_id` to link to.
pub async fn anchor_checkpoint(
    pool: &sqlx::PgPool,
    cfg: &crate::anchoring::AnchoringConfig,
    http: &reqwest::Client,
    cp: &PeerCheckpoint,
    checkpoint_id: Option<Uuid>,
) -> (usize, usize) {
    if !cfg.any_enabled() {
        return (0, 0);
    }
    let sig = cp.bjj_signature.as_ref();
    let hash = crate::anchoring::checkpoint_anchor_hash(
        &cp.ledger_root,
        cp.tree_size,
        cp.checkpoint_timestamp,
        &cp.authority_pubkey_hash,
        sig.map(|s| s.r8x.as_str()),
        sig.map(|s| s.r8y.as_str()),
        sig.map(|s| s.s.as_str()),
    );
    let (ok, errs) = crate::anchoring::anchor_all(pool, cfg, http, hash, checkpoint_id).await;
    for (kind, e) in &errs {
        tracing::warn!(
            "federation: anchor {} failed for checkpoint {:?}: {}",
            kind.as_str(),
            checkpoint_id,
            e
        );
    }
    (ok.len(), errs.len())
}

/// Store a checkpoint received from a peer.
pub async fn store_peer_checkpoint(
    pool: &PgPool,
    peer_id: Uuid,
    cp: &PeerCheckpoint,
    verified: bool,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    let sig = cp.bjj_signature.as_ref();

    sqlx::query(
        "INSERT INTO peer_checkpoints
             (id, peer_id, ledger_root, tree_size, checkpoint_timestamp,
              authority_pubkey_hash, groth16_proof, public_signals,
              bjj_signature_r8x, bjj_signature_r8y, bjj_signature_s,
              verified, received_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
         ON CONFLICT (peer_id, checkpoint_timestamp, ledger_root) DO NOTHING",
    )
    .bind(id)
    .bind(peer_id)
    .bind(&cp.ledger_root)
    .bind(cp.tree_size)
    .bind(cp.checkpoint_timestamp)
    .bind(&cp.authority_pubkey_hash)
    .bind(&cp.groth16_proof)
    .bind(serde_json::to_value(&cp.public_signals).unwrap_or_default())
    .bind(sig.map(|s| &s.r8x))
    .bind(sig.map(|s| &s.r8y))
    .bind(sig.map(|s| &s.s))
    .bind(verified)
    .execute(pool)
    .await?;

    Ok(id)
}

/// List checkpoints from a specific peer, newest first.
pub async fn list_peer_checkpoints(
    pool: &PgPool,
    peer_id: Option<Uuid>,
    limit: i64,
) -> Result<Vec<StoredCheckpoint>, sqlx::Error> {
    if let Some(pid) = peer_id {
        sqlx::query_as::<_, StoredCheckpoint>(
            "SELECT * FROM peer_checkpoints WHERE peer_id = $1
             ORDER BY received_at DESC LIMIT $2",
        )
        .bind(pid)
        .bind(limit)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, StoredCheckpoint>(
            "SELECT * FROM peer_checkpoints ORDER BY received_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod wire_tests {
    //! Audit L-F1: pin the wire-version behaviour so any future change
    //! to the serialised shape has to be conscious.
    use super::*;

    fn fixture_payload_without_version() -> serde_json::Value {
        // Mirrors a v0 emission (no `wire_version` field).
        serde_json::json!({
            "ledger_root": "1",
            "tree_size": 1,
            "checkpoint_timestamp": 1700000000,
            "authority_pubkey_hash": "0",
            "groth16_proof": null,
            "public_signals": [],
            "bjj_signature": null,
        })
    }

    /// Build a valid `PeerCheckpoint` and return its canonical JSON
    /// bytes — the byte-exact form a conformant peer would emit.
    fn canonical_fixture_bytes() -> Vec<u8> {
        let cp = PeerCheckpoint {
            wire_version: PeerCheckpoint::current_version(),
            ledger_root: "1".to_owned(),
            tree_size: 1,
            checkpoint_timestamp: 1_700_000_000,
            authority_pubkey_hash: "0".to_owned(),
            groth16_proof: serde_json::json!({"pi_a": [], "pi_b": [], "pi_c": []}),
            public_signals: vec!["1".to_owned()],
            bjj_signature: None,
        };
        canonical_checkpoint_bytes(&cp).expect("canonicalize fixture")
    }

    #[test]
    fn parse_canonical_accepts_canonical_bytes() {
        // Round-trip: emitter produces canonical bytes; receiver
        // accepts them. This is the happy path between two
        // JCS-conformant peers.
        let bytes = canonical_fixture_bytes();
        let cp = parse_canonical_checkpoint(&bytes).expect("canonical bytes must parse");
        assert_eq!(cp.ledger_root, "1");
        assert_eq!(cp.tree_size, 1);
    }

    #[test]
    fn parse_canonical_rejects_non_canonical_bytes() {
        // A peer emitting "valid JSON but not canonical" (e.g. with
        // whitespace, or keys out of canonical order) gets rejected.
        // JCS sorts object keys by UTF-16 code-unit order; this
        // hand-rolled form sorts keys differently and adds whitespace.
        let non_canonical = br#"{
  "wire_version": 1,
  "ledger_root": "1",
  "tree_size": 1,
  "checkpoint_timestamp": 1700000000,
  "authority_pubkey_hash": "0",
  "public_signals": ["1"],
  "groth16_proof": {"pi_a": [], "pi_b": [], "pi_c": []},
  "bjj_signature": null
}"#;
        let err = parse_canonical_checkpoint(non_canonical)
            .expect_err("non-canonical envelope must be rejected");
        assert!(
            err.contains("not RFC 8785 / JCS canonical"),
            "error should call out JCS violation, got: {err}"
        );
    }

    #[test]
    fn parse_canonical_rejects_invalid_json() {
        let err = parse_canonical_checkpoint(b"not even json")
            .expect_err("garbage bytes must be rejected");
        // Either the canonicalize step or the parse step fails — both
        // are acceptable since both are JCS-enforcement failures.
        assert!(
            err.contains("canonicalize") || err.contains("parse"),
            "error should indicate JCS or parse failure, got: {err}"
        );
    }

    #[test]
    fn current_version_constant_is_one() {
        // Wire version is currently 1. Any bump is intentional — this
        // test exists so the bump shows up in code review.
        assert_eq!(PeerCheckpoint::current_version(), 1);
        assert_eq!(default_wire_version(), 1);
    }

    #[test]
    fn deserialise_defaults_missing_wire_version_to_current() {
        // Peers emitting the pre-L-F1 shape (no `wire_version`) must
        // continue to deserialise at the current version so a partial
        // upgrade doesn't drop every checkpoint at the wire boundary.
        // verify_and_store still rejects mismatched versions; this is
        // only about parse-side compat.
        let cp: PeerCheckpoint =
            serde_json::from_value(fixture_payload_without_version()).expect("deserialise");
        assert_eq!(cp.wire_version, PeerCheckpoint::current_version());
    }

    #[test]
    fn explicit_wire_version_round_trips() {
        let mut payload = fixture_payload_without_version();
        payload["wire_version"] = serde_json::json!(7);
        let cp: PeerCheckpoint = serde_json::from_value(payload).unwrap();
        assert_eq!(cp.wire_version, 7);
        // Serialise → re-deserialise preserves the value.
        let json = serde_json::to_value(&cp).unwrap();
        assert_eq!(json["wire_version"], 7);
    }
}
