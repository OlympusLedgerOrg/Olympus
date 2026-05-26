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

/// Check if a peer's BJJ pubkey matches a given authority_pubkey_hash.
pub fn peer_matches_authority_hash(peer: &super::peer::PeerNode, authority_hash: &str) -> bool {
    use ark_bn254::Fr;
    let Ok(x) = crate::zk::proof::parse_fr(&peer.bjj_pubkey_x) else { return false };
    let Ok(y) = crate::zk::proof::parse_fr(&peer.bjj_pubkey_y) else { return false };
    let pubkey = crate::zk::witness::baby_jubjub::BabyJubJubPubKey { x, y };
    let Ok(hash) = pubkey.authority_hash() else { return false };
    fr_to_decimal(&hash) == authority_hash
}

/// Build this node's latest checkpoint from the database.
///
/// Returns `None` if the database has no ingest records yet.
///
/// **H-11 / M-5 status:** this function currently has no Groth16-proof
/// emission step. Rather than emit an unverifiable null-proof envelope
/// (which the receive path used to silently accept), it returns
/// `Err(BUILD_OWN_CHECKPOINT_NO_PROOF)` to make the missing proving
/// step visible. Wiring `prove_unified` here — constructing a
/// `UnifiedWitness` from the current ingest state, running the unified
/// circuit prover, and encoding the resulting Groth16 proof — is the
/// dual-side fix that lets honest peers participate again; until then,
/// federation gossip is honestly disabled at the producer rather than
/// silently emitting unattested checkpoints. The receive path
/// (`verify::verify_and_store`) hard-rejects null-proof envelopes.
pub const BUILD_OWN_CHECKPOINT_NO_PROOF: &str =
    "build_own_checkpoint: Groth16 proof emission not yet wired — \
     refusing to emit an unverifiable null-proof checkpoint (audit H-11/M-5). \
     See `checkpoint.rs::build_own_checkpoint` doc comment.";

pub async fn build_own_checkpoint(
    pool: &PgPool,
    bjj_key: &[u8; 32],
    bjj_pubkey: &crate::zk::witness::baby_jubjub::BabyJubJubPubKey,
) -> Result<Option<PeerCheckpoint>, String> {
    // Get latest ingest record with a Merkle/Poseidon root.
    let latest: Option<(String,)> = sqlx::query_as(
        "SELECT merkle_root FROM ingest_records
         WHERE merkle_root IS NOT NULL
         ORDER BY ts DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("DB error: {e}"))?;

    let merkle_root_str = match latest {
        Some((r,)) => r,
        None => return Ok(None),
    };

    let tree_size: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ingest_records")
        .fetch_one(pool)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let ledger_root = crate::zk::proof::parse_fr(&merkle_root_str)
        .map_err(|e| format!("parse ledger root: {e}"))?;

    let sig = crate::zk::witness::unified::UnifiedWitness::sign_checkpoint(
        bjj_key,
        ledger_root,
        now as u64,
    )
    .map_err(|e| format!("BJJ sign: {e}"))?;

    let authority_hash = bjj_pubkey
        .authority_hash()
        .map_err(|e| format!("pubkey hash: {e}"))?;

    // H-11 / M-5 closure: refuse to emit an unverifiable null-proof
    // envelope. See the const + function-level doc above. Suppress the
    // unused-variable warnings on values built for the
    // not-yet-wired prove_unified step; keeping the signing work in
    // place documents the message shape the proof will eventually bind.
    let _ = (merkle_root_str, tree_size, now, authority_hash, sig);
    Err(BUILD_OWN_CHECKPOINT_NO_PROOF.to_owned())
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
