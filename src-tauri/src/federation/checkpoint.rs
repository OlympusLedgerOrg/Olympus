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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCheckpoint {
    pub ledger_root: String,
    pub tree_size: i64,
    pub checkpoint_timestamp: i64,
    pub authority_pubkey_hash: String,
    pub groth16_proof: serde_json::Value,
    pub public_signals: Vec<String>,
    pub bjj_signature: Option<BjjSignatureWire>,
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

/// Verify the BJJ-EdDSA signature a peer attached to a checkpoint against the
/// peer's *registered* pubkey (`peer_nodes.bjj_pubkey_*`).
///
/// Audit (TOB-OLY-01): checkpoints were previously stored — and fed to
/// equivocation detection / auto-blocking — without ever verifying this
/// signature, so anyone who knew a trusted peer's public key (exposed via
/// `GET /federation/identity`) could forge checkpoints in that peer's name and
/// frame it into an equivocation block. The signed message is
/// `Poseidon(ledgerRoot, checkpointTimestamp)` — identical to
/// `UnifiedWitness::sign_checkpoint`.
pub fn verify_checkpoint_signature(peer: &super::peer::PeerNode, cp: &PeerCheckpoint) -> bool {
    use crate::zk::poseidon::hash2;
    use crate::zk::proof::parse_fr;
    use crate::zk::witness::baby_jubjub::{
        verify_signature, BabyJubJubPubKey, BabyJubJubSignature,
    };

    let Some(sig) = cp.bjj_signature.as_ref() else {
        return false;
    };
    if cp.checkpoint_timestamp < 0 {
        return false;
    }
    let (Ok(px), Ok(py)) = (parse_fr(&peer.bjj_pubkey_x), parse_fr(&peer.bjj_pubkey_y)) else {
        return false;
    };
    let (Ok(r8x), Ok(r8y), Ok(s)) = (parse_fr(&sig.r8x), parse_fr(&sig.r8y), parse_fr(&sig.s))
    else {
        return false;
    };
    let Ok(ledger_root) = parse_fr(&cp.ledger_root) else {
        return false;
    };
    let Ok(msg) = hash2(ledger_root, Fr::from(cp.checkpoint_timestamp as u64)) else {
        return false;
    };
    verify_signature(
        &BabyJubJubPubKey { x: px, y: py },
        &BabyJubJubSignature { r8x, r8y, s },
        msg,
    )
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

    Ok(Some(PeerCheckpoint {
        ledger_root: merkle_root_str.clone(),
        tree_size: tree_size.0,
        checkpoint_timestamp: now,
        authority_pubkey_hash: fr_to_decimal(&authority_hash),
        groth16_proof: serde_json::json!(null),
        public_signals: vec![
            merkle_root_str,
            tree_size.0.to_string(),
            now.to_string(),
            fr_to_decimal(&authority_hash),
        ],
        bjj_signature: Some(BjjSignatureWire {
            r8x: fr_to_decimal(&sig.r8x),
            r8y: fr_to_decimal(&sig.r8y),
            s: fr_to_decimal(&sig.s),
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
