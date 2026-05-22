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
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())",
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
