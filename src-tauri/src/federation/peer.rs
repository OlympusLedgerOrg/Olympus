//! Peer node management — add, remove, list, trust/block.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PeerNode {
    pub id: Uuid,
    pub name: Option<String>,
    pub onion_address: String,
    pub bjj_pubkey_x: String,
    pub bjj_pubkey_y: String,
    pub trust_status: String,
    pub last_seen_at: Option<chrono::NaiveDateTime>,
    pub added_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize)]
pub struct AddPeerRequest {
    pub name: Option<String>,
    pub onion_address: String,
    pub bjj_pubkey_x: String,
    pub bjj_pubkey_y: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTrustRequest {
    pub trust_status: String,
}

pub async fn list_peers(pool: &PgPool) -> Result<Vec<PeerNode>, sqlx::Error> {
    sqlx::query_as::<_, PeerNode>("SELECT * FROM peer_nodes ORDER BY added_at DESC")
        .fetch_all(pool)
        .await
}

pub async fn list_trusted_peers(pool: &PgPool) -> Result<Vec<PeerNode>, sqlx::Error> {
    sqlx::query_as::<_, PeerNode>(
        "SELECT * FROM peer_nodes WHERE trust_status = 'trusted' ORDER BY added_at",
    )
    .fetch_all(pool)
    .await
}

pub async fn add_peer(pool: &PgPool, req: &AddPeerRequest) -> Result<PeerNode, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO peer_nodes (id, name, onion_address, bjj_pubkey_x, bjj_pubkey_y)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(&req.name)
    .bind(&req.onion_address)
    .bind(&req.bjj_pubkey_x)
    .bind(&req.bjj_pubkey_y)
    .execute(pool)
    .await?;

    sqlx::query_as::<_, PeerNode>("SELECT * FROM peer_nodes WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
}

pub async fn remove_peer(pool: &PgPool, peer_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM peer_nodes WHERE id = $1")
        .bind(peer_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

const VALID_TRUST_STATUSES: &[&str] = &["pending", "trusted", "blocked"];

pub async fn update_trust(
    pool: &PgPool,
    peer_id: Uuid,
    trust_status: &str,
) -> Result<bool, String> {
    if !VALID_TRUST_STATUSES.contains(&trust_status) {
        return Err(format!(
            "invalid trust_status '{trust_status}'; must be one of: {}",
            VALID_TRUST_STATUSES.join(", ")
        ));
    }
    let result = sqlx::query(
        "UPDATE peer_nodes SET trust_status = $1 WHERE id = $2",
    )
    .bind(trust_status)
    .bind(peer_id)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;
    Ok(result.rows_affected() > 0)
}

pub async fn touch_last_seen(pool: &PgPool, peer_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE peer_nodes SET last_seen_at = NOW() WHERE id = $1")
        .bind(peer_id)
        .execute(pool)
        .await?;
    Ok(())
}
