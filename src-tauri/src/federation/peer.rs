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
    /// Audit L-F2: timestamp of the most recent pull failure. `None` if
    /// no failure has been recorded since startup (or since migration
    /// 0031 added the columns). Paired with `last_seen_at`: a peer with
    /// `last_pull_error_at > last_seen_at` is failing right now.
    #[serde(default)]
    pub last_pull_error_at: Option<chrono::NaiveDateTime>,
    /// Short human-readable failure reason from the last pull attempt.
    /// Truncated by [`record_pull_error`] to 512 chars to bound row size.
    #[serde(default)]
    pub last_pull_error_msg: Option<String>,
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

/// Validation errors that can be surfaced as a 4xx by the HTTP handler
/// rather than collapsed into a generic 500 from `sqlx::Error`.
#[derive(Debug, thiserror::Error)]
pub enum AddPeerError {
    #[error("invalid onion address: {0}")]
    InvalidOnionAddress(String),
    #[error("invalid BJJ pubkey: {0}")]
    InvalidPubkey(String),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

fn validate_v3_onion_address(onion_address: &str) -> Result<(), AddPeerError> {
    let host = onion_address.trim();
    if host != onion_address || host.is_empty() {
        return Err(AddPeerError::InvalidOnionAddress(
            "address must be a bare v3 .onion hostname without whitespace".to_owned(),
        ));
    }

    let Some(label) = host.strip_suffix(".onion") else {
        return Err(AddPeerError::InvalidOnionAddress(
            "address must end with .onion".to_owned(),
        ));
    };

    if label.len() != 56 {
        return Err(AddPeerError::InvalidOnionAddress(
            "v3 .onion host must have a 56-character service id".to_owned(),
        ));
    }

    if !label
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
    {
        return Err(AddPeerError::InvalidOnionAddress(
            "v3 .onion service id must be lower-case base32".to_owned(),
        ));
    }

    Ok(())
}

pub async fn add_peer(pool: &PgPool, req: &AddPeerRequest) -> Result<PeerNode, AddPeerError> {
    validate_v3_onion_address(&req.onion_address)?;

    // Audit M-8: validate the peer's BJJ pubkey is a well-formed point in
    // the prime-order subgroup BEFORE persisting. A cofactor-coset or
    // off-curve point would still parse as decimal Fr values and pass
    // SQL insertion, but `verify_and_store` would later reject every
    // checkpoint signed under it — failing closed silently. Catching
    // this at the boundary turns "your peer is silently broken" into a
    // 400 with a clear cause.
    let px = crate::zk::proof::parse_fr(&req.bjj_pubkey_x)
        .map_err(|e| AddPeerError::InvalidPubkey(format!("x: {e}")))?;
    let py = crate::zk::proof::parse_fr(&req.bjj_pubkey_y)
        .map_err(|e| AddPeerError::InvalidPubkey(format!("y: {e}")))?;
    let candidate = crate::zk::witness::baby_jubjub::BabyJubJubPubKey { x: px, y: py };
    crate::zk::witness::baby_jubjub::validate_pubkey_subgroup(&candidate)
        .map_err(|e| AddPeerError::InvalidPubkey(format!("subgroup check: {e}")))?;

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

    let row = sqlx::query_as::<_, PeerNode>("SELECT * FROM peer_nodes WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(row)
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
    let result = sqlx::query("UPDATE peer_nodes SET trust_status = $1 WHERE id = $2")
        .bind(trust_status)
        .bind(peer_id)
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;
    Ok(result.rows_affected() > 0)
}

pub async fn touch_last_seen(pool: &PgPool, peer_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE peer_nodes
            SET last_seen_at = NOW(),
                last_pull_error_at = NULL,
                last_pull_error_msg = NULL
          WHERE id = $1",
    )
    .bind(peer_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Audit L-F2: persist a gossip pull failure to `peer_nodes` so an
/// operator can answer "has peer X been reachable lately?" without
/// scraping logs. The message is truncated to [`MAX_ERROR_MSG_LEN`]
/// chars to bound row size — a flapping peer logging multi-KB error
/// strings shouldn't grow the table without bound.
pub async fn record_pull_error(
    pool: &PgPool,
    peer_id: Uuid,
    message: &str,
) -> Result<(), sqlx::Error> {
    let truncated: String = message.chars().take(MAX_ERROR_MSG_LEN).collect();
    sqlx::query(
        "UPDATE peer_nodes
            SET last_pull_error_at = NOW(),
                last_pull_error_msg = $1
          WHERE id = $2",
    )
    .bind(truncated)
    .bind(peer_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_v3_onion_address, AddPeerError};

    #[test]
    fn accepts_bare_v3_onion_hostname() {
        let onion = format!("{}.onion", "a".repeat(56));
        validate_v3_onion_address(&onion).expect("valid v3 onion hostname");
    }

    #[test]
    fn rejects_non_onion_or_non_v3_hosts() {
        for bad in [
            "example.com",
            "abcd.onion",
            "localhost",
            "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:80",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.onion",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion ",
        ] {
            let err = validate_v3_onion_address(bad).expect_err("must reject invalid host");
            assert!(matches!(err, AddPeerError::InvalidOnionAddress(_)));
        }
    }
}

/// Bound on `last_pull_error_msg` length. Picked to fit a few stack
/// frames of an HTTP transport error including timestamps and URLs,
/// without ballooning the row.
const MAX_ERROR_MSG_LEN: usize = 512;
