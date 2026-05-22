//! Equivocation detection — flag peers that publish conflicting checkpoints.
//!
//! If the same peer publishes two different ledger roots for the same
//! checkpoint timestamp, that's a provable equivocation (fork).

use sqlx::PgPool;
use uuid::Uuid;

/// Check whether a peer already has a checkpoint at the given timestamp
/// with a different ledger root. If so, mark both as equivocating.
///
/// Returns `true` if equivocation was detected.
pub async fn check_and_flag(
    pool: &PgPool,
    peer_id: Uuid,
    checkpoint_timestamp: i64,
    ledger_root: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let conflicting: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM peer_checkpoints
         WHERE peer_id = $1
           AND checkpoint_timestamp = $2
           AND ledger_root != $3
           AND equivocation_detected = false
         LIMIT 1
         FOR UPDATE",
    )
    .bind(peer_id)
    .bind(checkpoint_timestamp)
    .bind(ledger_root)
    .fetch_optional(&mut *tx)
    .await?;

    if conflicting.is_some() {
        tracing::warn!(
            "federation: EQUIVOCATION detected for peer {peer_id} at timestamp {checkpoint_timestamp}"
        );

        sqlx::query(
            "UPDATE peer_checkpoints
             SET equivocation_detected = true
             WHERE peer_id = $1 AND checkpoint_timestamp = $2",
        )
        .bind(peer_id)
        .bind(checkpoint_timestamp)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    } else {
        tx.commit().await?;
        Ok(false)
    }
}

/// Auto-block a peer that equivocated.
pub async fn auto_block_peer(pool: &PgPool, peer_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE peer_nodes SET trust_status = 'blocked' WHERE id = $1")
        .bind(peer_id)
        .execute(pool)
        .await?;
    tracing::warn!("federation: auto-blocked peer {peer_id} due to equivocation");
    Ok(())
}

/// Count equivocation events across all peers.
pub async fn equivocation_count(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT (peer_id, checkpoint_timestamp))
         FROM peer_checkpoints WHERE equivocation_detected = true",
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}
