//! Equivocation detection — flag peers that publish conflicting checkpoints.
//!
//! If the same peer publishes two different ledger roots for the same
//! checkpoint timestamp — OR for the same ledger height (`tree_size`) —
//! that's a provable equivocation (fork).

use sqlx::PgPool;
use uuid::Uuid;

/// Check whether a peer already has a stored checkpoint that conflicts with
/// the incoming `(ledger_root, checkpoint_timestamp, tree_size)`. A conflict
/// is a prior row from the same peer with a **different** `ledger_root` at
/// **either** the same `checkpoint_timestamp` **or** the same `tree_size`
/// (audit A1-03(b): two different roots at the same ledger height but
/// different timestamps used to escape detection). If a conflict is found,
/// mark all of the colliding rows (and, transitively, the incoming row once
/// stored) as equivocating.
///
/// Runs inside the caller's transaction (`&mut PgConnection`) so detection
/// and the subsequent [`super::checkpoint::store_peer_checkpoint`] INSERT are
/// atomic under the caller's per-peer advisory lock (audit A1-03(a): the
/// previous detect-then-store split let two concurrent conflicting pushes
/// each miss the other). **Must run BEFORE the incoming row is inserted** so
/// it sees prior rows, not itself.
///
/// Returns `true` if equivocation was detected.
pub async fn check_and_flag(
    conn: &mut sqlx::PgConnection,
    peer_id: Uuid,
    checkpoint_timestamp: i64,
    tree_size: i64,
    ledger_root: &str,
) -> Result<bool, sqlx::Error> {
    // Detection: a prior row from this peer with a DIFFERENT ledger_root at
    // the SAME timestamp OR the SAME height. No `equivocation_detected`
    // filter — already-flagged conflicts must still match so continued
    // equivocation at a flagged timestamp/height is not silently recorded
    // (audit A1-03(b)). `FOR UPDATE` locks the matched rows for the in-tx
    // UPDATE below.
    let conflicting: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM peer_checkpoints
         WHERE peer_id = $1
           AND ledger_root != $2
           AND (checkpoint_timestamp = $3 OR tree_size = $4)
         LIMIT 1
         FOR UPDATE",
    )
    .bind(peer_id)
    .bind(ledger_root)
    .bind(checkpoint_timestamp)
    .bind(tree_size)
    .fetch_optional(&mut *conn)
    .await?;

    if conflicting.is_some() {
        tracing::warn!(
            "federation: EQUIVOCATION detected for peer {peer_id} at timestamp \
             {checkpoint_timestamp} / tree_size {tree_size}"
        );

        // Flag the prior rows at the colliding timestamp or height. The
        // INCOMING row is flagged separately: it hasn't been inserted yet
        // (the INSERT runs after this in the same tx), so the caller passes
        // `equivocated = true` to `store_peer_checkpoint`, which stamps the
        // new row's `equivocation_detected`. We deliberately do NOT widen
        // this UPDATE to `ledger_root = <incoming>`: that would over-flag an
        // unrelated, non-conflicting prior row that happened to carry the
        // same root at a different timestamp/height.
        sqlx::query(
            "UPDATE peer_checkpoints
             SET equivocation_detected = true
             WHERE peer_id = $1
               AND ledger_root != $2
               AND (checkpoint_timestamp = $3 OR tree_size = $4)",
        )
        .bind(peer_id)
        .bind(ledger_root)
        .bind(checkpoint_timestamp)
        .bind(tree_size)
        .execute(&mut *conn)
        .await?;

        Ok(true)
    } else {
        Ok(false)
    }
}

/// Auto-block a peer that equivocated.
///
/// Runs on the caller's connection so the block lands in the same atomic
/// transaction as detection + store (audit A1-03(a)).
pub async fn auto_block_peer(
    conn: &mut sqlx::PgConnection,
    peer_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE peer_nodes SET trust_status = 'blocked' WHERE id = $1")
        .bind(peer_id)
        .execute(&mut *conn)
        .await?;
    tracing::warn!("federation: auto-blocked peer {peer_id} due to equivocation");
    Ok(())
}

/// Count the peers that have equivocated at least once.
///
/// Counts distinct *peers* rather than distinct `(peer_id, checkpoint_timestamp)`
/// pairs: detection is now disjunctive (`same timestamp OR same tree_size`,
/// audit A1-03), so a single height-based fork can flag rows at two different
/// timestamps. Grouping on the timestamp would then report one fork as two
/// "events"; counting distinct equivocating peers is unambiguous under either
/// match dimension.
pub async fn equivocation_count(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT peer_id)
         FROM peer_checkpoints WHERE equivocation_detected = true",
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}
