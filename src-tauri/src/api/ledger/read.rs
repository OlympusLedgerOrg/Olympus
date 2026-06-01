//! Read-only ledger routes: state, per-shard state, commit proof, and the
//! activity feed. Split out of the ledger module.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{NaiveDateTime, Utc};

use super::*;
use crate::api::middleware::auth::RateLimit;
use crate::state::AppState;

// ── DB row (activity feed) ──────────────────────────────────────────────────
#[derive(sqlx::FromRow)]
struct ActivityRow {
    id: String,
    timestamp: chrono::DateTime<Utc>,
    activity_type: String,
    title: String,
    description: String,
    related_commit_id: Option<String>,
    request_id: Option<String>,
}

// ── Helper: shard state root ──────────────────────────────────────────────────

/// Return the merkle_root of the most recent commit in `shard_id`, or ZERO_ROOT.
async fn shard_state_root(pool: &sqlx::PgPool, shard_id: &str) -> Result<String, ApiError> {
    let root: Option<Option<String>> = sqlx::query_scalar(
        "SELECT merkle_root FROM doc_commits
         WHERE shard_id = $1
         ORDER BY epoch_timestamp DESC
         LIMIT 1",
    )
    .bind(shard_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    Ok(root
        .flatten()
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| ZERO_ROOT.to_owned()))
}

// ── Route: GET /ledger/state ──────────────────────────────────────────────────

pub(super) async fn get_ledger_state(
    State(state): State<AppState>,
    _rl: RateLimit,
) -> Result<Json<LedgerStateResponse>, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let total_commits: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM doc_commits")
        .fetch_one(pool)
        .await
        .map_err(db_err)?;

    let last_epoch: Option<NaiveDateTime> =
        sqlx::query_scalar("SELECT MAX(epoch_timestamp) FROM doc_commits")
            .fetch_one(pool)
            .await
            .map_err(db_err)?;

    let shard_ids: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT shard_id FROM doc_commits ORDER BY shard_id LIMIT 1000",
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let shard_ids = if shard_ids.is_empty() {
        vec![DEFAULT_SHARD.to_owned()]
    } else {
        shard_ids
    };

    let mut shard_roots = Vec::with_capacity(shard_ids.len());
    for sid in &shard_ids {
        shard_roots.push(shard_state_root(pool, sid).await?);
    }

    let global_root = if shard_roots.len() == 1 {
        shard_roots[0].clone()
    } else {
        // BLAKE3 over domain tag + length-prefixed shard roots (lexicographic
        // order preserved above). Audit B1: each root is length-prefixed so the
        // preimage is unambiguous regardless of per-root byte length, and a
        // non-hex root is now a hard error rather than being silently hashed as
        // raw string bytes (which mixed two encodings into one digest).
        // The domain tag is versioned (`OLY:*:V*` convention) so a future
        // layout change can bump the suffix; this aggregate is display-only
        // (never persisted, signed, or anchored), so versioning it is
        // non-breaking.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"OLY:GLOBAL_ROOT:V1");
        for r in &shard_roots {
            let bytes = hex::decode(r).map_err(|e| {
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("shard state root is not valid hex: {e}"),
                )
            })?;
            hasher.update(&olympus_crypto::length_prefixed(&bytes));
        }
        hasher.finalize().to_hex().to_string()
    };

    Ok(Json(LedgerStateResponse {
        global_state_root: global_root,
        shard_count: shard_ids.len(),
        total_commits,
        last_epoch: last_epoch.map(|dt| dt.format("%Y-%m-%dT%H:%M:%S").to_string()),
    }))
}

// ── Route: GET /ledger/shard/{shard_id} ──────────────────────────────────────

pub(super) async fn get_shard_state(
    State(state): State<AppState>,
    _rl: RateLimit,
    Path(shard_id): Path<String>,
) -> Result<Json<ShardStateResponse>, ApiError> {
    if !valid_shard_id(&shard_id) {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid shard_id."));
    }

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let commit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM doc_commits WHERE shard_id = $1")
            .bind(&shard_id)
            .fetch_one(pool)
            .await
            .map_err(db_err)?;

    let commits = sqlx::query_as::<_, DocCommitRow>(
        "SELECT id, request_id, doc_hash, commit_id, epoch_timestamp, shard_id,
                merkle_root, zk_proof
         FROM doc_commits
         WHERE shard_id = $1
         ORDER BY epoch_timestamp DESC
         LIMIT 10",
    )
    .bind(&shard_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let state_root = shard_state_root(pool, &shard_id).await?;

    Ok(Json(ShardStateResponse {
        shard_id,
        state_root,
        commit_count,
        latest_commits: commits.iter().map(commit_summary).collect(),
    }))
}

fn commit_summary(row: &DocCommitRow) -> CommitSummary {
    CommitSummary {
        commit_id: row.commit_id.clone(),
        doc_hash: row.doc_hash.clone(),
        epoch: row.epoch_timestamp.format("%Y-%m-%dT%H:%M:%S").to_string(),
        shard_id: row.shard_id.clone(),
        merkle_root: row.merkle_root.clone(),
    }
}

// ── Route: GET /ledger/proof/{commit_id} ─────────────────────────────────────

pub(super) async fn get_commit_proof(
    State(state): State<AppState>,
    _rl: RateLimit,
    Path(commit_id): Path<String>,
) -> Result<(StatusCode, Json<ProofResponse>), ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let commit = sqlx::query_as::<_, DocCommitRow>(
        "SELECT id, request_id, doc_hash, commit_id, epoch_timestamp, shard_id,
                merkle_root, zk_proof
         FROM doc_commits
         WHERE commit_id = $1",
    )
    .bind(&commit_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Commit not found."))?;

    Ok((
        StatusCode::ACCEPTED,
        Json(ProofResponse {
            commit_id: commit.commit_id,
            shard_id: commit.shard_id,
            epoch: commit
                .epoch_timestamp
                .format("%Y-%m-%dT%H:%M:%S")
                .to_string(),
            status: "pending",
            reason: "ZK proof generation pending Groth16 trusted setup ceremony. \
                     This record is anchored in the Merkle ledger but the ZK proof \
                     is not yet available.",
            merkle_root: commit.merkle_root,
            merkle_proof: vec![],
        }),
    ))
}

// ── Route: GET /ledger/activity ───────────────────────────────────────────────

pub(super) async fn get_ledger_activity(
    State(state): State<AppState>,
    _rl: RateLimit,
    Query(params): Query<ActivityQuery>,
) -> Result<Json<ActivityFeedResponse>, ApiError> {
    let limit =
        crate::api::pagination::clamp_with_log("GET /ledger/activity", params.limit, 1, 200) as i64;
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let (rows, total) = if let Some(ref activity_type) = params.activity_type {
        let upper = activity_type.to_uppercase();
        let rows = sqlx::query_as::<_, ActivityRow>(
            "SELECT id, timestamp, activity_type, title, description,
                    related_commit_id, request_id
             FROM ledger_activities
             WHERE activity_type = $1
             ORDER BY timestamp DESC
             LIMIT $2",
        )
        .bind(&upper)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ledger_activities WHERE activity_type = $1")
                .bind(&upper)
                .fetch_one(pool)
                .await
                .map_err(db_err)?;

        (rows, total)
    } else {
        let rows = sqlx::query_as::<_, ActivityRow>(
            "SELECT id, timestamp, activity_type, title, description,
                    related_commit_id, request_id
             FROM ledger_activities
             ORDER BY timestamp DESC
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ledger_activities")
            .fetch_one(pool)
            .await
            .map_err(db_err)?;

        (rows, total)
    };

    let items = rows
        .into_iter()
        .map(|r| ActivityItem {
            id: r.id,
            timestamp: r.timestamp.format("%Y-%m-%dT%H:%M:%S").to_string(),
            activity_type: r.activity_type,
            title: r.title,
            description: r.description,
            related_commit_id: r.related_commit_id,
            related_request_id: r.request_id,
        })
        .collect();

    Ok(Json(ActivityFeedResponse { items, total }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_summary_maps_row_fields() {
        let row = DocCommitRow {
            id: "row-id".into(),
            request_id: None,
            doc_hash: "dh".into(),
            commit_id: "cid".into(),
            epoch_timestamp: chrono::DateTime::from_timestamp(0, 0)
                .expect("epoch 0 is valid")
                .naive_utc(),
            shard_id: "0x4F3A".into(),
            merkle_root: Some("mr".into()),
            zk_proof: None,
        };
        let s = commit_summary(&row);
        assert_eq!(s.commit_id, "cid");
        assert_eq!(s.doc_hash, "dh");
        assert_eq!(s.shard_id, "0x4F3A");
        assert_eq!(s.merkle_root.as_deref(), Some("mr"));
        // epoch_timestamp is rendered with the second-precision format.
        assert!(s.epoch.starts_with("1970-01-01"));
    }
}
