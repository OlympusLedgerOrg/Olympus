//! `GET /admin/smt/stats` — operational visibility into the persistent Sparse
//! Merkle Tree's on-disk state.
//!
//! Complements the per-operation `tracing` telemetry (see `smt/tree.rs`) with a
//! point-in-time snapshot operators can scrape: row counts, the deep-node
//! population, depth ceiling, on-disk sizes, and the current global root.
//!
//! Admin-gated through the shared [`require_admin_auth`] gate (the `x-admin-key`
//! header or an `admin`-role + `admin`-scope API key) — the same gate `/admin/*`
//! uses. SMT internals are operational detail, so this is not a public endpoint.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::api::middleware::auth::require_admin_auth;
use crate::state::AppState;

/// Mirror of `smt::tree::LAZY_DEPTH` (ADR-0022). Nodes deeper than this are
/// recomputed on read and only persisted for over-cap canopies, so a non-zero
/// `deep_nodes` count is the operational signal that some canopy crossed
/// `CANOPY_RECOMPUTE_CAP` (non-uniform / colliding record keys). Pinned const,
/// mirrored here exactly as migration `0044` mirrors it (a change is a
/// migration-class event).
const LAZY_DEPTH: i16 = 72;

type ApiError = (StatusCode, Json<Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(json!({ "detail": detail })))
}

#[derive(Serialize)]
pub struct SmtStats {
    /// Rows in `smt_nodes` (the persisted internal-node set; near-constant in N
    /// under lazy deep-node storage).
    pub node_count: i64,
    /// Rows in `smt_leaves`.
    pub leaf_count: i64,
    /// Persisted nodes with `depth > LAZY_DEPTH` — non-zero only for over-cap
    /// canopies (operational anomaly signal; see ADR-0022).
    pub deep_nodes: i64,
    /// Deepest persisted node depth (0 when the tree is empty).
    pub max_depth: i32,
    /// `pg_total_relation_size('smt_nodes')` — bytes incl. indexes/TOAST.
    pub nodes_bytes: i64,
    /// `pg_total_relation_size('smt_leaves')`.
    pub leaves_bytes: i64,
    /// `nodes_bytes + leaves_bytes`.
    pub total_bytes: i64,
    /// Hex of the global root (the depth-0 node). `None` when the tree is empty.
    pub root_hex: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/admin/smt/stats", get(get_smt_stats))
}

async fn get_smt_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SmtStats>, ApiError> {
    // Pool check first (matches /admin/shards), so a down DB returns 503 before
    // we touch auth.
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;
    require_admin_auth(&headers, pool, &state.bjj_trusted_issuers).await?;

    let db_err = |e: sqlx::Error| {
        tracing::error!("smt_stats: database error: {e}");
        err(StatusCode::INTERNAL_SERVER_ERROR, "Query failed.")
    };

    let node_count: i64 = sqlx::query_scalar("SELECT count(*) FROM smt_nodes")
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    let leaf_count: i64 = sqlx::query_scalar("SELECT count(*) FROM smt_leaves")
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    let deep_nodes: i64 = sqlx::query_scalar("SELECT count(*) FROM smt_nodes WHERE depth > $1")
        .bind(LAZY_DEPTH)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    // `max(depth)` is SMALLINT; COALESCE to 0 for an empty tree, widen to i32.
    let max_depth: i32 =
        sqlx::query_scalar::<_, i16>("SELECT COALESCE(MAX(depth), 0) FROM smt_nodes")
            .fetch_one(pool)
            .await
            .map_err(db_err)? as i32;
    let nodes_bytes: i64 = sqlx::query_scalar("SELECT pg_total_relation_size('smt_nodes')")
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    let leaves_bytes: i64 = sqlx::query_scalar("SELECT pg_total_relation_size('smt_leaves')")
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    // Global root = the depth-0 node (empty `path_bits`). Absent on an empty tree.
    let root_hex: Option<String> =
        sqlx::query_scalar("SELECT encode(hash, 'hex') FROM smt_nodes WHERE depth = 0 LIMIT 1")
            .fetch_optional(pool)
            .await
            .map_err(db_err)?;

    Ok(Json(SmtStats {
        node_count,
        leaf_count,
        deep_nodes,
        max_depth,
        nodes_bytes,
        leaves_bytes,
        total_bytes: nodes_bytes + leaves_bytes,
        root_hex,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Error path: with no DB the handler returns 503 before any auth work
    /// (the pool check precedes `require_admin_auth`).
    #[tokio::test]
    async fn smt_stats_returns_503_without_db() {
        let result = get_smt_stats(State(AppState::new(None)), HeaderMap::new()).await;
        match result {
            Err((status, _)) => assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE),
            Ok(_) => panic!("expected 503 without a database"),
        }
    }
}
