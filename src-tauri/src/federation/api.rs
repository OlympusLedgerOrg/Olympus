//! HTTP routes for P2P federation.
//!
//! Two sets of routes:
//! - **Public (Tor-exposed)**: identity, checkpoint push/pull — served on the hidden service.
//! - **Admin (local-only)**: peer management, checkpoint listing, status.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::AppState;
use super::checkpoint::{self, PeerCheckpoint};
use super::equivocation;
use super::peer::{self, AddPeerRequest, UpdateTrustRequest};

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": detail })))
}

fn db_or_503(state: &AppState) -> Result<&sqlx::PgPool, ApiError> {
    state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable"))
}

// ── Tor-exposed routes (hidden service) ─────────────────────────────────────

/// GET /federation/identity — this node's BJJ pubkey + onion address.
async fn get_identity(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let config = state
        .federation_config
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Federation not enabled"))?;

    let pubkey = state
        .bjj_authority_pubkey
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "BJJ key not configured"))?;

    let x = checkpoint::fr_to_decimal(&pubkey.x);
    let y = checkpoint::fr_to_decimal(&pubkey.y);

    Ok(Json(serde_json::json!({
        "onion_address": config.onion_address,
        "bjj_pubkey_x": x,
        "bjj_pubkey_y": y,
    })))
}

/// POST /federation/checkpoint — receive a checkpoint from a peer (push model).
async fn receive_checkpoint(
    State(state): State<AppState>,
    Json(cp): Json<PeerCheckpoint>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pool = db_or_503(&state)?;

    // Look up the peer by their authority pubkey hash.
    // For now, store as "unknown peer" — a future version would match by BJJ pubkey.
    let peer: Option<super::peer::PeerNode> = sqlx::query_as(
        "SELECT * FROM peer_nodes WHERE trust_status = 'trusted' LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;

    let peer_id = match peer {
        Some(p) => p.id,
        None => {
            return Err(err(StatusCode::FORBIDDEN, "No trusted peer matches this checkpoint"));
        }
    };

    // Check equivocation.
    let equivocated =
        equivocation::check_and_flag(pool, peer_id, cp.checkpoint_timestamp, &cp.ledger_root)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("equivocation: {e}")))?;

    if equivocated {
        if let Some(ref config) = state.federation_config {
            if config.auto_block_equivocators {
                let _ = equivocation::auto_block_peer(pool, peer_id).await;
            }
        }
    }

    let cp_id = checkpoint::store_peer_checkpoint(pool, peer_id, &cp, false)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("store: {e}")))?;

    Ok(Json(serde_json::json!({
        "stored": true,
        "checkpoint_id": cp_id,
        "equivocation_detected": equivocated,
    })))
}

/// GET /federation/checkpoint/latest — this node's latest checkpoint.
async fn get_latest_checkpoint(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pool = db_or_503(&state)?;

    let bjj_key = state
        .bjj_authority_key
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "BJJ key not configured"))?;
    let bjj_pubkey = state
        .bjj_authority_pubkey
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "BJJ pubkey not available"))?;

    match checkpoint::build_own_checkpoint(pool, bjj_key, bjj_pubkey).await {
        Ok(Some(cp)) => Ok(Json(serde_json::to_value(&cp).unwrap())),
        Ok(None) => Err(err(StatusCode::NOT_FOUND, "No checkpoint data yet")),
        Err(e) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, &e)),
    }
}

// ── Admin routes (local API only) ───────────────────────────────────────────

async fn list_peers(State(state): State<AppState>) -> Result<Json<Vec<peer::PeerNode>>, ApiError> {
    let pool = db_or_503(&state)?;
    peer::list_peers(pool)
        .await
        .map(Json)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))
}

async fn add_peer_handler(
    State(state): State<AppState>,
    Json(req): Json<AddPeerRequest>,
) -> Result<(StatusCode, Json<peer::PeerNode>), ApiError> {
    let pool = db_or_503(&state)?;
    peer::add_peer(pool, &req)
        .await
        .map(|p| (StatusCode::CREATED, Json(p)))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))
}

async fn remove_peer_handler(
    State(state): State<AppState>,
    Path(peer_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pool = db_or_503(&state)?;
    let deleted = peer::remove_peer(pool, peer_id)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    if deleted {
        Ok(Json(serde_json::json!({ "deleted": true })))
    } else {
        Err(err(StatusCode::NOT_FOUND, "Peer not found"))
    }
}

async fn update_trust_handler(
    State(state): State<AppState>,
    Path(peer_id): Path<Uuid>,
    Json(req): Json<UpdateTrustRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !["pending", "trusted", "blocked"].contains(&req.trust_status.as_str()) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "trust_status must be pending, trusted, or blocked",
        ));
    }
    let pool = db_or_503(&state)?;
    let updated = peer::update_trust(pool, peer_id, &req.trust_status)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    if updated {
        Ok(Json(serde_json::json!({ "updated": true })))
    } else {
        Err(err(StatusCode::NOT_FOUND, "Peer not found"))
    }
}

#[derive(Deserialize)]
struct CheckpointListQuery {
    peer_id: Option<Uuid>,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    50
}

async fn list_checkpoints(
    State(state): State<AppState>,
    Query(q): Query<CheckpointListQuery>,
) -> Result<Json<Vec<checkpoint::StoredCheckpoint>>, ApiError> {
    let pool = db_or_503(&state)?;
    checkpoint::list_peer_checkpoints(pool, q.peer_id, q.limit)
        .await
        .map(Json)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))
}

/// GET /federation/status — federation health summary.
async fn federation_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pool = db_or_503(&state)?;

    let config = state.federation_config.as_ref();
    let enabled = config.map(|c| c.enabled).unwrap_or(false);
    let onion = config.and_then(|c| c.onion_address.clone());

    let peer_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM peer_nodes WHERE trust_status = 'trusted'")
            .fetch_one(pool)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;

    let checkpoint_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM peer_checkpoints")
            .fetch_one(pool)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;

    let equiv_count = equivocation::equivocation_count(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;

    Ok(Json(serde_json::json!({
        "enabled": enabled,
        "onion_address": onion,
        "trusted_peers": peer_count.0,
        "total_checkpoints": checkpoint_count.0,
        "equivocation_events": equiv_count,
    })))
}

// ── Routers ─────────────────────────────────────────────────────────────────

/// Routes exposed on the Tor hidden service (peer-facing).
pub fn tor_router() -> Router<AppState> {
    Router::new()
        .route("/federation/identity", get(get_identity))
        .route("/federation/checkpoint", post(receive_checkpoint))
        .route("/federation/checkpoint/latest", get(get_latest_checkpoint))
}

/// Routes exposed on the local admin API only.
pub fn admin_router() -> Router<AppState> {
    Router::new()
        .route("/federation/peers", get(list_peers))
        .route("/federation/peers", post(add_peer_handler))
        .route("/federation/peers/{peer_id}", delete(remove_peer_handler))
        .route(
            "/federation/peers/{peer_id}/trust",
            put(update_trust_handler),
        )
        .route("/federation/checkpoints", get(list_checkpoints))
        .route("/federation/status", get(federation_status))
}
