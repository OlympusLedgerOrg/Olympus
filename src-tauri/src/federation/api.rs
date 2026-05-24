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

use crate::api::middleware::auth::AuthenticatedKey;
use crate::state::AppState;
use super::checkpoint::{self, PeerCheckpoint};
use super::equivocation;
use super::peer::{self, AddPeerRequest, UpdateTrustRequest};

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": detail })))
}

/// Log a DB error internally and return a generic message (audit TOB-OLY-07).
fn db_err(e: impl std::fmt::Display) -> ApiError {
    tracing::error!("federation DB error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
}

/// Gate for the local-admin federation routes.
///
/// Audit (TOB-OLY-02): these routes (add/remove peer, set trust) carried no
/// authentication and are merged onto the same listener the Tor hidden-service
/// proxy forwards to, so they would be reachable over the `.onion` if the
/// service were wired up. Require an `admin`-scoped API key.
fn require_admin(auth: &AuthenticatedKey) -> Result<(), ApiError> {
    if auth.has_scope("admin") {
        Ok(())
    } else {
        Err(err(StatusCode::FORBIDDEN, "admin scope required"))
    }
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

    // Match the peer by their authority pubkey hash against known BJJ pubkeys.
    let peer: Option<super::peer::PeerNode> = sqlx::query_as(
        "SELECT * FROM peer_nodes
         WHERE trust_status = 'trusted'
           AND bjj_pubkey_x IS NOT NULL
         ORDER BY last_seen_at DESC NULLS LAST",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| db_err(e))?
    .into_iter()
    .find(|p: &super::peer::PeerNode| {
        checkpoint::peer_matches_authority_hash(p, &cp.authority_pubkey_hash)
    });

    let peer = match peer {
        Some(p) => p,
        None => {
            return Err(err(StatusCode::FORBIDDEN, "No trusted peer matches this checkpoint"));
        }
    };

    // Verify the peer's BJJ signature over the checkpoint before trusting it
    // (audit TOB-OLY-01) — matching the authority hash alone proves nothing
    // since that hash is public.
    if !checkpoint::verify_checkpoint_signature(&peer, &cp) {
        return Err(err(StatusCode::UNAUTHORIZED, "checkpoint signature verification failed"));
    }
    let peer_id = peer.id;

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
        Ok(Some(cp)) => serde_json::to_value(&cp)
            .map(Json)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("serialize: {e}"))),
        Ok(None) => Err(err(StatusCode::NOT_FOUND, "No checkpoint data yet")),
        Err(e) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, &e)),
    }
}

// ── Admin routes (local API only) ───────────────────────────────────────────

async fn list_peers(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
) -> Result<Json<Vec<peer::PeerNode>>, ApiError> {
    require_admin(&auth)?;
    let pool = db_or_503(&state)?;
    peer::list_peers(pool)
        .await
        .map(Json)
        .map_err(|e| db_err(e))
}

async fn add_peer_handler(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    Json(req): Json<AddPeerRequest>,
) -> Result<(StatusCode, Json<peer::PeerNode>), ApiError> {
    require_admin(&auth)?;
    let pool = db_or_503(&state)?;
    peer::add_peer(pool, &req)
        .await
        .map(|p| (StatusCode::CREATED, Json(p)))
        .map_err(|e| db_err(e))
}

async fn remove_peer_handler(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    Path(peer_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&auth)?;
    let pool = db_or_503(&state)?;
    let deleted = peer::remove_peer(pool, peer_id)
        .await
        .map_err(|e| db_err(e))?;
    if deleted {
        Ok(Json(serde_json::json!({ "deleted": true })))
    } else {
        Err(err(StatusCode::NOT_FOUND, "Peer not found"))
    }
}

async fn update_trust_handler(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    Path(peer_id): Path<Uuid>,
    Json(req): Json<UpdateTrustRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&auth)?;
    let pool = db_or_503(&state)?;
    let updated = peer::update_trust(pool, peer_id, &req.trust_status)
        .await
        .map_err(|e| err(StatusCode::BAD_REQUEST, &e))?;
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
    auth: AuthenticatedKey,
    Query(q): Query<CheckpointListQuery>,
) -> Result<Json<Vec<checkpoint::StoredCheckpoint>>, ApiError> {
    require_admin(&auth)?;
    let pool = db_or_503(&state)?;
    let limit = q.limit.clamp(1, 1000);
    checkpoint::list_peer_checkpoints(pool, q.peer_id, limit)
        .await
        .map(Json)
        .map_err(|e| db_err(e))
}

/// GET /federation/status — federation health summary.
async fn federation_status(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&auth)?;
    let pool = db_or_503(&state)?;

    let config = state.federation_config.as_ref();
    let enabled = config.map(|c| c.enabled).unwrap_or(false);
    let onion = config.and_then(|c| c.onion_address.clone());

    let peer_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM peer_nodes WHERE trust_status = 'trusted'")
            .fetch_one(pool)
            .await
            .map_err(|e| db_err(e))?;

    let checkpoint_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM peer_checkpoints")
            .fetch_one(pool)
            .await
            .map_err(|e| db_err(e))?;

    let equiv_count = equivocation::equivocation_count(pool)
        .await
        .map_err(|e| db_err(e))?;

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
