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
use super::peer::{self, AddPeerError, AddPeerRequest, UpdateTrustRequest};

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

/// Audit H-10: every admin handler must gate on `AuthenticatedKey` +
/// `admin` scope. Defense in depth against the Tor proxy reaching the
/// admin surface (the separate-listener fix is a follow-up; this auth
/// gate is the primary protection — Tor traffic never carries an API
/// key, so every admin route 401s regardless of routing).
fn require_admin(auth: &AuthenticatedKey) -> Result<(), ApiError> {
    if auth.has_scope("admin") {
        Ok(())
    } else {
        Err(err(StatusCode::FORBIDDEN, "admin scope required"))
    }
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
///
/// Audit H-11 / M-5 / H-12: every gate now lives in
/// [`super::verify::verify_and_store`] so push (this handler) and pull
/// (`gossip::process_received_checkpoint`) share the same sig-then-
/// proof-then-equivocation pipeline. Anything that fails before the
/// store step returns a 403 with the specific reason; nothing is
/// persisted and no equivocation flag fires on unverified data.
async fn receive_checkpoint(
    State(state): State<AppState>,
    Json(cp): Json<PeerCheckpoint>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pool = db_or_503(&state)?;
    let config = state
        .federation_config
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Federation not enabled"))?;

    // Match the peer by their authority pubkey hash. We MUST resolve the
    // full PeerNode (not just the id) because the verify pipeline needs
    // the pinned `bjj_pubkey_{x,y}` to check the signature on `cp`.
    let peer: Option<super::peer::PeerNode> = sqlx::query_as(
        "SELECT * FROM peer_nodes
         WHERE trust_status = 'trusted'
           AND bjj_pubkey_x IS NOT NULL
         ORDER BY last_seen_at DESC NULLS LAST",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?
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

    let outcome = super::verify::verify_and_store(pool, config, &peer, &cp)
        .await
        .map_err(|e| err(StatusCode::FORBIDDEN, &format!("checkpoint rejected: {e}")))?;

    Ok(Json(serde_json::json!({
        "stored": true,
        "checkpoint_id": outcome.checkpoint_id,
        "signature_verified": outcome.signature_verified,
        "proof_verified": outcome.proof_verified,
        "equivocation_detected": outcome.equivocation_detected,
        "auto_blocked": outcome.auto_blocked,
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
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))
}

async fn add_peer_handler(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    Json(req): Json<AddPeerRequest>,
) -> Result<(StatusCode, Json<peer::PeerNode>), ApiError> {
    require_admin(&auth)?;
    let pool = db_or_503(&state)?;
    match peer::add_peer(pool, &req).await {
        Ok(p) => Ok((StatusCode::CREATED, Json(p))),
        // Audit M-8: a malformed / off-curve pubkey is a client bug, not
        // a server bug — surface it as 400 with the specific reason
        // instead of collapsing into a generic 500.
        Err(AddPeerError::InvalidPubkey(reason)) => Err(err(
            StatusCode::BAD_REQUEST,
            &format!("invalid BJJ pubkey: {reason}"),
        )),
        Err(AddPeerError::Db(e)) => {
            Err(err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))
        }
    }
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
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
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
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))
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

/// POST /federation/identity/rotate — wipe the persisted hidden-service
/// identity material so the next process start mints a new `.onion`
/// address (audit M-F2).
///
/// This is a foot-gun: every peer that pinned the old onion address
/// becomes unreachable until the operator re-publishes the new one and
/// peers re-add this node. Gated on `admin` scope and only enabled when
/// federation has been bootstrapped at least once (so
/// `federation_state_dir` is populated). See `docs/federation.md`.
async fn rotate_identity(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&auth)?;
    let state_dir = state.federation_state_dir.as_ref().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Federation has never been bootstrapped on this node; \
             nothing to rotate. Start the hidden service first.",
        )
    })?;
    let removed = super::tor::wipe_hidden_service_keys(state_dir).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to wipe hidden-service keys: {e}"),
        )
    })?;
    tracing::warn!(
        "federation: hidden-service identity wiped ({} entr{} removed); \
         restart the process to mint a new .onion address",
        removed,
        if removed == 1 { "y" } else { "ies" },
    );
    Ok(Json(serde_json::json!({
        "wiped_entries": removed,
        "next_step": "Restart the Olympus desktop process to bring up a fresh hidden service. \
                      The new .onion address will be logged at startup. Existing peers must be \
                      re-added with the new address — see docs/federation.md.",
    })))
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
        .route("/federation/identity/rotate", post(rotate_identity))
}
