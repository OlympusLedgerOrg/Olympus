//! HTTP routes for inspecting anchor receipts.
//!
//! All routes require an authenticated key with at least the `read` or
//! `admin` scope; submitting new anchors happens automatically on
//! checkpoint build (and via the federation's `/federation/checkpoint`
//! flow), not as an explicit user action.

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::Response,
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;

use super::store;

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(json!({ "error": detail })))
}

fn db_err(e: impl std::fmt::Display) -> ApiError {
    tracing::error!("anchoring API DB error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
}

fn require_read(auth: &AuthenticatedKey) -> Result<(), ApiError> {
    if auth.has_scope("read") || auth.has_scope("verify") || auth.has_scope("admin") {
        Ok(())
    } else {
        Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: 'read', 'verify', or 'admin'",
        ))
    }
}

fn db(state: &AppState) -> Result<&sqlx::PgPool, ApiError> {
    state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable"))
}

#[derive(Deserialize)]
struct ListQuery {
    checkpoint_id: Option<Uuid>,
    #[serde(default = "default_limit")]
    limit: i64,
}
fn default_limit() -> i64 {
    100
}

/// GET /anchors — list anchor receipts (newest first).
async fn list_anchors(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Query(q): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_read(&auth)?;
    let pool = db(&state)?;
    let rows = store::list(pool, q.checkpoint_id, q.limit)
        .await
        .map_err(db_err)?;

    // Render anchored_hash as hex for human inspection; clients that
    // need the raw bytes can pull /anchors/{id}/receipt.
    let view: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id":              r.id,
                "anchor_kind":     r.anchor_kind,
                "anchored_hash":   hex::encode(&r.anchored_hash),
                "checkpoint_id":   r.checkpoint_id,
                "target":          r.target,
                "submitted_at":    r.submitted_at,
                "verified_at":     r.verified_at,
                "metadata":        r.metadata,
                "receipt_bytes":   r.blob_size,
            })
        })
        .collect();

    Ok(Json(json!({ "anchors": view })))
}

/// GET /anchors/{id}/receipt — raw receipt bytes for offline verification.
///
/// Content-Type is set per anchor kind so e.g. `curl --output - | openssl
/// ts -reply -in /dev/stdin -text` works without further conversion.
async fn get_receipt(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    require_read(&auth)?;
    let pool = db(&state)?;

    let row = store::fetch_blob(pool, id)
        .await
        .map_err(db_err)?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "anchor not found"))?;
    let (kind, blob) = row;

    let content_type = match kind.as_str() {
        "rfc3161" => "application/timestamp-reply",
        "rekor" => "application/json",
        "ots" => "application/vnd.opentimestamps",
        _ => "application/octet-stream",
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{kind}-{id}.bin\""),
        )
        .body(Body::from(blob))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("body: {e}")))
}

/// GET /anchors/{id} — JSON metadata + base64 receipt (convenience).
async fn get_anchor_json(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_read(&auth)?;
    let pool = db(&state)?;

    let row = store::fetch_blob(pool, id)
        .await
        .map_err(db_err)?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "anchor not found"))?;
    let (kind, blob) = row;

    Ok(Json(json!({
        "id":           id,
        "anchor_kind":  kind,
        "receipt_b64":  B64.encode(&blob),
        "receipt_size": blob.len(),
    })))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/anchors", get(list_anchors))
        .route("/anchors/{id}", get(get_anchor_json))
        .route("/anchors/{id}/receipt", get(get_receipt))
}
