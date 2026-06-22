use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde_json::json;

use crate::state::AppState;

pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    if state.db_error.is_some() {
        // Do NOT echo the raw DB error string here. `/health` is mounted on
        // both the loopback router AND the Tor hidden-service router
        // (`build_tor_router`), so returning `state.db_error` would disclose
        // internal failure detail (embedded-Postgres paths, connection
        // strings, schema/version text) to any anonymous onion client —
        // recon/fingerprinting material. The body stays generic.
        //
        // The detail is NOT lost for the trusted local operator: the Tauri
        // desktop reads it via the `get_db_error` IPC command (local, no
        // network), and the browser-dev fallback in `DbErrorGate.tsx` already
        // degrades to "Database failed to start." when this field is absent.
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "error",
                "service": "olympus-desktop",
                "db": "failed",
            })),
        )
            .into_response();
    }
    if state.pool.is_none() {
        return Json(json!({
            "status": "degraded",
            "service": "olympus-desktop",
            "db": "unavailable",
        }))
        .into_response();
    }
    Json(json!({
        "status": "ok",
        "service": "olympus-desktop",
        "db": "ok",
    }))
    .into_response()
}

/// Catch-all for routes not yet implemented in the embedded Axum server.
/// Returns 501 so callers can distinguish "server is up, route not ready yet"
/// from a network error.
pub async fn not_implemented(req: Request) -> impl IntoResponse {
    let path = req.uri().path().to_owned();
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "not_implemented",
            "path": path,
        })),
    )
}
