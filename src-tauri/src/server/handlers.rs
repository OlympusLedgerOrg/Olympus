use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde_json::json;

use crate::state::AppState;

pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(ref err) = state.db_error {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "error",
                "service": "olympus-desktop",
                "db": "failed",
                "error": err,
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
