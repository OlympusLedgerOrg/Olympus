use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde_json::json;

pub async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "olympus-desktop",
        "phase": 1
    }))
}

/// Catch-all for routes not yet implemented in the embedded Axum server.
/// Returns 501 so callers can distinguish "server is up, route not ready yet"
/// from a network error.  Phase 2+ will replace stubs with real handlers.
pub async fn not_implemented(req: Request) -> impl IntoResponse {
    let path = req.uri().path().to_owned();
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "not_implemented",
            "path": path,
            "message": "This route is a Phase 1 stub. Full implementation lands in Phase 2.",
            "phase": 1
        })),
    )
}
