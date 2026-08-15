use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde_json::json;

use crate::state::AppState;

const RELEASE_STAGE: &str = "pre-v1";
const DATA_DURABILITY: &str = "development-disposable";
const RELEASE_NOTICE: &str = "Pre-v1 development databases are disposable; durable reliance begins with v1 production ceremony artifacts, documented migrations, and verifier-compatible proof bundles.";

/// Build-time release metadata.
///
/// `channel` and `preview_tag` come from the `build.rs` stamp
/// (docs/plans/preview-release-channel.md §D2) and are the authoritative
/// answer to "what am I running": the frontend header chip reads them from
/// here rather than from a Vite define, so there is exactly one source and it
/// is the one bound to the binary that carries the ceremony artifacts.
///
/// Safe on the Tor-facing router. The handler below is careful never to echo
/// the raw DB error, but that restriction is about internal failure detail;
/// this block is public build metadata of exactly the same kind as the
/// `stage`/`notice` fields already served here.
fn release_metadata() -> serde_json::Value {
    let preview_tag = crate::env::PREVIEW_TAG;
    json!({
        "stage": RELEASE_STAGE,
        "production_trust_ready": false,
        "data_durability": DATA_DURABILITY,
        "notice": RELEASE_NOTICE,
        "channel": crate::env::release_channel().as_str(),
        "preview_tag": if preview_tag.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(preview_tag.to_owned())
        },
    })
}

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
                "release": release_metadata(),
            })),
        )
            .into_response();
    }
    if state.pool.is_none() {
        return Json(json!({
            "status": "degraded",
            "service": "olympus-desktop",
            "db": "unavailable",
            "release": release_metadata(),
        }))
        .into_response();
    }
    Json(json!({
        "status": "ok",
        "service": "olympus-desktop",
        "db": "ok",
        "release": release_metadata(),
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
