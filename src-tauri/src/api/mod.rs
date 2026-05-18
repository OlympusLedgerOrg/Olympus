pub mod admin;
pub mod auth;
pub mod documents;
pub mod error;
pub mod keys;
pub mod ledger;
pub mod merkle;
pub mod public_stats;
pub mod redaction;
pub mod user_auth;
pub mod state;
pub mod validation;

use axum::{middleware, routing::{delete, get, post}, Router};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use auth::auth_middleware;
use state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    // Routes that require a valid API key.
    let authed = Router::new()
        .route("/doc/commit", post(documents::commit_doc))
        .route("/redaction/commitment", post(redaction::compute_commitment))
        .route("/keys", post(keys::create_key))
        .route("/keys", get(keys::list_keys))
        .route("/keys/{key_id}", delete(keys::revoke_key))
        .route("/admin/stats", get(admin::get_admin_stats))
        .route("/admin/users", get(admin::list_users))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth_middleware,
        ));

    // Public routes (rate-limited via middleware in auth.rs called per-request).
    let public = Router::new()
        .route("/public/stats", get(public_stats::get_stats))
        .route("/doc/verify", post(documents::verify_doc))
        .route("/redaction/verify", post(redaction::verify_redaction))
        .route("/ledger/state", get(ledger::get_state))
        .route("/ledger/shard/{shard_id}", get(ledger::get_shard))
        .route("/ledger/proof/{commit_id}", get(ledger::get_proof))
        .route("/ledger/activity", get(ledger::get_activity))
        .route("/auth/register", post(user_auth::register))
        .route("/auth/login", post(user_auth::login))
        .route("/health", get(health));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(Any);

    Router::new()
        .merge(public)
        .merge(authed)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
