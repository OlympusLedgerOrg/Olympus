use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderName, Method},
    routing::get,
    Router,
};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::api::{admin, admin_users, credentials, ingest, keys, ledger, redaction, user_auth, zk};
use crate::routes::public_stats;
use crate::state::AppState;

mod handlers;

pub async fn start(state: AppState) -> Result<SocketAddr, std::io::Error> {
    // Allow overriding the port via env var (e.g. OLYMPUS_API_PORT=8000 in dev
    // so the Vite proxy can reach the embedded server from a browser tab).
    let port: u16 = std::env::var("OLYMPUS_API_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        axum::serve(listener, build_router(state))
            .await
            .expect("axum server exited unexpectedly");
    });
    Ok(addr)
}

fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin, _| {
            let s = origin.as_bytes();
            s == b"tauri://localhost"
                || s == b"http://tauri.localhost"
                || s == b"https://tauri.localhost"
                || s.starts_with(b"http://localhost:")
                || s.starts_with(b"http://127.0.0.1:")
        }))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, HeaderName::from_static("x-api-key")])
        .max_age(std::time::Duration::from_secs(3600));

    let router = Router::new()
        .route("/health", get(handlers::health))  // returns db error details when DB failed
        // Both paths for compat: /public/stats (dev/health) and the versioned
        // /v1/public/stats (matches the Python API mount and what api.ts calls).
        .route("/public/stats", get(public_stats::get_public_stats))
        .route("/v1/public/stats", get(public_stats::get_public_stats))
        .merge(user_auth::router())
        .merge(keys::router())
        .merge(ingest::router())
        .merge(ledger::router())
        .merge(redaction::router())
        .merge(admin::router())
        .merge(admin_users::router())
        .merge(credentials::router())
        .merge(zk::router())
        .merge(crate::anchoring::api::router());
    #[cfg(feature = "federation")]
    let router = router
        .merge(crate::federation::api::tor_router())
        .merge(crate::federation::api::admin_router());
    router
        .fallback(handlers::not_implemented)
        .with_state(state)
        .layer(DefaultBodyLimit::max(128 * 1024 * 1024)) // 128 MB
        .layer(cors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;

    fn test_state() -> AppState {
        AppState::new(None)
    }

    #[tokio::test]
    async fn server_binds_and_returns_addr() {
        let addr = start(test_state()).await.expect("server should start");
        assert_eq!(addr.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn health_endpoint_returns_200() {
        let addr = start(test_state()).await.expect("server should start");
        let url = format!("http://{}/health", addr);
        let mut last_err = None;
        for attempt in 0..10u64 {
            tokio::time::sleep(std::time::Duration::from_millis(10 * (1 << attempt))).await;
            match reqwest::get(&url).await {
                Ok(resp) => {
                    assert_eq!(resp.status(), 200);
                    return;
                }
                Err(e) => last_err = Some(e),
            }
        }
        panic!("health endpoint never responded: {:?}", last_err);
    }

    #[tokio::test]
    async fn public_stats_returns_503_without_db() {
        let addr = start(test_state()).await.expect("server should start");
        let url = format!("http://{}/public/stats", addr);
        let mut last_err = None;
        for attempt in 0..10u64 {
            tokio::time::sleep(std::time::Duration::from_millis(10 * (1 << attempt))).await;
            match reqwest::get(&url).await {
                Ok(resp) => {
                    assert_eq!(resp.status(), 503);
                    return;
                }
                Err(e) => last_err = Some(e),
            }
        }
        panic!("stats endpoint never responded: {:?}", last_err);
    }

    #[tokio::test]
    async fn v1_public_stats_returns_503_without_db() {
        let addr = start(test_state()).await.expect("server should start");
        let url = format!("http://{}/v1/public/stats", addr);
        let mut last_err = None;
        for attempt in 0..10u64 {
            tokio::time::sleep(std::time::Duration::from_millis(10 * (1 << attempt))).await;
            match reqwest::get(&url).await {
                Ok(resp) => {
                    assert_eq!(resp.status(), 503);
                    return;
                }
                Err(e) => last_err = Some(e),
            }
        }
        panic!("v1 stats endpoint never responded: {:?}", last_err);
    }
}
