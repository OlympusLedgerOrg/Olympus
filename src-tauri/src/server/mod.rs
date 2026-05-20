use axum::{
    http::{header, Method},
    routing::get,
    Router,
};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::api::{admin, ingest, keys, ledger, redaction, user_auth};
use crate::routes::public_stats;
use crate::state::AppState;

mod handlers;

pub async fn start(state: AppState) -> Result<SocketAddr, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
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
                || s.starts_with(b"http://localhost:")
                || s.starts_with(b"http://127.0.0.1:")
        }))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

    Router::new()
        .route("/health", get(handlers::health))
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
        .fallback(handlers::not_implemented)
        .with_state(state)
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
