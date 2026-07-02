use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderName, Method, Request, StatusCode},
    middleware::{from_fn, Next},
    response::Response,
    routing::get,
    Router,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;

use crate::api::{
    admin, admin_users, checkpoint_bundle, credentials, ingest, keys, ledger, redaction, shards,
    smt_stats, user_auth, zk,
};
use crate::routes::public_stats;
use crate::state::AppState;

mod handlers;

/// Global per-request wall-clock budget for everything that isn't ZK proving.
/// Sized to comfortably cover any legitimate handler (DB queries, multipart
/// upload up to 128 MB on a slow loopback) while still cutting off
/// slow-loris-style stalls. Audit finding F-1.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Longer budget for `/zk/prove`. The unified-circuit prove takes ~55 s on
/// modest hardware; allow 5× headroom for slower laptops while still
/// guaranteeing the WasmSemaphore slot eventually frees. Audit finding F-1.
const ZK_PROVE_TIMEOUT: Duration = Duration::from_secs(300);

/// Body-size cap for the unauthenticated auth surface (login / register /
/// recovery / reissue). These bodies are small JSON objects; 64 KiB is ample
/// headroom for an email, password, name, and scope list while keeping the
/// global 128 MB ingest budget away from endpoints reachable before
/// authentication. (Audit: route-specific body budgets.)
const AUTH_BODY_LIMIT: usize = 64 * 1024;

pub async fn start(state: AppState) -> Result<SocketAddr, std::io::Error> {
    // Allow overriding the port via env var (e.g. OLYMPUS_API_PORT=8000 in dev
    // so the Vite proxy can reach the embedded server from a browser tab).
    let port: u16 = std::env::var("OLYMPUS_API_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;

    // Defense in depth: confirm we actually bound to loopback. The per-IP
    // rate limiter's correctness assumes 127.0.0.1-only (audit M-6 / F-10);
    // if a future refactor accidentally surfaces this on 0.0.0.0 the limiter
    // collapses to one bucket for all remote callers. Fail closed.
    if !addr.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!(
                "refusing to start: Axum server bound to non-loopback address {} \
                 — per-IP rate limiting assumes loopback-only (audit F-10)",
                addr
            ),
        ));
    }

    let router = build_router(state);
    tokio::spawn(async move {
        // Don't `.expect()` here: a panic in a detached task is confined to the
        // task and never reaches the caller (which already returned Ok(addr)),
        // leaving a silently-dead listener. Log loudly instead so the failure is
        // at least visible in the desktop's tracing output.
        if let Err(e) = axum::serve(listener, router).await {
            tracing::error!("axum server exited unexpectedly: {e}");
        }
    });
    Ok(addr)
}

/// Bind a second loopback listener serving only the verify/read subset of the
/// API plus the federation peer protocol, and return its address. The Tor
/// hidden service proxies inbound onion streams to *this* port instead of the
/// full router's port, so `/admin/*`, `/auth/*`, `/key/*`, `/zk/prove`, and
/// every write endpoint stay off the Tor surface entirely. The full router
/// remains bound to its own loopback port for the local desktop UI.
#[cfg(feature = "federation")]
pub async fn start_tor_listener(state: AppState) -> Result<SocketAddr, std::io::Error> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    if !addr.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("refusing to start: Tor-facing listener bound to non-loopback address {addr}"),
        ));
    }
    let router = build_tor_router(state);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            tracing::error!("tor-facing axum server exited unexpectedly: {e}");
        }
    });
    Ok(addr)
}

/// CORS-allowed origins. Tauri webview origins are fixed. Local Vite dev
/// origins are allowed only under explicit development mode. Any other browser
/// origin must be explicitly listed in `CORS_ORIGINS` (comma-separated, exact
/// origins; `*` is ignored).
fn configured_cors_origins() -> Vec<Vec<u8>> {
    let raw = match std::env::var("CORS_ORIGINS") {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return Vec::new(),
        Err(std::env::VarError::NotUnicode(_)) => {
            tracing::warn!("CORS_ORIGINS is not valid Unicode; ignoring extra browser origins");
            return Vec::new();
        }
    };

    raw.split(',')
        .filter_map(|origin| {
            let origin = origin.trim();
            if origin.is_empty() {
                return None;
            }
            if origin == "*" {
                tracing::warn!("ignoring wildcard CORS_ORIGINS entry");
                return None;
            }
            Some(origin.as_bytes().to_vec())
        })
        .collect()
}

fn is_tauri_origin(origin: &[u8]) -> bool {
    origin == b"tauri://localhost"
        || origin == b"http://tauri.localhost"
        || origin == b"https://tauri.localhost"
}

fn is_vite_dev_origin(origin: &[u8]) -> bool {
    origin == b"http://127.0.0.1:5173" || origin == b"http://localhost:5173"
}

/// Defense-in-depth against DNS rebinding: even with CORS in place, reject any
/// request whose `Host` header is not loopback. CORS keeps browsers honest
/// about their own Origin, but a remote attacker controlling a DNS name that
/// resolves to 127.0.0.1 in the target's resolver can still aim cross-context
/// requests at the embedded server. The Host header carries the name the
/// caller resolved, so refusing anything outside `127.0.0.1` / `[::1]` /
/// `localhost` closes that vector regardless of Origin handling. Audit M-API-1.
async fn validate_loopback_host(req: Request<axum::body::Body>, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Strip optional `:port` suffix; compare against the loopback hostnames
    // we actually bind. IPv6 literals arrive as `[::1]:port`.
    let host_only = if let Some(stripped) = host.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    };
    let ok = matches!(host_only, "127.0.0.1" | "::1" | "localhost");
    if !ok {
        tracing::warn!("rejected non-loopback Host header: {host:?}");
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(axum::body::Body::empty())
            .expect("static response");
    }
    next.run(req).await
}

fn cors_layer() -> CorsLayer {
    let extra_origins = configured_cors_origins();
    let allow_vite_dev_origins = crate::env::is_development();
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _| {
            let s = origin.as_bytes();
            if is_tauri_origin(s) {
                return true;
            }
            if allow_vite_dev_origins && is_vite_dev_origin(s) {
                return true;
            }
            extra_origins.iter().any(|allowed| allowed.as_slice() == s)
        }))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            HeaderName::from_static("x-api-key"),
        ])
        .max_age(Duration::from_secs(3600))
}

fn build_router(state: AppState) -> Router {
    // Build /zk/prove on its own sub-router with the longer timeout BEFORE
    // merging into the global stack. Axum layers apply outside-in, so if we
    // put the long timeout on a route and the short timeout on the parent
    // router, the short timeout wraps everything and wins. Splitting routers
    // lets each subset have its own effective request timeout.
    // (Audit F-1.)
    let prove_router = zk::router().layer(TimeoutLayer::with_status_code(
        axum::http::StatusCode::GATEWAY_TIMEOUT,
        ZK_PROVE_TIMEOUT,
    ));

    let fast_router = Router::new()
        .route("/health", get(handlers::health)) // generic status only; raw db error is never echoed (handler is shared with the Tor router)
        // Both paths for compat: /public/stats (dev/health) and the versioned
        // /v1/public/stats (matches the Python API mount and what api.ts calls).
        .route("/public/stats", get(public_stats::get_public_stats))
        .route("/v1/public/stats", get(public_stats::get_public_stats))
        // Auth routes carry only small JSON bodies (email/password/scopes).
        // Cap them well below the global 128 MB ingest budget so the
        // unauthenticated login/register/recovery surface cannot be used as a
        // heap-exhaustion vector. Applied to the auth sub-router so the limit
        // sits closer to the handler and overrides the outer default for these
        // routes only. (Audit: route-specific body budgets.)
        .merge(user_auth::router().layer(DefaultBodyLimit::max(AUTH_BODY_LIMIT)))
        .merge(keys::router())
        .merge(ingest::router())
        .merge(ledger::router())
        .merge(redaction::router())
        .merge(admin::router())
        .merge(admin_users::router())
        .merge(checkpoint_bundle::router())
        .merge(shards::router())
        .merge(smt_stats::router())
        .merge(credentials::router())
        .merge(crate::anchoring::api::router())
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ));
    #[cfg(feature = "federation")]
    let fast_router = fast_router
        .merge(
            crate::federation::api::tor_router().layer(TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                REQUEST_TIMEOUT,
            )),
        )
        .merge(
            crate::federation::api::admin_router().layer(TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                REQUEST_TIMEOUT,
            )),
        );

    Router::new()
        .merge(fast_router)
        .merge(prove_router)
        .fallback(handlers::not_implemented)
        .with_state(state)
        .layer(DefaultBodyLimit::max(128 * 1024 * 1024)) // 128 MB
        .layer(cors_layer())
        .layer(from_fn(validate_loopback_host))
}

/// Router served on the Tor-facing loopback listener. Carries only the
/// read/verify subset of each API module plus the federation peer protocol
/// (`tor_router`: identity / checkpoint / cosign). Deliberately omits the
/// federation `admin_router`, `/zk/prove`, and all admin/auth/key/write
/// routes so reaching the onion service can never reach a mutating or
/// authority-bound endpoint. Keeps the same loopback-host + body-limit + CORS
/// layers as the full router; inbound onion streams arrive from 127.0.0.1 with
/// a loopback `Host` header, so `validate_loopback_host` still passes.
#[cfg(feature = "federation")]
fn build_tor_router(state: AppState) -> Router {
    let public = Router::new()
        .route("/health", get(handlers::health))
        .route("/public/stats", get(public_stats::get_public_stats))
        .route("/v1/public/stats", get(public_stats::get_public_stats))
        .merge(zk::public_router())
        .merge(ledger::public_router())
        .merge(credentials::public_router())
        .merge(ingest::public_router())
        .merge(crate::federation::api::tor_router())
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ));

    Router::new()
        .merge(public)
        .fallback(handlers::not_implemented)
        .with_state(state)
        .layer(DefaultBodyLimit::max(128 * 1024 * 1024)) // 128 MB
        .layer(cors_layer())
        .layer(from_fn(validate_loopback_host))
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
    async fn health_does_not_leak_db_error_detail() {
        // The handler is shared with the Tor hidden-service router, so a
        // failed-DB /health response must NOT echo the raw error string
        // (recon material for anonymous onion clients). It returns a generic
        // `db: "failed"` status; the detail stays on the local `get_db_error`
        // IPC path.
        let secret = "embedded-postgres-secret-path-/tmp/xyzzy-should-not-leak";
        let state = AppState::new_with_error(None, Some(secret.to_string()));
        let addr = start(state).await.expect("server should start");
        let url = format!("http://{}/health", addr);
        let mut last_err = None;
        for attempt in 0..10u64 {
            tokio::time::sleep(std::time::Duration::from_millis(10 * (1 << attempt))).await;
            match reqwest::get(&url).await {
                Ok(resp) => {
                    assert_eq!(resp.status(), 503);
                    let body = resp.text().await.expect("body");
                    assert!(
                        body.contains("\"db\":\"failed\""),
                        "must report db failed: {body}"
                    );
                    // Parse JSON and assert "error" key is absent.
                    let json: serde_json::Value =
                        serde_json::from_str(&body).expect("response must be valid JSON");
                    assert!(
                        !json.as_object().unwrap().contains_key("error"),
                        "response must not contain an 'error' key: {body}"
                    );
                    // Defense-in-depth: also check the raw secret substring is not present.
                    assert!(
                        !body.contains(secret),
                        "must not leak raw db error detail: {body}"
                    );
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
    async fn rejects_spoofed_host_header() {
        // Audit M-API-1: requests with a non-loopback Host must be rejected
        // with 403, even though the TCP connection itself is on loopback.
        let addr = start(test_state()).await.expect("server should start");
        let url = format!("http://{}/health", addr);
        let client = reqwest::Client::new();
        // Retry briefly while the server warms up.
        let mut last = None;
        for attempt in 0..10u64 {
            tokio::time::sleep(std::time::Duration::from_millis(10 * (1 << attempt))).await;
            match client
                .get(&url)
                .header("Host", "evil.example.com")
                .send()
                .await
            {
                Ok(resp) => {
                    assert_eq!(resp.status(), 403, "spoofed Host must be rejected");
                    return;
                }
                Err(e) => last = Some(e),
            }
        }
        panic!("server never responded: {:?}", last);
    }

    #[tokio::test]
    async fn accepts_loopback_host_header() {
        let addr = start(test_state()).await.expect("server should start");
        let url = format!("http://{}/health", addr);
        let client = reqwest::Client::new();
        let mut last = None;
        for attempt in 0..10u64 {
            tokio::time::sleep(std::time::Duration::from_millis(10 * (1 << attempt))).await;
            // Default reqwest sends `127.0.0.1:PORT` as Host — must pass.
            match client.get(&url).send().await {
                Ok(resp) => {
                    assert_eq!(resp.status(), 200);
                    return;
                }
                Err(e) => last = Some(e),
            }
        }
        panic!("server never responded: {:?}", last);
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
