//! CORS-preflight coverage for `src-tauri/src/server/mod.rs::cors_layer`.
//!
//! Replaces the deleted `tests/test_cors_preflight.py`. Lives in its
//! own binary so it doesn't pay the `pg_embed` startup cost — the CORS
//! layer doesn't touch the database.

use std::net::SocketAddr;
use std::time::Duration;

use olympus_tauri_lib::server;
use olympus_tauri_lib::state::AppState;

async fn boot(cors_origins: Option<&str>) -> SocketAddr {
    let old_cors = std::env::var("CORS_ORIGINS").ok();

    match cors_origins {
        Some(v) => std::env::set_var("CORS_ORIGINS", v),
        None => std::env::remove_var("CORS_ORIGINS"),
    }

    let result = server::start(AppState::new(None)).await;

    match old_cors {
        Some(v) => std::env::set_var("CORS_ORIGINS", v),
        None => std::env::remove_var("CORS_ORIGINS"),
    }

    result.expect("server should start")
}

async fn preflight(addr: SocketAddr, origin: &str) -> reqwest::Response {
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/health");
    let mut last = None;
    for attempt in 0..10u64 {
        tokio::time::sleep(Duration::from_millis(10 * (1 << attempt))).await;
        let r = client
            .request(reqwest::Method::OPTIONS, &url)
            .header("Origin", origin)
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "content-type, x-api-key")
            .send()
            .await;
        match r {
            Ok(resp) => return resp,
            Err(e) => last = Some(e),
        }
    }
    panic!("server never responded: {last:?}");
}

#[tokio::test]
async fn tauri_origin_is_always_allowed() {
    let addr = boot(None).await;
    let resp = preflight(addr, "tauri://localhost").await;
    assert_eq!(resp.status(), 200, "CORS preflight for tauri:// must 200");
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("tauri://localhost"),
    );
}

#[tokio::test]
async fn https_tauri_origin_is_allowed() {
    let addr = boot(None).await;
    let resp = preflight(addr, "https://tauri.localhost").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://tauri.localhost"),
        "allowed origin must be echoed in Allow-Origin (200 alone false-passes — \
         a rejected origin also returns 200, just without this header)",
    );
}

#[tokio::test]
async fn localhost_origin_requires_cors_origins_allowlist() {
    let addr = boot(None).await;
    let resp = preflight(addr, "http://localhost:5173").await;
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "localhost origin must not be implicitly echoed"
    );

    let addr = boot(Some("http://localhost:5173")).await;
    let resp = preflight(addr, "http://localhost:5173").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("http://localhost:5173"),
        "explicit CORS_ORIGINS localhost origin must be echoed",
    );
}

#[tokio::test]
async fn arbitrary_origin_is_rejected() {
    let addr = boot(None).await;
    let resp = preflight(addr, "https://attacker.example.com").await;
    // tower-http returns 200 OPTIONS without the
    // `access-control-allow-origin` header → browser blocks. Verify the
    // header is absent.
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "evil origin must NOT be echoed in Allow-Origin"
    );
}
