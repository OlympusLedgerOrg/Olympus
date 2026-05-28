//! Integration coverage for `src-tauri/src/api/admin_users.rs`.
//!
//! These tests exercise the **no-DB path** of every admin-user route:
//! they spin up the real Axum server via `server::start` with an
//! `AppState` that has no Postgres pool, fire HTTP requests at it, and
//! assert that the routes are wired, the extractors fire, and the
//! `db_or_503` early return shapes the response correctly (HTTP 503 with
//! a `detail` body). This is the cheap half of the coverage story —
//! it does NOT exercise the post-DB happy paths or the
//! `require_admin_auth` gate's auth logic itself (those need a live
//! pg-embed harness — separate follow-up).
//!
//! Pattern mirrors `src-tauri/src/server/mod.rs::tests`:
//! retry a short window while the server warms up, then assert.
//!
//! Run:  `cargo test -p olympus-desktop --test api_admin_users -- --nocapture`

use std::time::Duration;

use olympus_tauri_lib::server::start;
use olympus_tauri_lib::state::AppState;

/// Short retry window for the loopback server to bind + start accepting.
/// 10 attempts with exponential backoff (10, 20, 40, … ms) covers warm-up
/// without dragging cold-start tests above ~1 s in the worst case.
async fn request_with_retry<F, Fut>(send: F) -> reqwest::Response
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    let mut last_err = None;
    for attempt in 0..10u64 {
        tokio::time::sleep(Duration::from_millis(10 * (1 << attempt))).await;
        match send().await {
            Ok(resp) => return resp,
            Err(e) => last_err = Some(e),
        }
    }
    panic!("server never responded after retries: {:?}", last_err);
}

async fn boot_no_db_server() -> std::net::SocketAddr {
    start(AppState::new(None))
        .await
        .expect("server should bind on loopback")
}

#[tokio::test]
async fn list_users_returns_503_when_db_unavailable() {
    let addr = boot_no_db_server().await;
    let url = format!("http://{addr}/admin/users");
    let client = reqwest::Client::new();
    let resp = request_with_retry(|| client.get(&url).send()).await;
    assert_eq!(
        resp.status(),
        503,
        "GET /admin/users with no pool must hit db_or_503"
    );
    let body: serde_json::Value = resp.json().await.expect("response is JSON");
    assert!(
        body.get("detail").is_some(),
        "503 body must carry a `detail` field, got: {body}"
    );
}

#[tokio::test]
async fn mint_key_for_user_returns_503_when_db_unavailable() {
    let addr = boot_no_db_server().await;
    let url = format!(
        "http://{addr}/admin/users/00000000-0000-0000-0000-000000000001/keys"
    );
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "name": "test-key",
        "scopes": ["read"],
    });
    let resp = request_with_retry(|| client.post(&url).json(&body).send()).await;
    assert_eq!(
        resp.status(),
        503,
        "POST /admin/users/{{user_id}}/keys with no pool must hit db_or_503"
    );
}

#[tokio::test]
async fn revoke_key_returns_503_when_db_unavailable() {
    let addr = boot_no_db_server().await;
    let url = format!("http://{addr}/admin/keys/abc-123");
    let client = reqwest::Client::new();
    let resp = request_with_retry(|| client.delete(&url).send()).await;
    assert_eq!(
        resp.status(),
        503,
        "DELETE /admin/keys/{{key_id}} with no pool must hit db_or_503"
    );
}

#[tokio::test]
async fn update_key_scopes_returns_503_when_db_unavailable() {
    let addr = boot_no_db_server().await;
    let url = format!("http://{addr}/admin/keys/abc-123/scopes");
    let client = reqwest::Client::new();
    let body = serde_json::json!({ "scopes": ["read", "verify"] });
    let resp = request_with_retry(|| client.patch(&url).json(&body).send()).await;
    assert_eq!(
        resp.status(),
        503,
        "PATCH /admin/keys/{{key_id}}/scopes with no pool must hit db_or_503"
    );
}

#[tokio::test]
async fn update_user_role_returns_503_when_db_unavailable() {
    let addr = boot_no_db_server().await;
    let url = format!(
        "http://{addr}/admin/users/00000000-0000-0000-0000-000000000001/role"
    );
    let client = reqwest::Client::new();
    let body = serde_json::json!({ "role": "admin" });
    let resp = request_with_retry(|| client.patch(&url).json(&body).send()).await;
    assert_eq!(
        resp.status(),
        503,
        "PATCH /admin/users/{{user_id}}/role with no pool must hit db_or_503"
    );
}

