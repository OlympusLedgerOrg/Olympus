//! ADR-0036 "Scope Matrix Direction" follow-up: closes the exact gap named in
//! `tests/api_admin_users.rs`'s own doc comment — "it does NOT exercise...
//! the `require_admin_auth` gate's auth logic itself (those need a live
//! pg-embed harness — separate follow-up)" — for the ADR-0036 signed-envelope
//! gate specifically (`require_signed_admin_mutation_if_configured`).
//!
//! `src-tauri/src/api/admin_routes.rs::SIGNED_ADMIN_MUTATION_ROUTES` is
//! already proven internally self-consistent (two hand-written lists agree,
//! see `admin_routes.rs`'s own tests) and the pattern-matcher is unit-tested
//! against synthetic paths (`middleware/signed_request.rs`'s
//! `signed_admin_mutation_scope_covers_shared_admin_mutation_routes`). Neither
//! check ever fires an HTTP request at the real router. This file does: it
//! boots the actual Axum server (no DB — the gate rejects a missing/malformed
//! envelope before ever touching the pool, see `verify_wire_envelope`) and
//! asserts, for every declared route:
//!
//! 1. with `OLYMPUS_REQUIRE_SIGNED_ADMIN_REQUESTS=true`, a request with no
//!    signed envelope is rejected by the gate (not by some other layer);
//! 2. with the gate unset (desktop default), the same request is NOT
//!    rejected by the gate — it falls through to the ordinary handler (which
//!    503s with no pool) — proving the opt-in switch actually toggles
//!    behavior, not just that the pattern matcher recognises the path;
//! 3. a same-path, different-method request (e.g. `GET /admin/shards`,
//!    which is read-only and deliberately absent from the mutation table)
//!    is never gated, even with enforcement on — the gate keys on method
//!    *and* path, not path alone.
//!
//! `OLYMPUS_REQUIRE_SIGNED_ADMIN_REQUESTS` is process-global, so tests in
//! this binary that set it serialize on `SIGNED_ADMIN_GATE_ENV_LOCK` and
//! restore the prior value on drop — the same pattern
//! `tests/api_db/external_pg_roles.rs::ExternalDatabaseEnvRestore` uses for
//! its own process-global env vars. This file is its own test binary
//! (separate process), so it cannot race the `tests/api_db.rs` binary's
//! tests, which never set this variable.
//!
//! Run:  `cargo test -p olympus-desktop --test api_admin_signed_mutation_gate -- --nocapture`

use std::net::SocketAddr;
use std::time::Duration;

use olympus_tauri_lib::api::admin_routes::SIGNED_ADMIN_MUTATION_ROUTES;
use olympus_tauri_lib::server::start;
use olympus_tauri_lib::state::AppState;
use reqwest::{Client, Response};
use serde_json::Value;

/// Mirrors `tests/api_admin_users.rs::request_with_retry` — short exponential
/// backoff while the freshly-bound loopback listener warms up.
async fn request_with_retry<F, Fut>(send: F) -> Response
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<Response, reqwest::Error>>,
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

/// `OLYMPUS_REQUIRE_SIGNED_ADMIN_REQUESTS` is read fresh on every request
/// (`signed_admin_mutation_enforcement_enabled`), so tests in this binary
/// that need different values must not run concurrently against a shared
/// process env var.
static SIGNED_ADMIN_GATE_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct EnvRestore {
    name: &'static str,
    old: Option<String>,
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        match self.old.take() {
            Some(v) => std::env::set_var(self.name, v),
            None => std::env::remove_var(self.name),
        }
    }
}

fn set_env(name: &'static str, value: &str) -> EnvRestore {
    let old = std::env::var(name).ok();
    std::env::set_var(name, value);
    EnvRestore { name, old }
}

fn unset_env(name: &'static str) -> EnvRestore {
    let old = std::env::var(name).ok();
    std::env::remove_var(name);
    EnvRestore { name, old }
}

async fn boot() -> SocketAddr {
    start(AppState::new(None))
        .await
        .expect("server should bind on loopback")
}

/// Fill every `{param}` segment of a declared route pattern with a
/// placeholder. The ADR-0036 gate matches on the raw request path against
/// `SIGNED_ADMIN_MUTATION_ROUTES` (see `route_pattern_matches`) independently
/// of Axum's own route table, so the placeholder never needs to resolve to a
/// real row — any non-empty segment matches `{param}`.
fn sample_path(pattern: &str) -> String {
    pattern
        .split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                "test-id"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn dispatch(client: &Client, method: &str, url: &str) -> reqwest::RequestBuilder {
    match method {
        "POST" => client.post(url),
        "PATCH" => client.patch(url),
        "DELETE" => client.delete(url),
        "PUT" => client.put(url),
        other => panic!("unexpected admin-mutation method {other} in SIGNED_ADMIN_MUTATION_ROUTES"),
    }
}

/// The exact shape `SignedRequestRejection::into_response` produces.
async fn rejection_code(resp: Response) -> Option<String> {
    let body: Value = resp.json().await.ok()?;
    body.get("code")?.as_str().map(str::to_owned)
}

#[tokio::test]
async fn signed_admin_mutation_routes_are_rejected_without_a_signed_envelope_when_gate_is_enabled()
{
    let _lock = SIGNED_ADMIN_GATE_ENV_LOCK.lock().await;
    let _restore_env = set_env("OLYMPUS_ENV", "test");
    let _restore_gate = set_env("OLYMPUS_REQUIRE_SIGNED_ADMIN_REQUESTS", "true");

    let addr = boot().await;
    let client = Client::new();

    for route in SIGNED_ADMIN_MUTATION_ROUTES {
        let url = format!("http://{addr}{}", sample_path(route.path_pattern));
        let resp = request_with_retry(|| {
            dispatch(&client, route.method, &url)
                .json(&serde_json::json!({}))
                .send()
        })
        .await;
        let status = resp.status();
        let code = rejection_code(resp).await;
        assert_eq!(
            code.as_deref(),
            Some("SIGNED_REQUEST_REJECTED"),
            "{} {} must be rejected by the ADR-0036 signed-request gate \
             when OLYMPUS_REQUIRE_SIGNED_ADMIN_REQUESTS=true, got status {status} \
             and no SIGNED_REQUEST_REJECTED code",
            route.method,
            route.path_pattern
        );
        assert!(
            status.is_client_error(),
            "{} {} gate rejection must be a 4xx, got {status}",
            route.method,
            route.path_pattern
        );
    }
}

#[tokio::test]
async fn signed_admin_mutation_gate_is_opt_in_and_inert_when_not_enabled() {
    let _lock = SIGNED_ADMIN_GATE_ENV_LOCK.lock().await;
    let _restore_env = set_env("OLYMPUS_ENV", "test");
    let _restore_gate = unset_env("OLYMPUS_REQUIRE_SIGNED_ADMIN_REQUESTS");

    let addr = boot().await;
    let client = Client::new();

    for route in SIGNED_ADMIN_MUTATION_ROUTES {
        let url = format!("http://{addr}{}", sample_path(route.path_pattern));
        let resp = request_with_retry(|| {
            dispatch(&client, route.method, &url)
                .json(&serde_json::json!({}))
                .send()
        })
        .await;
        let code = rejection_code(resp).await;
        assert_ne!(
            code.as_deref(),
            Some("SIGNED_REQUEST_REJECTED"),
            "{} {} must NOT be rejected by the ADR-0036 gate when \
             OLYMPUS_REQUIRE_SIGNED_ADMIN_REQUESTS is unset (desktop default) — \
             the opt-in switch must actually toggle enforcement, not just be \
             recognised by the pattern matcher",
            route.method,
            route.path_pattern
        );
    }
}

#[tokio::test]
async fn signed_admin_mutation_gate_keys_on_method_not_just_path() {
    let _lock = SIGNED_ADMIN_GATE_ENV_LOCK.lock().await;
    let _restore_env = set_env("OLYMPUS_ENV", "test");
    let _restore_gate = set_env("OLYMPUS_REQUIRE_SIGNED_ADMIN_REQUESTS", "true");

    let addr = boot().await;
    let client = Client::new();

    // POST /admin/shards is in SIGNED_ADMIN_MUTATION_ROUTES; GET /admin/shards
    // (a read, listing shards) shares the path but is deliberately absent —
    // the gate must not over-match on path alone and block ordinary reads.
    let url = format!("http://{addr}/admin/shards");
    let resp = request_with_retry(|| client.get(&url).send()).await;
    let code = rejection_code(resp).await;
    assert_ne!(
        code.as_deref(),
        Some("SIGNED_REQUEST_REJECTED"),
        "GET /admin/shards must never be gated by the POST-only admin-mutation policy"
    );
}
