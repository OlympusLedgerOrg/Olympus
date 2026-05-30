//! HTTP integration coverage for `src-tauri/src/api/user_auth.rs`.
//!
//! Replaces the deleted Python suites `test_auth.py`,
//! `test_user_auth_router.py`, and `test_auth_registration_scopes.py`.
//! Boots `pg_embed`, drives the full router (so password hashing,
//! UNIQUE-email enforcement, the "first user → admin" advisory-lock
//! path, and the scope-subset rule on `create_key` are all exercised
//! end-to-end against real Postgres).
//!
//! Tests use unique emails (`common::unique_id`) so they're safe to run
//! in any order or in parallel within this binary.

use crate::common;

use serde_json::{json, Value};

const PW: &str = "correct-horse-battery-staple";

fn email(slug: &str) -> String {
    format!("{}@example.com", common::unique_id(slug))
}

/// A raw API key is 32 bytes hex-encoded (64 lowercase hex chars), with an
/// optional cosmetic `oly_` prefix. `generate_raw_key` (user keys) emits the
/// bare form; `derive_api_key_from_bjj` (the bootstrap key) adds the prefix.
/// `blake3_key_hash` normalises both before hashing, so both authenticate.
fn is_raw_key(k: &str) -> bool {
    let body = k.strip_prefix("oly_").unwrap_or(k);
    body.len() == 64 && body.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn register(h: &common::TestHarness, e: &str, scopes: Value) -> reqwest::Response {
    common::post_json_no_auth(
        &h.client,
        &common::url(h, "/auth/register"),
        &json!({
            "email": e,
            "password": PW,
            "name": "default",
            "scopes": scopes,
        }),
    )
    .await
}

#[tokio::test]
async fn register_then_login_round_trip() {
    let h = common::boot().await;
    let e = email("login-rt");

    let reg = register(h, &e, json!(["read"])).await;
    assert_eq!(reg.status(), 201);
    let reg_body: Value = reg.json().await.expect("JSON");
    let api_key = reg_body["api_key"].as_str().expect("api_key").to_owned();
    // User-registration keys are bare 64-char hex from `generate_raw_key`
    // (only the bootstrap key carries the cosmetic `oly_` prefix via
    // `derive_api_key_from_bjj`; `blake3_key_hash` accepts both forms).
    assert!(is_raw_key(&api_key), "unexpected key shape: {api_key}");

    // Login round-trip.
    let login = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/auth/login"),
        &json!({ "email": e, "password": PW }),
    )
    .await;
    assert_eq!(login.status(), 200);
    let login_body: Value = login.json().await.expect("JSON");
    assert_eq!(login_body["email"], e);
    let keys = login_body["keys"].as_array().expect("keys array");
    assert!(
        !keys.is_empty(),
        "login should surface at least one active key"
    );
}

#[tokio::test]
async fn register_duplicate_email_is_4xx() {
    let h = common::boot().await;
    let e = email("dup-email");

    let first = register(h, &e, json!(["read"])).await;
    assert_eq!(first.status(), 201);

    let second = register(h, &e, json!(["read"])).await;
    // The UNIQUE constraint on `users.email` rejects the duplicate.
    // The handler maps it to a client error — exact code is 4xx,
    // we don't pin to one because the exact mapping is subject to
    // change (409 vs 422 vs 400).
    let status = second.status().as_u16();
    assert!(
        (400..500).contains(&status),
        "duplicate email should be 4xx, got {status}"
    );
}

#[tokio::test]
async fn register_unknown_scope_is_400() {
    let h = common::boot().await;
    let e = email("bad-scope");
    let resp = register(h, &e, json!(["read", "totally-bogus"])).await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn login_with_wrong_password_is_401() {
    let h = common::boot().await;
    let e = email("wrong-pw");

    let reg = register(h, &e, json!(["read"])).await;
    assert_eq!(reg.status(), 201);

    let login = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/auth/login"),
        &json!({ "email": e, "password": "definitely-not-the-password" }),
    )
    .await;
    assert_eq!(login.status(), 401);
}

#[tokio::test]
async fn login_for_unknown_email_is_401() {
    let h = common::boot().await;

    // Always-401 ("invalid email or password") — same shape as
    // wrong-password to defeat email-enumeration timing oracles.
    let resp = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/auth/login"),
        &json!({ "email": "nobody@nowhere", "password": "irrelevant" }),
    )
    .await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn reissue_key_returns_fresh_credential() {
    let h = common::boot().await;
    let e = email("reissue");

    let reg = register(h, &e, json!(["read"])).await;
    assert_eq!(reg.status(), 201);
    let original_key = reg.json::<Value>().await.expect("JSON")["api_key"]
        .as_str()
        .expect("api_key")
        .to_owned();

    let resp = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/auth/reissue-key"),
        &json!({ "email": e, "password": PW, "scopes": ["read"] }),
    )
    .await;
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.expect("JSON");
    let new_key = body["api_key"].as_str().expect("api_key");
    assert!(is_raw_key(new_key), "unexpected key shape: {new_key}");
    assert_ne!(
        new_key, original_key,
        "reissued key must differ from original"
    );
}

#[tokio::test]
async fn create_key_widening_scopes_is_rejected() {
    let h = common::boot().await;
    let e = email("widen");

    // Register with only `read`.
    let reg = register(h, &e, json!(["read"])).await;
    assert_eq!(reg.status(), 201);
    let api_key = reg.json::<Value>().await.expect("JSON")["api_key"]
        .as_str()
        .expect("api_key")
        .to_owned();

    // Attempt to mint a key with `write` (privileged) — the caller's
    // own scopes don't include `write`, so this MUST be rejected.
    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/auth/keys"),
        &api_key,
        &json!({ "name": "wider", "scopes": ["read", "write"] }),
    )
    .await;
    assert!(
        resp.status().is_client_error(),
        "scope-widening should be 4xx, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn list_then_revoke_key_round_trip() {
    let h = common::boot().await;
    let e = email("revoke-rt");

    let reg = register(h, &e, json!(["read"])).await;
    assert_eq!(reg.status(), 201);
    let body: Value = reg.json().await.expect("JSON");
    let api_key = body["api_key"].as_str().expect("api_key").to_owned();
    let original_key_id = body["key_id"].as_str().expect("key_id").to_owned();

    // Mint a second key (same scopes — subset rule satisfied).
    let mint = common::post_json_with_key(
        &h.client,
        &common::url(h, "/auth/keys"),
        &api_key,
        &json!({ "name": "extra", "scopes": ["read"] }),
    )
    .await;
    assert_eq!(mint.status(), 201);
    let mint_body: Value = mint.json().await.expect("JSON");
    let extra_key_id = mint_body["key_id"].as_str().expect("key_id").to_owned();

    // List — should contain both.
    let list = common::get_with_key(&h.client, &common::url(h, "/auth/keys"), &api_key).await;
    assert_eq!(list.status(), 200);
    let list_body: Value = list.json().await.expect("JSON");
    let arr = list_body.as_array().expect("keys array");
    assert!(arr.len() >= 2, "expected at least 2 keys, got {:#?}", arr);

    // Revoke the extra key (the original keeps us authenticated for
    // the follow-up list).
    let revoke = common::delete_with_key(
        &h.client,
        &common::url(h, &format!("/auth/keys/{extra_key_id}")),
        &api_key,
    )
    .await;
    assert_eq!(revoke.status(), 204);

    // Re-list: extra key gone, original still present.
    let after = common::get_with_key(&h.client, &common::url(h, "/auth/keys"), &api_key).await;
    let after_body: Value = after.json().await.expect("JSON");
    let ids: Vec<String> = after_body
        .as_array()
        .expect("keys array")
        .iter()
        .map(|k| k["id"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(
        ids.contains(&original_key_id),
        "original key should still be active"
    );
    assert!(
        !ids.contains(&extra_key_id),
        "revoked key must NOT appear in list"
    );
}

#[tokio::test]
async fn double_revoke_is_409() {
    let h = common::boot().await;
    let e = email("double-revoke");

    let reg = register(h, &e, json!(["read"])).await;
    assert_eq!(reg.status(), 201);
    let body: Value = reg.json().await.expect("JSON");
    let api_key = body["api_key"].as_str().expect("api_key").to_owned();

    // Mint an extra key to revoke twice. Revoking the only key would
    // (correctly) lock us out before the second DELETE.
    let mint = common::post_json_with_key(
        &h.client,
        &common::url(h, "/auth/keys"),
        &api_key,
        &json!({ "name": "extra", "scopes": ["read"] }),
    )
    .await;
    let extra_key_id = mint.json::<Value>().await.expect("JSON")["key_id"]
        .as_str()
        .expect("key_id")
        .to_owned();

    let first = common::delete_with_key(
        &h.client,
        &common::url(h, &format!("/auth/keys/{extra_key_id}")),
        &api_key,
    )
    .await;
    assert_eq!(first.status(), 204);

    let second = common::delete_with_key(
        &h.client,
        &common::url(h, &format!("/auth/keys/{extra_key_id}")),
        &api_key,
    )
    .await;
    assert_eq!(second.status(), 409);
}
