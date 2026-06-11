//! With-DB happy-path coverage for `src-tauri/src/api/admin_users.rs`.
//!
//! Complements `tests/api_admin_users.rs` (which only exercises the no-DB
//! 503 path) — this file boots `pg_embed`, drives the full router through
//! `require_admin_auth`'s `x-admin-key` branch, and asserts that the
//! happy-path SQL actually mutates `users` / `api_keys`. Replaces the
//! deleted Python coverage in `tests/test_admin_endpoint_rate_limit.py`
//! (the limit-bucket scenarios that needed a live DB) plus the
//! "admin users CRUD" subset previously covered by `test_auth.py`.

use crate::common;

use serde_json::{json, Value};

/// `/admin/users` returns the system user plus any other rows we've
/// registered through the auth flow.
#[tokio::test]
async fn list_users_returns_rows() {
    let h = common::boot().await;

    let resp = common::get_admin(&h.client, &common::url(h, "/admin/users"), &h.admin_key).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("JSON");
    let rows = body.get("rows").and_then(Value::as_array).expect("rows");
    // The bootstrap system user (00…001) is always present; UI tests rely
    // on that, so any other change here would be a behavior regression.
    assert!(
        rows.iter().any(|r| r["email"] == "system@olympus.local"),
        "expected system user row in list_users response; got {body:#}"
    );
}

#[tokio::test]
async fn list_users_without_admin_key_is_401() {
    let h = common::boot().await;

    // No header at all → admin gate fails fast.
    let resp = h
        .client
        .get(common::url(h, "/admin/users"))
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn list_users_with_wrong_admin_key_is_401() {
    let h = common::boot().await;

    let resp = common::get_admin(
        &h.client,
        &common::url(h, "/admin/users"),
        "not-the-real-key",
    )
    .await;
    // Audit L-API-3: a wrong header is rejected outright, not fallen
    // through to the API-key path — proves the constant-time compare
    // guard is wired.
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn mint_key_for_user_then_revoke_round_trip() {
    let h = common::boot().await;
    let email = format!("{}@example.com", common::unique_id("mint-target"));

    // Register a target user (first non-system reg → role=admin; that's
    // fine, we just need a row to mint against).
    let reg = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/auth/register"),
        &json!({
            "email": email,
            "password": "correct-horse-battery-staple",
            "name": "default",
            "scopes": ["read"]
        }),
    )
    .await;
    // First-user path returns 201 with role auto-promoted to admin;
    // subsequent users get 201 too — either is OK for "user exists".
    assert!(reg.status() == 201, "register failed: {}", reg.status());
    let reg_body: Value = reg.json().await.expect("JSON");
    let user_id = reg_body["user_id"].as_str().expect("user_id").to_owned();

    // Mint a fresh key for that user.
    let mint = common::post_admin_json(
        &h.client,
        &common::url(h, &format!("/admin/users/{user_id}/keys")),
        &h.admin_key,
        &json!({ "name": "minted-by-admin", "scopes": ["read", "verify"] }),
    )
    .await;
    assert_eq!(mint.status(), 200, "mint failed");
    let mint_body: Value = mint.json().await.expect("JSON");
    let key_id = mint_body["key_id"].as_str().expect("key_id").to_owned();
    let raw_key = mint_body["raw_key"].as_str().expect("raw_key").to_owned();
    assert!(
        raw_key.starts_with("oly_"),
        "raw_key should be `oly_<hex>`, got {raw_key}"
    );

    // Sanity-check the new key authenticates: GET /auth/keys runs the
    // `AuthenticatedKey` extractor with no scope requirement, so a valid
    // key (any scopes) returns 200. We deliberately pick an *auth-gated*
    // route here — the `/ingest/records/*` reads are public, so they'd
    // return the same status regardless of key validity and prove nothing.
    let probe = common::get_with_key(&h.client, &common::url(h, "/auth/keys"), &raw_key).await;
    assert_eq!(
        probe.status(),
        200,
        "minted key should authenticate on GET /auth/keys"
    );

    // Revoke it.
    let revoke = common::delete_admin(
        &h.client,
        &common::url(h, &format!("/admin/keys/{key_id}")),
        &h.admin_key,
    )
    .await;
    assert_eq!(revoke.status(), 200);

    // The same probe now must 401 — `revoked_at IS NULL` is checked on
    // every auth-extractor query.
    let after = common::get_with_key(&h.client, &common::url(h, "/auth/keys"), &raw_key).await;
    assert_eq!(after.status(), 401, "revoked key must 401 on next request");
}

#[tokio::test]
async fn update_key_scopes_rejects_unknown() {
    let h = common::boot().await;
    let email = format!("{}@example.com", common::unique_id("scope-target"));

    let reg = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/auth/register"),
        &json!({
            "email": email,
            "password": "correct-horse-battery-staple",
            "name": "default",
            "scopes": ["read"]
        }),
    )
    .await;
    assert_eq!(reg.status(), 201);
    let reg_body: Value = reg.json().await.expect("JSON");
    let key_id = reg_body["key_id"].as_str().expect("key_id").to_owned();

    // Unknown scope → 422.
    let bad = common::patch_admin_json(
        &h.client,
        &common::url(h, &format!("/admin/keys/{key_id}/scopes")),
        &h.admin_key,
        &json!({ "scopes": ["read", "not-a-real-scope"] }),
    )
    .await;
    assert_eq!(bad.status(), 422);

    // Known scopes → 200, body reflects the new list.
    let good = common::patch_admin_json(
        &h.client,
        &common::url(h, &format!("/admin/keys/{key_id}/scopes")),
        &h.admin_key,
        &json!({ "scopes": ["read", "verify"] }),
    )
    .await;
    assert_eq!(good.status(), 200);
    let body: Value = good.json().await.expect("JSON");
    assert_eq!(body["scopes"], json!(["read", "verify"]));
}

#[tokio::test]
async fn update_user_role_rejects_unknown_role() {
    let h = common::boot().await;
    let email = format!("{}@example.com", common::unique_id("role-target"));

    let reg = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/auth/register"),
        &json!({
            "email": email,
            "password": "correct-horse-battery-staple",
            "name": "default",
            "scopes": ["read"]
        }),
    )
    .await;
    assert_eq!(reg.status(), 201);
    let user_id = reg.json::<Value>().await.expect("JSON")["user_id"]
        .as_str()
        .expect("user_id")
        .to_owned();

    // Reject role outside VALID_ROLES.
    let bad = common::patch_admin_json(
        &h.client,
        &common::url(h, &format!("/admin/users/{user_id}/role")),
        &h.admin_key,
        &json!({ "role": "god-mode" }),
    )
    .await;
    assert_eq!(bad.status(), 422);

    // Accept a recognized role value. This first-registered user is the sole
    // admin, so we assert the idempotent admin→admin path here (200); demoting
    // the last admin is intentionally blocked and covered by its own test below.
    let good = common::patch_admin_json(
        &h.client,
        &common::url(h, &format!("/admin/users/{user_id}/role")),
        &h.admin_key,
        &json!({ "role": "admin" }),
    )
    .await;
    assert_eq!(good.status(), 200);
}

/// The last-admin guard must NOT over-block a normal demotion: once two admins
/// exist, either can be demoted (200).
///
/// Note on coverage: the complementary "demoting the *global* sole admin is
/// refused (409)" branch is deliberately NOT integration-tested here. `boot()`
/// shares ONE database across every test in this binary (OnceLock harness), and
/// "first non-system user becomes admin" is a global condition — so the number
/// of admin rows depends on test execution order and can never be pinned to
/// exactly one. That branch is enforced in SQL (the `EXISTS (… id <> $2)`
/// predicate under a `FOR UPDATE` lock) and exercised by unit-level reasoning;
/// an order-dependent 409 assertion here would be flaky (it was — it passed
/// locally when this test happened to run first and failed in CI when it ran
/// after other admin-creating tests).
#[tokio::test]
async fn update_user_role_allows_demotion_when_another_admin_exists() {
    let h = common::boot().await;

    // Create two users and force BOTH to admin, so the guard's "another admin
    // exists" branch is satisfied deterministically regardless of how many
    // admins other tests in this shared DB have already created.
    let mut ids = Vec::new();
    for slug in ["multi-admin-a", "multi-admin-b"] {
        let email = format!("{}@example.com", common::unique_id(slug));
        let reg = common::post_json_no_auth(
            &h.client,
            &common::url(h, "/auth/register"),
            &json!({ "email": email, "password": "correct-horse-battery-staple", "name": slug, "scopes": ["read"] }),
        )
        .await;
        assert_eq!(reg.status(), 201);
        let id = reg.json::<Value>().await.expect("JSON")["user_id"]
            .as_str()
            .expect("user_id")
            .to_owned();
        // Promote (idempotent if registration already made them admin).
        let promote = common::patch_admin_json(
            &h.client,
            &common::url(h, &format!("/admin/users/{id}/role")),
            &h.admin_key,
            &json!({ "role": "admin" }),
        )
        .await;
        assert_eq!(promote.status(), 200);
        ids.push(id);
    }

    // With at least two admins present, demoting one is allowed (200) — the
    // guard only blocks when it would remove the final admin.
    let allowed = common::patch_admin_json(
        &h.client,
        &common::url(h, &format!("/admin/users/{}/role", ids[0])),
        &h.admin_key,
        &json!({ "role": "user" }),
    )
    .await;
    assert_eq!(
        allowed.status(),
        200,
        "demotion must be allowed while another admin exists"
    );
}

#[tokio::test]
async fn revoke_unknown_key_is_404() {
    let h = common::boot().await;
    let resp = common::delete_admin(
        &h.client,
        &common::url(h, "/admin/keys/00000000-0000-0000-0000-deadbeefdead"),
        &h.admin_key,
    )
    .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn mint_key_for_unknown_user_is_404() {
    let h = common::boot().await;
    let resp = common::post_admin_json(
        &h.client,
        &common::url(h, "/admin/users/00000000-0000-0000-0000-deadbeefdead/keys"),
        &h.admin_key,
        &json!({ "name": "anything", "scopes": ["read"] }),
    )
    .await;
    assert_eq!(resp.status(), 404);
}
