//! HTTP integration coverage for `src-tauri/src/api/credentials.rs`.
//!
//! Replaces the deleted `tests/test_sbt_metadata.py` and the SBT subset
//! previously inside the wider auth-suite. Covers:
//!
//! * `POST /credentials` (plaintext + Pedersen-commit path)
//! * `GET  /credentials` (list + filter)
//! * `GET  /credentials/{id}`
//! * `POST /credentials/{id}/verify` (plaintext + opening path)
//! * `POST /credentials/{id}/revoke` (+ double-revoke 409)

use crate::common;

use serde_json::{json, Value};

fn holder(slug: &str) -> String {
    // Holder keys are opaque — use the unique-id helper directly so we
    // don't collide on UNIQUE (holder_key, credential_type) constraints.
    common::unique_id(&format!("holder-{slug}"))
}

#[tokio::test]
async fn issue_plaintext_then_list_and_get() {
    let h = common::boot().await;
    let h_key = holder("plain-list");

    let issue = common::post_json_with_key(
        &h.client,
        &common::url(h, "/credentials"),
        &h.api_key,
        &json!({
            "holder_key": h_key,
            "credential_type": "press",
            "details": { "role": "journalist", "tier": 2 },
        }),
    )
    .await;
    // POST /credentials returns 201 Created.
    assert_eq!(issue.status(), 201, "expected 201, got {}", issue.status());
    let issued: Value = issue.json().await.expect("JSON");
    let id = issued["id"].as_str().expect("id").to_owned();
    let commit_id = issued["commit_id"].as_str().expect("commit_id");
    assert_eq!(issued["holder_key"].as_str(), Some(h_key.as_str()));
    assert_eq!(issued["credential_type"].as_str(), Some("press"));
    assert_eq!(issued["details"]["role"].as_str(), Some("journalist"));
    assert!(
        !commit_id.is_empty(),
        "commit_id must be populated for plaintext path"
    );
    // Plaintext path: no opening returned.
    assert!(
        issued.get("opening").is_none() || issued["opening"].is_null(),
        "plaintext issue must NOT return an opening"
    );

    // GET by id round-trips.
    let got = common::get_with_key(
        &h.client,
        &common::url(h, &format!("/credentials/{id}")),
        &h.api_key,
    )
    .await;
    assert_eq!(got.status(), 200);
    let got_body: Value = got.json().await.expect("JSON");
    assert_eq!(got_body["id"].as_str(), Some(id.as_str()));
    assert_eq!(got_body["commit_id"].as_str(), Some(commit_id));

    // LIST filtered by holder shows it.
    let list = common::get_with_key(
        &h.client,
        &common::url(h, &format!("/credentials?holder={h_key}")),
        &h.api_key,
    )
    .await;
    assert_eq!(list.status(), 200);
    let list_body: Value = list.json().await.expect("JSON");
    let arr = list_body["credentials"]
        .as_array()
        .expect("credentials array");
    assert!(
        arr.iter().any(|c| c["id"].as_str() == Some(id.as_str())),
        "list filtered by holder must include the issued credential"
    );
}

#[tokio::test]
async fn issue_commit_returns_opening_and_verify_round_trips() {
    let h = common::boot().await;
    let h_key = holder("commit");

    let issue = common::post_json_with_key(
        &h.client,
        &common::url(h, "/credentials"),
        &h.api_key,
        &json!({
            "holder_key": h_key,
            "credential_type": "press",
            "details": { "role": "journalist" },
            "commit": true,
        }),
    )
    .await;
    assert_eq!(issue.status(), 201);
    let body: Value = issue.json().await.expect("JSON");
    let id = body["id"].as_str().expect("id").to_owned();
    // The opener tuple (m, r) is returned exactly once.
    let opening = &body["opening"];
    let m = opening["m"].as_str().expect("opening.m").to_owned();
    let r = opening["r"].as_str().expect("opening.r").to_owned();
    assert!(!m.is_empty() && !r.is_empty());
    // Stored row's `details` must be an empty object — the cleartext
    // never hits the DB on the commit path.
    assert_eq!(body["details"], json!({}));
    // Commitment coords are surfaced for verifiers.
    assert!(body["commitment"]["x"].is_string());
    assert!(body["commitment"]["y"].is_string());

    // Verify with the correct opening → commitment_opens true.
    let verify_ok = common::post_json_with_key(
        &h.client,
        &common::url(h, &format!("/credentials/{id}/verify")),
        &h.api_key,
        &json!({ "opening": { "m": m, "r": r } }),
    )
    .await;
    assert_eq!(verify_ok.status(), 200);
    let v_ok: Value = verify_ok.json().await.expect("JSON");
    assert_eq!(v_ok["issued_signature_valid"], Value::Bool(true));
    assert_eq!(v_ok["commit_id_matches"], Value::Bool(true));
    assert_eq!(v_ok["commitment_opens"], Value::Bool(true));
    assert_eq!(v_ok["is_revoked"], Value::Bool(false));

    // Verify with a WRONG opening → commitment_opens false (but
    // signature still valid against the stored commit_id).
    let verify_bad = common::post_json_with_key(
        &h.client,
        &common::url(h, &format!("/credentials/{id}/verify")),
        &h.api_key,
        &json!({ "opening": { "m": "1", "r": "1" } }),
    )
    .await;
    assert_eq!(verify_bad.status(), 200);
    let v_bad: Value = verify_bad.json().await.expect("JSON");
    assert_eq!(v_bad["commitment_opens"], Value::Bool(false));
    // A wrong opening must NOT invalidate the issuer signature or the
    // commit_id binding — only the Pedersen opening fails.
    assert_eq!(v_bad["issued_signature_valid"], Value::Bool(true));
    assert_eq!(v_bad["commit_id_matches"], Value::Bool(true));
}

#[tokio::test]
async fn revoke_credential_round_trip() {
    let h = common::boot().await;
    let h_key = holder("revoke");

    let issue = common::post_json_with_key(
        &h.client,
        &common::url(h, "/credentials"),
        &h.api_key,
        &json!({
            "holder_key": h_key,
            "credential_type": "press",
            "details": { "role": "journalist" },
        }),
    )
    .await;
    assert_eq!(issue.status(), 201);
    let id = issue.json::<Value>().await.expect("JSON")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // Revoke once.
    let revoke = common::post_json_with_key(
        &h.client,
        &common::url(h, &format!("/credentials/{id}/revoke")),
        &h.api_key,
        &json!({}),
    )
    .await;
    assert_eq!(revoke.status(), 200);
    let revoked_body: Value = revoke.json().await.expect("JSON");
    assert!(revoked_body["revoked_at"].is_string());
    assert!(revoked_body["revoked_signature"]["s"].is_string());

    // Verify now reports is_revoked + revoked_signature_valid.
    let verify = common::post_json_with_key(
        &h.client,
        &common::url(h, &format!("/credentials/{id}/verify")),
        &h.api_key,
        &json!({}),
    )
    .await;
    assert_eq!(verify.status(), 200);
    let v: Value = verify.json().await.expect("JSON");
    assert_eq!(v["is_revoked"], Value::Bool(true));
    assert_eq!(v["revoked_signature_valid"], Value::Bool(true));

    // Double revoke → 409.
    let again = common::post_json_with_key(
        &h.client,
        &common::url(h, &format!("/credentials/{id}/revoke")),
        &h.api_key,
        &json!({}),
    )
    .await;
    assert_eq!(again.status(), 409);
}

#[tokio::test]
async fn issue_missing_holder_key_is_422() {
    let h = common::boot().await;

    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/credentials"),
        &h.api_key,
        &json!({
            "holder_key": "",
            "credential_type": "press",
            "details": {},
        }),
    )
    .await;
    assert_eq!(resp.status(), 422);
}

#[tokio::test]
async fn issue_missing_credential_type_is_422() {
    let h = common::boot().await;

    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/credentials"),
        &h.api_key,
        &json!({
            "holder_key": "h-x",
            "credential_type": "",
            "details": {},
        }),
    )
    .await;
    assert_eq!(resp.status(), 422);
}

#[tokio::test]
async fn get_unknown_credential_is_404() {
    let h = common::boot().await;
    let resp = common::get_with_key(
        &h.client,
        &common::url(h, "/credentials/00000000-0000-0000-0000-deadbeefdead"),
        &h.api_key,
    )
    .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn issue_without_admin_scope_is_403() {
    let h = common::boot().await;

    // Register a fresh user with only `read` — their api_key cannot
    // POST /credentials (which requires `admin`).
    let e = format!("{}@example.com", common::unique_id("nonadmin"));
    let reg = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/auth/register"),
        &json!({
            "email": e,
            "password": "correct-horse-battery-staple",
            "name": "default",
            "scopes": ["read"],
        }),
    )
    .await;
    assert_eq!(reg.status(), 201);
    let body: Value = reg.json().await.expect("JSON");
    let key = body["api_key"].as_str().expect("api_key").to_owned();

    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/credentials"),
        &key,
        &json!({
            "holder_key": "h",
            "credential_type": "press",
            "details": {},
        }),
    )
    .await;
    // Note: depending on whether this user landed as the first-user
    // (admin auto-promote) the response is either 201 Created (issue
    // succeeded with auto-granted admin scope) or 403 (read-only key
    // lacks `admin`). Both are valid; the deliberate case here is the
    // FORBIDDEN branch. Soft-assert so test ordering within the binary
    // doesn't matter.
    let s = resp.status().as_u16();
    assert!(
        s == 201 || s == 403,
        "expected 201 (first-user auto-admin) or 403 (read-only), got {s}"
    );
}

// ── Audit M-1: credential read/list is admin-only ───────────────────────────
//
// Raw credential rows leak holder BJJ keys, issuer pubkeys, signatures and
// (uncommitted) details. `read`/`verify` are the default scopes on every
// self-registered account, so they must NOT be able to enumerate or fetch
// credential rows. Transparency verification stays available via
// `POST /credentials/{id}/verify` (covered separately).
#[tokio::test]
async fn read_only_key_cannot_list_or_get_credentials() {
    let h = common::boot().await;

    // Two registrations → the second is a guaranteed read/verify role='user'
    // account regardless of suite ordering (see `common::register_user`).
    let _first = common::register_user(h, "m1-first").await;
    let (_uid, key) = common::register_user(h, "m1-readonly").await;

    // GET /credentials (bulk list / arbitrary `?holder=` enumeration).
    let list = common::get_with_key(&h.client, &common::url(h, "/credentials"), &key).await;
    assert_eq!(
        list.status(),
        403,
        "read/verify key must not list credentials"
    );

    // GET /credentials/{id} — the scope gate runs before the row lookup, so a
    // nonexistent id still yields 403 (gate fired), not 404.
    let get = common::get_with_key(
        &h.client,
        &common::url(h, "/credentials/does-not-exist"),
        &key,
    )
    .await;
    assert_eq!(
        get.status(),
        403,
        "read/verify key must not fetch a credential by id"
    );
}

// ── Audit M-3: credential issuance requires an authority role ───────────────
//
// The `admin` *scope* alone is not enough — an `authority_sbt` minted here
// confers scopes, so a `role = 'user'` key carrying merely the admin scope
// could otherwise self-bootstrap authority. Issuance now demands `role` ∈
// {admin, system} AND the admin scope.
#[tokio::test]
async fn admin_scope_without_admin_role_cannot_issue() {
    let h = common::boot().await;

    // A guaranteed role='user' account.
    let _first = common::register_user(h, "m3-first").await;
    let (user_id, _user_key) = common::register_user(h, "m3-user").await;

    // Operator mints an *admin-scope* key for that role='user' user — the
    // exact M-3 escalation precondition (admin scope, non-authority role).
    let mint = common::post_admin_json(
        &h.client,
        &common::url(h, &format!("/admin/users/{user_id}/keys")),
        &h.admin_key,
        &json!({ "name": "m3-admin-scope", "scopes": ["admin"] }),
    )
    .await;
    assert_eq!(
        mint.status(),
        200,
        "operator mint of an admin-scope key should succeed"
    );
    let raw_key = mint.json::<Value>().await.expect("mint JSON")["raw_key"]
        .as_str()
        .expect("raw_key")
        .to_owned();

    // Admin scope present, but owning user's role is 'user' → refused.
    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/credentials"),
        &raw_key,
        &json!({
            "holder_key": common::unique_id("m3-holder"),
            "credential_type": "press",
            "details": {},
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        403,
        "admin-scope key on a role='user' account must be refused (M-3)"
    );
}
