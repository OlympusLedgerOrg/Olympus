//! HTTP integration coverage for `src-tauri/src/api/shards.rs` — the
//! operator-controlled shard-creation gate (migration `0039_shards.sql`).
//!
//! Exercises the admin-gated registry endpoints (`POST`/`GET /admin/shards`)
//! and the fail-closed enforcement on `POST /ingest/files`: a `shard_id` that
//! is not registered (and active) is rejected with `403`, and registering it
//! via the admin path unblocks the write.
//!
//! Shares the one bootstrapped server + DB with the rest of the `api_db`
//! binary, so every test uses `common::unique_id` to avoid colliding on the
//! `shards.shard_id` primary key with sibling tests running in parallel.
//!
//! The owner-binding branch of `authorize_write` (a shard bound to
//! `owner_user_id` accepts writes only from that account or an `admin`-scoped
//! key) is exercised at the unit level in `api::shards` rather than here: an
//! end-to-end check would need to mint a non-admin, write-scoped key against
//! the shared DB, where the "first registered user is auto-promoted to admin"
//! rule makes the role non-deterministic under parallel test execution.

use crate::common;

use reqwest::multipart::{Form, Part};

/// Build a one-field file upload for `/ingest/files` targeting `shard_id`.
fn file_form(shard_id: &str, body: &str) -> Form {
    Form::new()
        .part(
            "file",
            Part::bytes(body.as_bytes().to_vec()).file_name("test.txt"),
        )
        .text("shard_id", shard_id.to_owned())
}

/// POST a file upload to `/ingest/files` with the given API key.
async fn ingest_file(
    h: &common::TestHarness,
    api_key: &str,
    shard_id: &str,
    body: &str,
) -> reqwest::Response {
    h.client
        .post(common::url(h, "/ingest/files"))
        .header("x-api-key", api_key)
        .multipart(file_form(shard_id, body))
        .send()
        .await
        .expect("POST /ingest/files")
}

// ── Admin registry endpoints ────────────────────────────────────────────────────

#[tokio::test]
async fn register_shard_requires_admin() {
    let h = common::boot().await;
    let shard = common::unique_id("noadmin");

    // No auth at all → the require_admin_auth gate rejects (401).
    let resp = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/admin/shards"),
        &serde_json::json!({ "shard_id": shard }),
    )
    .await;
    assert_eq!(
        resp.status(),
        401,
        "registering a shard without admin auth must be 401"
    );
}

#[tokio::test]
async fn register_shard_then_list_and_conflict() {
    let h = common::boot().await;
    let shard = common::unique_id("reg");

    // First registration: 201 CREATED with the row echoed back.
    let resp = common::post_admin_json(
        &h.client,
        &common::url(h, "/admin/shards"),
        &h.admin_key,
        &serde_json::json!({ "shard_id": shard, "label": "press pool" }),
    )
    .await;
    assert_eq!(resp.status(), 201, "first registration should be 201");
    let body: serde_json::Value = resp.json().await.expect("JSON");
    assert_eq!(body["shard_id"].as_str(), Some(shard.as_str()));
    assert_eq!(body["label"].as_str(), Some("press pool"));
    assert_eq!(body["active"], serde_json::Value::Bool(true));
    assert!(body["owner_user_id"].is_null(), "unowned when omitted");

    // Re-registering the same shard_id is a 409 — never a silent overwrite.
    let dup = common::post_admin_json(
        &h.client,
        &common::url(h, "/admin/shards"),
        &h.admin_key,
        &serde_json::json!({ "shard_id": shard }),
    )
    .await;
    assert_eq!(dup.status(), 409, "re-registering must conflict, not clobber");

    // It shows up in the admin listing.
    let list = common::get_admin(&h.client, &common::url(h, "/admin/shards"), &h.admin_key).await;
    assert_eq!(list.status(), 200);
    let arr: serde_json::Value = list.json().await.expect("JSON");
    let found = arr
        .as_array()
        .expect("array")
        .iter()
        .any(|r| r["shard_id"].as_str() == Some(shard.as_str()));
    assert!(found, "registered shard must appear in GET /admin/shards");
}

#[tokio::test]
async fn register_shard_rejects_malformed_id() {
    let h = common::boot().await;
    let resp = common::post_admin_json(
        &h.client,
        &common::url(h, "/admin/shards"),
        &h.admin_key,
        &serde_json::json!({ "shard_id": "has space" }),
    )
    .await;
    assert_eq!(
        resp.status(),
        422,
        "a shard_id failing the [A-Za-z0-9:._-] rule must be 422"
    );
}

// ── Fail-closed enforcement on the ingest write path ────────────────────────────

#[tokio::test]
async fn ingest_to_unregistered_shard_is_403() {
    let h = common::boot().await;
    // A syntactically valid but unregistered shard_id — first use must be
    // operator-authorized, so the gate rejects with 403 before any write.
    let shard = common::unique_id("unreg");
    let resp = ingest_file(h, &h.api_key, &shard, "payload for unregistered shard").await;
    assert_eq!(
        resp.status(),
        403,
        "ingest to an unregistered shard must be 403 (operator-controlled creation)"
    );
}

#[tokio::test]
async fn ingest_to_registered_shard_succeeds() {
    let h = common::boot().await;
    let shard = common::unique_id("ok");

    // Register first…
    let reg = common::post_admin_json(
        &h.client,
        &common::url(h, "/admin/shards"),
        &h.admin_key,
        &serde_json::json!({ "shard_id": shard }),
    )
    .await;
    assert_eq!(reg.status(), 201);

    // …then the same write that would have 403'd now succeeds. Body is
    // unique-per-test so it can't dedup against a sibling's commit.
    let payload = format!("registered shard payload — {}", common::unique_id("body"));
    let resp = ingest_file(h, &h.api_key, &shard, &payload).await;
    let s = resp.status().as_u16();
    assert!(
        s == 200 || s == 201,
        "ingest to a registered shard should be 2xx, got {s}"
    );
    let body: serde_json::Value = resp.json().await.expect("JSON");
    assert_eq!(body["shard_id"].as_str(), Some(shard.as_str()));
}

#[tokio::test]
async fn ingest_to_default_seeded_shard_succeeds_without_registration() {
    let h = common::boot().await;
    // Migration 0039 seeds the default `files` shard, so the out-of-the-box
    // upload flow works with no admin setup.
    let payload = format!("default shard payload — {}", common::unique_id("dflt"));
    let resp = ingest_file(h, &h.api_key, "files", &payload).await;
    let s = resp.status().as_u16();
    assert!(
        s == 200 || s == 201,
        "ingest to the seeded default `files` shard should be 2xx, got {s}"
    );
}
