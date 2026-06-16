//! HTTP integration coverage for `src-tauri/src/api/shards.rs` — the
//! operator-controlled shard-creation gate (migration `0039_shards.sql`).
//!
//! Exercises the admin-gated registry endpoints (`POST`/`GET /admin/shards`),
//! the fail-closed enforcement on `POST /ingest/files` (an unregistered shard
//! is rejected `403`; registering it unblocks the write), and the owner-binding
//! branch of `authorize_write` (a shard bound to `owner_user_id` accepts writes
//! only from that account or an `admin`-scoped key).
//!
//! The owner tests get a deterministic non-admin, write-scoped writer by
//! registering a plain user via `/auth/register` and then minting a `["write"]`
//! key for that user through the admin path
//! (`POST /admin/users/{user_id}/keys`). Crucially, `authorize_write`'s admin
//! bypass keys on the `admin` *scope*, not the user's role — so a `["write"]`
//! key never bypasses the owner check regardless of whether its owner happened
//! to be the auto-promoted first user. That sidesteps the
//! first-user-auto-promotion non-determinism that would plague a writer minted
//! purely through public registration.
//!
//! Shares the one bootstrapped server + DB with the rest of the `api_db`
//! binary, so every test uses `common::unique_id` to avoid colliding on the
//! `shards.shard_id` primary key with sibling tests running in parallel.

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

/// A non-admin, write-scoped writer minted deterministically.
struct Writer {
    /// `users.id` of the freshly-registered plain account.
    user_id: String,
    /// Raw API key carrying exactly `["write"]` — write-capable but, crucially,
    /// *not* `admin`-scoped, so it never bypasses the owner check.
    api_key: String,
}

/// Register a fresh plain user (read-only self-service scope, which is never
/// privileged so registration can't 403), then mint a `["write"]` key for that
/// user through the admin path. Returns the user's id + the write key.
async fn mint_write_only_writer(h: &common::TestHarness) -> Writer {
    let email = format!("{}@example.com", common::unique_id("shard-writer"));
    let reg = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/auth/register"),
        &serde_json::json!({
            "email": email,
            "password": "correct-horse-battery-staple",
            "name": "default",
            "scopes": ["read"],
        }),
    )
    .await;
    assert_eq!(reg.status(), 201, "plain user registration should be 201");
    let reg_body: serde_json::Value = reg.json().await.expect("JSON");
    let user_id = reg_body["user_id"].as_str().expect("user_id").to_owned();

    // Mint a write-only key for that user via the admin path. `["write"]`
    // satisfies the ingest scope check but does NOT carry `admin`, so the
    // owner-bypass branch of authorize_write never fires for it.
    let mint = common::post_admin_json(
        &h.client,
        &common::url(h, &format!("/admin/users/{user_id}/keys")),
        &h.admin_key,
        &serde_json::json!({ "name": "shard-writer-key", "scopes": ["write"] }),
    )
    .await;
    assert_eq!(mint.status(), 200, "admin key mint should be 200");
    let mint_body: serde_json::Value = mint.json().await.expect("JSON");
    let api_key = mint_body["raw_key"].as_str().expect("raw_key").to_owned();

    Writer { user_id, api_key }
}

/// Register an owned shard via the admin path (asserting 201).
async fn register_owned_shard(h: &common::TestHarness, shard_id: &str, owner_user_id: &str) {
    let resp = common::post_admin_json(
        &h.client,
        &common::url(h, "/admin/shards"),
        &h.admin_key,
        &serde_json::json!({ "shard_id": shard_id, "owner_user_id": owner_user_id }),
    )
    .await;
    assert_eq!(resp.status(), 201, "owned-shard registration should be 201");
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
    assert_eq!(
        dup.status(),
        409,
        "re-registering must conflict, not clobber"
    );

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

// ── Owner-binding enforcement ───────────────────────────────────────────────────

#[tokio::test]
async fn owner_bound_shard_rejects_non_owner_writer() {
    let h = common::boot().await;
    let shard = common::unique_id("owned");

    // Bind the shard to an arbitrary owner that is NOT our writer's user_id.
    let writer = mint_write_only_writer(h).await;
    // Create a different user to be the owner.
    let other_owner = mint_write_only_writer(h).await;
    register_owned_shard(h, &shard, &other_owner.user_id).await;

    // The write-only (non-owner, non-admin) writer is rejected with 403.
    let resp = ingest_file(h, &writer.api_key, &shard, "intruder payload").await;
    assert_eq!(
        resp.status(),
        403,
        "a non-owner, non-admin writer must be rejected from an owned shard"
    );
}

#[tokio::test]
async fn owner_bound_shard_accepts_its_owner() {
    let h = common::boot().await;
    let shard = common::unique_id("ownedself");

    // Bind the shard to the writer's own user_id — the same write-only key now
    // passes the owner check.
    let writer = mint_write_only_writer(h).await;
    register_owned_shard(h, &shard, &writer.user_id).await;

    let payload = format!("owner payload — {}", common::unique_id("body"));
    let resp = ingest_file(h, &writer.api_key, &shard, &payload).await;
    let s = resp.status().as_u16();
    assert!(
        s == 200 || s == 201,
        "the shard's owner should be able to write to it, got {s}"
    );
    let body: serde_json::Value = resp.json().await.expect("JSON");
    assert_eq!(body["shard_id"].as_str(), Some(shard.as_str()));
}

#[tokio::test]
async fn admin_scoped_key_bypasses_owner_check() {
    let h = common::boot().await;
    let shard = common::unique_id("ownedadmin");

    // Bind to an arbitrary owner, then confirm the system key (which carries
    // the `admin` scope) can still write — admin bypasses the owner check.
    // Create a user to be the owner.
    let owner = mint_write_only_writer(h).await;
    register_owned_shard(h, &shard, &owner.user_id).await;

    let payload = format!("admin override payload — {}", common::unique_id("body"));
    let resp = ingest_file(h, &h.api_key, &shard, &payload).await;
    let s = resp.status().as_u16();
    assert!(
        s == 200 || s == 201,
        "an admin-scoped key should bypass the owner check, got {s}"
    );
}

// ── Insert-only ledger (ADR-0031 §2) ────────────────────────────────────────────

/// POST `/ingest/files` with an explicit record identity (`record_id` +
/// `version`) so two distinct files can be aimed at the *same* parser-SMT key.
async fn ingest_file_with_identity(
    h: &common::TestHarness,
    api_key: &str,
    shard_id: &str,
    record_id: &str,
    version: i32,
    body: &str,
) -> reqwest::Response {
    let form = Form::new()
        .part(
            "file",
            Part::bytes(body.as_bytes().to_vec()).file_name("test.txt"),
        )
        .text("shard_id", shard_id.to_owned())
        .text("record_id", record_id.to_owned())
        .text("version", version.to_string());
    h.client
        .post(common::url(h, "/ingest/files"))
        .header("x-api-key", api_key)
        .multipart(form)
        .send()
        .await
        .expect("POST /ingest/files")
}

#[tokio::test]
async fn insert_only_record_identity_conflict_is_409() {
    let h = common::boot().await;
    // Pin the record identity (shard/type/record_id/version) so the parser-SMT
    // key is shared across uploads; only the file content (value_hash) differs.
    let record_id = common::unique_id("insert-only");

    // First commit at this identity → created.
    let first =
        ingest_file_with_identity(h, &h.api_key, "files", &record_id, 1, "original bytes").await;
    let s = first.status().as_u16();
    assert!(s == 200 || s == 201, "first ingest should be 2xx, got {s}");

    // A DIFFERENT file at the SAME identity is a write-once violation on the
    // parser-SMT leaf — the ledger is insert-only, so it must surface as 409
    // (not a swallowed warning, not 500).
    let conflict =
        ingest_file_with_identity(h, &h.api_key, "files", &record_id, 1, "tampered bytes").await;
    assert_eq!(
        conflict.status(),
        409,
        "rewriting a committed record identity with different content must be 409 (ADR-0031)"
    );

    // Re-uploading the SAME first file is an idempotent dedup (same value_hash),
    // never a conflict — the no-op re-commit path still succeeds.
    let dedup =
        ingest_file_with_identity(h, &h.api_key, "files", &record_id, 1, "original bytes").await;
    let ds = dedup.status().as_u16();
    assert!(
        ds == 200 || ds == 201,
        "identical re-upload must dedup to 2xx, got {ds}"
    );

    // Retrying the *rejected* file B is a content-dedup (2xx), NOT a second 409.
    // This is intentional and not a regression: the first B attempt already
    // persisted B's own ledger row before the parser-SMT conflict surfaced (the
    // SMT commit runs after `tx.commit`, by design), so the retry's INSERT sees a
    // duplicate `(content_hash, shard_id)` → `is_new=false` → the parser-SMT step
    // is skipped entirely. Crucially the insert-only invariant still holds: the
    // identity stays immutably bound to the *original* content — the retry never
    // rebinds it, it only re-observes that B's bytes already exist on the ledger.
    let retry_b =
        ingest_file_with_identity(h, &h.api_key, "files", &record_id, 1, "tampered bytes").await;
    let rs = retry_b.status().as_u16();
    assert!(
        rs == 200 || rs == 201,
        "retrying the rejected payload dedups to 2xx (identity stays bound to the original), got {rs}"
    );
    let body: serde_json::Value = retry_b.json().await.expect("JSON");
    assert_eq!(
        body["deduplicated"],
        serde_json::Value::Bool(true),
        "the retry must be reported as a dedup, not a fresh commit"
    );
}

#[tokio::test]
async fn register_shard_rejects_nonexistent_owner() {
    let h = common::boot().await;
    let shard = common::unique_id("phantom");

    // Binding to an owner_user_id that doesn't reference a real user is a 400 —
    // the handler validates owner existence up front (the table has no FK).
    let resp = common::post_admin_json(
        &h.client,
        &common::url(h, "/admin/shards"),
        &h.admin_key,
        &serde_json::json!({
            "shard_id": shard,
            "owner_user_id": common::unique_id("no-such-user"),
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        400,
        "registering a shard with a non-existent owner_user_id must be 400"
    );
}
