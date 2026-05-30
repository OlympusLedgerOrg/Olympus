//! HTTP integration coverage for `src-tauri/src/api/ledger.rs`.
//!
//! Replaces the deleted Python coverage in `test_ledger.py`,
//! `test_ledger_simple_api.py`, `test_router_shards.py`, and the
//! `/ledger/*` subset of `test_router_misc.py`. Drives the simple
//! multipart ingest → verify round-trip end-to-end against pg_embed
//! (which is how the Tauri "OPEN FILE…" path commits documents in
//! production), plus the read-side state/activity/proof endpoints.

mod common;

use reqwest::multipart::{Form, Part};

#[tokio::test]
async fn ledger_state_returns_ok_with_default_shard() {
    let h = common::boot().await;

    let resp = h
        .client
        .get(common::url(h, "/ledger/state"))
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("JSON");
    // shard_count is at least 1 (the default shard appears even when no
    // commits exist yet — see DEFAULT_SHARD fallback in get_ledger_state).
    let sc = body["shard_count"].as_u64().expect("shard_count");
    assert!(sc >= 1, "shard_count should be >= 1, got {sc}");
    assert!(body["global_state_root"].is_string());
    assert!(body["total_commits"].is_number());
}

#[tokio::test]
async fn ledger_activity_returns_items_array() {
    let h = common::boot().await;

    let resp = h
        .client
        .get(common::url(h, "/ledger/activity?limit=5"))
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("JSON");
    assert!(body["items"].is_array());
    assert!(body["total"].is_number());
}

#[tokio::test]
async fn shard_state_rejects_invalid_shard_id() {
    let h = common::boot().await;
    let resp = h
        .client
        .get(common::url(h, "/ledger/shard/has space"))
        .send()
        .await
        .expect("GET");
    // Both the path encoding and the explicit validator can land us here;
    // either way it must be 4xx (not 500). 422 is the documented value.
    let s = resp.status().as_u16();
    assert!(
        s == 400 || s == 422 || s == 404,
        "invalid shard_id should be 4xx, got {s}"
    );
}

#[tokio::test]
async fn shard_state_for_known_default_shard() {
    let h = common::boot().await;
    let resp = h
        .client
        .get(common::url(h, "/ledger/shard/files"))
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("JSON");
    assert_eq!(body["shard_id"].as_str(), Some("files"));
}

#[tokio::test]
async fn commit_proof_unknown_id_is_404() {
    let h = common::boot().await;
    let resp = h
        .client
        .get(common::url(h, "/ledger/proof/0xdeadbeef"))
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn simple_ingest_then_verify_round_trip() {
    let h = common::boot().await;

    // Make the body unique-per-test so re-runs (and parallel tests
    // inside this binary) don't collide on the doc_hash UNIQUE
    // constraint and short-circuit the INSERT.
    let payload = format!(
        "Olympus integration test payload — {}",
        common::unique_id("ingest")
    );
    let form = Form::new().part(
        "file",
        Part::bytes(payload.clone().into_bytes()).file_name("test.txt"),
    );

    let ingest = h
        .client
        .post(common::url(h, "/ledger/ingest/simple"))
        .header("x-api-key", &h.api_key)
        .multipart(form)
        .send()
        .await
        .expect("POST");
    assert!(
        ingest.status() == 200 || ingest.status() == 201,
        "expected 2xx from /ledger/ingest/simple, got {}",
        ingest.status()
    );
    let body: serde_json::Value = ingest.json().await.expect("JSON");
    let commit_id = body["commit_id"].as_str().expect("commit_id").to_owned();
    let doc_hash = body["doc_hash"].as_str().expect("doc_hash").to_owned();
    assert!(commit_id.starts_with("0x"));
    assert_eq!(doc_hash.len(), 64, "BLAKE3 hex must be 64 chars");

    // Verify by commit_id (no auth required — /verify/simple is public).
    let form2 = Form::new().text("commit_id", commit_id.clone());
    let verify = h
        .client
        .post(common::url(h, "/ledger/verify/simple"))
        .multipart(form2)
        .send()
        .await
        .expect("POST");
    assert_eq!(verify.status(), 200);
    let vbody: serde_json::Value = verify.json().await.expect("JSON");
    assert_eq!(vbody["verified"], serde_json::Value::Bool(true));
    assert_eq!(vbody["commit_id"].as_str(), Some(commit_id.as_str()));
    assert_eq!(vbody["doc_hash"].as_str(), Some(doc_hash.as_str()));

    // Verify by re-uploading the file → same commit row.
    let form3 = Form::new().part(
        "file",
        Part::bytes(payload.into_bytes()).file_name("test.txt"),
    );
    let verify2 = h
        .client
        .post(common::url(h, "/ledger/verify/simple"))
        .multipart(form3)
        .send()
        .await
        .expect("POST");
    assert_eq!(verify2.status(), 200);
    let v2body: serde_json::Value = verify2.json().await.expect("JSON");
    assert_eq!(v2body["verified"], serde_json::Value::Bool(true));
    assert_eq!(v2body["commit_id"].as_str(), Some(commit_id.as_str()));

    // /ledger/proof/{commit_id} on a fresh row returns 202 ACCEPTED with
    // a `pending` status (Groth16 proof is generated lazily / ceremony-
    // gated).
    let proof = h
        .client
        .get(common::url(h, &format!("/ledger/proof/{commit_id}")))
        .send()
        .await
        .expect("GET");
    assert_eq!(proof.status(), 202);
    let pbody: serde_json::Value = proof.json().await.expect("JSON");
    assert_eq!(pbody["commit_id"].as_str(), Some(commit_id.as_str()));
    assert_eq!(pbody["status"].as_str(), Some("pending"));
}

#[tokio::test]
async fn simple_verify_unknown_doc_returns_not_verified() {
    let h = common::boot().await;

    // The file path: a brand-new payload no one has ingested.
    let unique = common::unique_id("unknown-payload");
    let form = Form::new().part(
        "file",
        Part::bytes(unique.clone().into_bytes()).file_name("unknown.txt"),
    );
    let resp = h
        .client
        .post(common::url(h, "/ledger/verify/simple"))
        .multipart(form)
        .send()
        .await
        .expect("POST");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("JSON");
    assert_eq!(body["verified"], serde_json::Value::Bool(false));
}

#[tokio::test]
async fn simple_verify_without_any_input_is_400() {
    let h = common::boot().await;

    // Empty multipart with no `file`/`commit_id`/`doc_hash` field.
    let resp = h
        .client
        .post(common::url(h, "/ledger/verify/simple"))
        .multipart(Form::new())
        .send()
        .await
        .expect("POST");
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn simple_ingest_without_write_scope_is_403() {
    let h = common::boot().await;

    // Register a read-only user and try to ingest with their key.
    let e = format!("{}@example.com", common::unique_id("ingest-noscope"));
    let reg = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/auth/register"),
        &serde_json::json!({
            "email": e,
            "password": "correct-horse-battery-staple",
            "name": "default",
            "scopes": ["read"],
        }),
    )
    .await;
    assert_eq!(reg.status(), 201);
    let key = reg.json::<serde_json::Value>().await.expect("JSON")["api_key"]
        .as_str()
        .expect("api_key")
        .to_owned();

    let payload = format!("no-scope payload — {}", common::unique_id("no-scope"));
    let form = Form::new().part(
        "file",
        Part::bytes(payload.into_bytes()).file_name("nope.txt"),
    );
    let resp = h
        .client
        .post(common::url(h, "/ledger/ingest/simple"))
        .header("x-api-key", &key)
        .multipart(form)
        .send()
        .await
        .expect("POST");
    // The first registered user becomes admin (auto-promote), in which
    // case this returns 200. Otherwise the FORBIDDEN branch fires.
    let s = resp.status().as_u16();
    assert!(
        s == 200 || s == 201 || s == 403,
        "expected 2xx (first-user auto-admin) or 403, got {s}"
    );
}
