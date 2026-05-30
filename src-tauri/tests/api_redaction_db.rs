//! HTTP integration coverage for `src-tauri/src/api/redaction.rs`.
//!
//! Replaces the route-level subset of the deleted `test_redaction_ledger.py`
//! / `test_redaction_semantics.py`. Covers:
//!
//! * `POST /redaction/link`  (public) — chunk-count validation, unknown-commit
//!   404, and the happy path (ingest a doc, then link 64-chunk arrays).
//! * `POST /redaction/issue` (auth)   — auth/scope gating + input validation.
//!   The full Groth16 prove path is NOT exercised here (it needs a resolved
//!   `proofs_dir` + committed content and is covered by the `zk_prove_*`
//!   suite); these tests pin the cheap pre-prove guards.

mod common;

use reqwest::multipart::{Form, Part};
use serde_json::{json, Value};

/// 64 distinct valid 64-hex chunk hashes (one per leaf; `link` requires
/// exactly `MAX_LEAVES == 64`).
fn chunks_64() -> Vec<String> {
    (0..64u32).map(|i| format!("{:064x}", i + 1)).collect()
}

/// Ingest a unique document via the simple multipart path and return its
/// `commit_id` — `/redaction/link` requires the original commit to exist.
async fn ingest_commit(h: &common::TestHarness) -> String {
    let payload = format!("redaction-src-{}", common::unique_id("doc"));
    let form = Form::new().part(
        "file",
        Part::bytes(payload.into_bytes()).file_name("orig.txt"),
    );
    let resp = h
        .client
        .post(common::url(h, "/ledger/ingest/simple"))
        .header("x-api-key", &h.api_key)
        .multipart(form)
        .send()
        .await
        .expect("POST ingest");
    assert!(
        resp.status() == 200 || resp.status() == 201,
        "ingest setup failed: {}",
        resp.status()
    );
    resp.json::<Value>().await.expect("JSON")["commit_id"]
        .as_str()
        .expect("commit_id")
        .to_owned()
}

#[tokio::test]
async fn link_rejects_wrong_original_chunk_count() {
    let h = common::boot().await;
    let resp = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/redaction/link"),
        &json!({
            "original_commit_id": "0xwhatever",
            "original_chunks": ["aa"],          // not 64
            "redacted_chunks": chunks_64(),
        }),
    )
    .await;
    assert_eq!(resp.status(), 422);
}

#[tokio::test]
async fn link_rejects_wrong_redacted_chunk_count() {
    let h = common::boot().await;
    let resp = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/redaction/link"),
        &json!({
            "original_commit_id": "0xwhatever",
            "original_chunks": chunks_64(),
            "redacted_chunks": ["bb", "cc"],    // not 64
        }),
    )
    .await;
    assert_eq!(resp.status(), 422);
}

#[tokio::test]
async fn link_unknown_commit_is_404() {
    let h = common::boot().await;
    // Well-formed 64+64 chunks but a commit_id that isn't in the ledger.
    let resp = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/redaction/link"),
        &json!({
            "original_commit_id": format!("0x{}", common::unique_id("missing")),
            "original_chunks": chunks_64(),
            "redacted_chunks": chunks_64(),
        }),
    )
    .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn link_all_identical_chunks_is_422() {
    let h = common::boot().await;
    let commit_id = ingest_commit(h).await;
    // original == redacted → "no redaction detected" → 422.
    let resp = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/redaction/link"),
        &json!({
            "original_commit_id": commit_id,
            "original_chunks": chunks_64(),
            "redacted_chunks": chunks_64(),
        }),
    )
    .await;
    assert_eq!(resp.status(), 422);
}

#[tokio::test]
async fn link_happy_path_computes_mask_and_counts() {
    let h = common::boot().await;
    let commit_id = ingest_commit(h).await;

    let original = chunks_64();
    // Redact the first 4 chunks: replace them with different valid hex.
    let mut redacted = original.clone();
    for (i, slot) in redacted.iter_mut().enumerate().take(4) {
        *slot = format!("{:064x}", 0xdead_0000u32 + i as u32);
    }

    let resp = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/redaction/link"),
        &json!({
            "original_commit_id": commit_id,
            "original_chunks": original,
            "redacted_chunks": redacted,
        }),
    )
    .await;
    assert_eq!(resp.status(), 200, "expected 200 from /redaction/link");
    let body: Value = resp.json().await.expect("JSON");
    assert_eq!(body["verified"], Value::Bool(true));
    assert_eq!(body["redacted_count"].as_u64(), Some(4));
    assert_eq!(body["revealed_count"].as_u64(), Some(60));
    // reveal_mask is 1 for unchanged chunks, 0 for the 4 redacted ones.
    let mask = body["reveal_mask"].as_array().expect("reveal_mask");
    assert_eq!(mask.len(), 64);
    assert_eq!(mask[0].as_u64(), Some(0), "redacted chunk → mask 0");
    assert_eq!(mask[10].as_u64(), Some(1), "unchanged chunk → mask 1");
    assert!(body["original_root"].is_string());
    assert!(body["redacted_commitment"].is_string());
}

// ── /redaction/issue — auth + validation only (no proving) ────────────────────

#[tokio::test]
async fn issue_without_auth_is_401() {
    let h = common::boot().await;
    let resp = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/redaction/issue"),
        &json!({ "content_hash": "ab", "reveal_mask": [1], "recipient_id": "1" }),
    )
    .await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn issue_rejects_bad_content_hash() {
    let h = common::boot().await;
    // Admin bootstrap key passes the scope gate; a non-hex content_hash is
    // rejected at validation (422) before any proving machinery runs.
    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/redaction/issue"),
        &h.api_key,
        &json!({
            "content_hash": "not-a-valid-hash",
            "reveal_mask": [1, 0, 1],
            "recipient_id": "1",
        }),
    )
    .await;
    assert_eq!(resp.status(), 422);
}

#[tokio::test]
async fn issue_rejects_wrong_mask_length() {
    let h = common::boot().await;
    // Valid 64-hex content_hash, but a mask of the wrong length → 422
    // (before proving). The exact MAX_LEAVES doesn't matter — 3 is wrong.
    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/redaction/issue"),
        &h.api_key,
        &json!({
            "content_hash": format!("{:064x}", 1),
            "reveal_mask": [1, 0, 1],
            "recipient_id": "1",
        }),
    )
    .await;
    assert_eq!(resp.status(), 422);
}
