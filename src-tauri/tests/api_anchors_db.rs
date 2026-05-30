//! HTTP integration coverage for `src-tauri/src/anchoring/api.rs`.
//!
//! Replaces the route-level subset of the deleted `test_anchors_coverage.py`.
//! No outbound TSA / Rekor / OTS calls are made — these tests cover the
//! read endpoints' auth gating, the empty-list shape, and 404s. Anchor
//! *submission* happens on checkpoint build, not via these routes, so an
//! empty `anchor_receipts` table is the expected fresh-DB state.

mod common;

use serde_json::Value;

/// A well-formed UUID guaranteed absent from a fresh `anchor_receipts`
/// table (anchors are only inserted on checkpoint build, which these
/// tests never trigger). Constant is fine — the lookups are read-only.
const MISSING_ANCHOR_ID: &str = "00000000-0000-4000-8000-00000000dead";

#[tokio::test]
async fn list_anchors_empty_ok() {
    let h = common::boot().await;
    let resp = common::get_with_key(&h.client, &common::url(h, "/anchors"), &h.api_key).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("JSON");
    let anchors = body["anchors"].as_array().expect("anchors array");
    // Fresh DB: no checkpoints anchored yet.
    assert!(
        anchors.is_empty(),
        "expected no anchors on a fresh DB, got {}",
        anchors.len()
    );
}

#[tokio::test]
async fn list_anchors_honours_limit_param() {
    let h = common::boot().await;
    let resp =
        common::get_with_key(&h.client, &common::url(h, "/anchors?limit=5"), &h.api_key).await;
    assert_eq!(resp.status(), 200);
    assert!(resp.json::<Value>().await.expect("JSON")["anchors"].is_array());
}

#[tokio::test]
async fn list_anchors_without_auth_is_401() {
    let h = common::boot().await;
    let resp = h
        .client
        .get(common::url(h, "/anchors"))
        .send()
        .await
        .expect("GET");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn get_unknown_anchor_json_is_404() {
    let h = common::boot().await;
    let resp = common::get_with_key(
        &h.client,
        &common::url(h, &format!("/anchors/{MISSING_ANCHOR_ID}")),
        &h.api_key,
    )
    .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn get_unknown_anchor_receipt_is_404() {
    let h = common::boot().await;
    let resp = common::get_with_key(
        &h.client,
        &common::url(h, &format!("/anchors/{MISSING_ANCHOR_ID}/receipt")),
        &h.api_key,
    )
    .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn get_anchor_with_malformed_uuid_is_4xx() {
    let h = common::boot().await;
    // Path type is `Uuid`; a non-UUID segment fails extraction → 400.
    let resp = common::get_with_key(
        &h.client,
        &common::url(h, "/anchors/not-a-uuid"),
        &h.api_key,
    )
    .await;
    let s = resp.status().as_u16();
    assert!(
        (400..500).contains(&s),
        "malformed UUID should be 4xx, got {s}"
    );
}
