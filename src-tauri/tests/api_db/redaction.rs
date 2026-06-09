//! HTTP integration coverage for `src-tauri/src/api/redaction.rs`.
//!
//! Covers the object-level producer (ADR-0026):
//! * `POST /redaction/issue` (auth) — auth/scope gating + pre-prove input
//!   validation (bad content_hash, unknown document). The full Groth16 prove
//!   path is NOT exercised here (it needs resolved `proofs_dir` + a committed
//!   object manifest, covered by the `zk_prove_*` suite); these pin the cheap
//!   guards. The chunk-era `/redaction/link` endpoint was removed in ADR-0026.

use crate::common;

use serde_json::json;

// ── /redaction/issue — auth + validation only (no proving) ────────────────────

#[tokio::test]
async fn issue_without_auth_is_401() {
    let h = common::boot().await;
    let resp = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/redaction/issue"),
        &json!({ "content_hash": "ab", "redacted_obj_ids": [1], "recipient_id": "1" }),
    )
    .await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn issue_rejects_bad_content_hash() {
    let h = common::boot().await;
    // Admin bootstrap key passes the scope gate; a non-hex content_hash is
    // rejected at validation (422) before any DB/proving machinery runs.
    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/redaction/issue"),
        &h.api_key,
        &json!({
            "content_hash": "not-a-valid-hash",
            "redacted_obj_ids": [1],
            "recipient_id": "1",
        }),
    )
    .await;
    assert_eq!(resp.status(), 422);
}

#[tokio::test]
async fn issue_unknown_document_is_404() {
    let h = common::boot().await;
    // Well-formed 64-hex content_hash that was never ingested → no object
    // manifest → 404 (before any proving). This pins the new object-level
    // lookup path that replaced the chunk-leaf lookup.
    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/redaction/issue"),
        &h.api_key,
        &json!({
            "content_hash": format!("{:064x}", 0xdead_beefu32),
            "redacted_obj_ids": [1],
            "recipient_id": "1",
        }),
    )
    .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn redact_without_auth_is_401() {
    let h = common::boot().await;
    let resp = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/redaction/redact"),
        &json!({ "original_base64": "AAAA", "redacted_obj_ids": [1], "recipient_id": "1" }),
    )
    .await;
    assert_eq!(resp.status(), 401);
}
