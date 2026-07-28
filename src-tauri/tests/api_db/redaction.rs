//! HTTP integration coverage for `src-tauri/src/api/redaction.rs`.
//!
//! Covers the object-level producer (ADR-0030 V3 signed-Merkle bundle):
//! * `POST /redaction/redact` (auth) — auth/scope gating + the cheap input
//!   guards (invalid base64, unknown document). The full bundle-assembly path
//!   is NOT exercised here (it needs a committed object manifest + the blind /
//!   signing keys, covered by the `zk::segment` + `bundle_v3` unit suites);
//!   these pin the cheap guards. The Groth16 `/redaction/issue` endpoint was
//!   retired in ADR-0030 (no recipient-verifiable artifact); the chunk-era
//!   `/redaction/link` endpoint was removed earlier in ADR-0026.
//! * `POST /redaction/describe` (auth) — was untested for authentication
//!   entirely (ADR-0036 scope-matrix follow-up): `redact` and `manifest`
//!   both had a `_without_auth_is_401` case, `describe` did not.
//! * All three of the above (`describe`, `redact`, `manifest`) share the same
//!   `require_redact_scope` gate (`redact`/`write`/`ingest`/`admin`, ADR-0036
//!   scope-matrix follow-up) — none of the existing tests proved the gate
//!   actually discriminates by scope rather than just requiring *some* valid
//!   key, so a key with only `read`/`verify` was never tried against it.

use crate::common;

use serde_json::json;

// ── POST /redaction/redact — auth + cheap input guards (no bundle assembly) ────

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

#[tokio::test]
async fn redact_rejects_invalid_base64() {
    let h = common::boot().await;
    // Admin bootstrap key passes the scope gate; non-base64 `original_base64` is
    // rejected at validation (422) before any DB/manifest machinery runs.
    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/redaction/redact"),
        &h.api_key,
        &json!({
            "original_base64": "not valid base64 !!!",
            "redacted_obj_ids": [1],
            "recipient_id": "1",
        }),
    )
    .await;
    assert_eq!(resp.status(), 422);
}

#[tokio::test]
async fn redact_unknown_document_is_404() {
    let h = common::boot().await;
    // Well-formed base64 whose BLAKE3 was never ingested → no object manifest →
    // 404 (before any bundle assembly). This pins the original_root-keyed lookup
    // path the V3 producer resolves by `content_hash`.
    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/redaction/redact"),
        &h.api_key,
        &json!({
            "original_base64": "AAAAAAAA",
            "redacted_obj_ids": [1],
            "recipient_id": "1",
        }),
    )
    .await;
    assert_eq!(resp.status(), 404);
}

// ── GET /redaction/manifest/:content_hash — auth + lookup ─────────────────────

#[tokio::test]
async fn manifest_without_auth_is_401() {
    let h = common::boot().await;
    let resp = h
        .client
        .get(common::url(h, &format!("/redaction/manifest/{:064x}", 1)))
        .send()
        .await
        .expect("GET manifest");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn manifest_unknown_document_is_404() {
    let h = common::boot().await;
    // Well-formed but never-ingested content_hash → no object manifest → 404.
    let resp = h
        .client
        .get(common::url(
            h,
            &format!("/redaction/manifest/{:064x}", 0xfeedu32),
        ))
        .header("x-api-key", &h.api_key)
        .send()
        .await
        .expect("GET manifest");
    assert_eq!(resp.status(), 404);
}

// ── POST /redaction/describe — auth (ADR-0036 scope-matrix follow-up) ─────────

#[tokio::test]
async fn describe_without_auth_is_401() {
    let h = common::boot().await;
    let resp = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/redaction/describe"),
        &json!({ "content_hash": "aa".repeat(32), "original_base64": "AAAA" }),
    )
    .await;
    assert_eq!(resp.status(), 401);
}

// ── require_redact_scope actually discriminates by scope ──────────────────────
//
// `describe`/`redact`/`manifest` all gate on the same `require_redact_scope`
// (`redact`/`write`/`ingest`/`admin`). Every existing test above only tries
// "no key at all" — none proves the gate rejects a key that IS valid but
// lacks all four accepted scopes, which is the actual thing `require_scope`
// functions exist to enforce. `common::register_user` mints a `read`+`verify`
// only key (see `credentials.rs`'s identical use for the `admin` gate).
//
// One `#[tokio::test]` per endpoint (not a single combined test) so a
// regression in one endpoint's scope gate can't `assert_eq!`-panic before the
// other two are even exercised, which would hide further breakage in this
// security-relevant path (CodeRabbit review, PR #1502).

#[tokio::test]
async fn describe_rejects_a_key_without_redact_scope() {
    let h = common::boot().await;
    let (_uid, key) = common::register_user(h, "redact-scope-readonly-describe").await;

    let describe = common::post_json_with_key(
        &h.client,
        &common::url(h, "/redaction/describe"),
        &key,
        &json!({ "content_hash": "aa".repeat(32), "original_base64": "AAAA" }),
    )
    .await;
    assert_eq!(
        describe.status(),
        403,
        "read/verify key must not pass POST /redaction/describe's scope gate"
    );
}

#[tokio::test]
async fn redact_rejects_a_key_without_redact_scope() {
    let h = common::boot().await;
    let (_uid, key) = common::register_user(h, "redact-scope-readonly-redact").await;

    let redact = common::post_json_with_key(
        &h.client,
        &common::url(h, "/redaction/redact"),
        &key,
        &json!({ "original_base64": "AAAA", "redacted_obj_ids": [1], "recipient_id": "1" }),
    )
    .await;
    assert_eq!(
        redact.status(),
        403,
        "read/verify key must not pass POST /redaction/redact's scope gate"
    );
}

#[tokio::test]
async fn manifest_rejects_a_key_without_redact_scope() {
    let h = common::boot().await;
    let (_uid, key) = common::register_user(h, "redact-scope-readonly-manifest").await;

    let manifest = common::get_with_key(
        &h.client,
        &common::url(h, &format!("/redaction/manifest/{:064x}", 1)),
        &key,
    )
    .await;
    assert_eq!(
        manifest.status(),
        403,
        "read/verify key must not pass GET /redaction/manifest's scope gate"
    );
}
