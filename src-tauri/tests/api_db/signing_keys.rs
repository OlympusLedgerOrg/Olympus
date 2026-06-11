//! HTTP integration coverage for the account signing-key scope gates
//! (`src-tauri/src/api/keys.rs`).
//!
//! Audit M-2: register / list / revoke of account signing keys previously
//! accepted any authenticated key regardless of scope. They now require the
//! same capability as the rest of the API (`write` for mutations, `read` for
//! the listing), enforced *before* any possession-proof validation.

use crate::common;

use serde_json::json;

#[tokio::test]
async fn read_verify_key_cannot_register_signing_key() {
    let h = common::boot().await;

    // Guaranteed read/verify, role='user' account (second registration).
    let _first = common::register_user(h, "m2-first").await;
    let (_uid, key) = common::register_user(h, "m2-readverify").await;

    // POST /key/signing requires `write`. A read/verify key is rejected at
    // the scope gate, before the Ed25519 possession proof is examined — so a
    // syntactically-valid-but-unsigned body still yields 403, not 422/400.
    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/key/signing"),
        &key,
        &json!({
            "public_key": "00".repeat(32),
            "label": "test-key",
            "purpose": "signing",
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        403,
        "read/verify key must not register a signing key (M-2)"
    );
}

#[tokio::test]
async fn read_verify_key_cannot_delete_signing_key() {
    let h = common::boot().await;

    let _first = common::register_user(h, "m2del-first").await;
    let (_uid, key) = common::register_user(h, "m2del-readverify").await;

    // DELETE /key/signing/{id} requires `write`; a read/verify key is rejected
    // at the scope gate, which runs before the row lookup — so a well-formed
    // but nonexistent key_id still yields 403 (gate fired), not 404.
    let resp = common::delete_with_key(
        &h.client,
        &common::url(h, "/key/signing/00000000-0000-0000-0000-000000000000"),
        &key,
    )
    .await;
    assert_eq!(
        resp.status(),
        403,
        "read/verify key must not delete a signing key (M-2)"
    );
}

#[tokio::test]
async fn verify_only_key_cannot_list_signing_keys() {
    let h = common::boot().await;

    // GET /key/signing requires `read`. The default registration scopes
    // (read + verify) *do* satisfy that, so to exercise the gate we need a
    // key without `read`: the operator mints a `verify`-only key for a
    // role='user' account via the x-admin-key path.
    let _first = common::register_user(h, "m2list-first").await;
    let (user_id, _user_key) = common::register_user(h, "m2list-user").await;

    let mint = common::post_admin_json(
        &h.client,
        &common::url(h, &format!("/admin/users/{user_id}/keys")),
        &h.admin_key,
        &json!({ "name": "m2-verify-only", "scopes": ["verify"] }),
    )
    .await;
    assert_eq!(
        mint.status(),
        200,
        "operator mint of a verify-only key should succeed"
    );
    let verify_key = mint.json::<serde_json::Value>().await.expect("mint JSON")["raw_key"]
        .as_str()
        .expect("raw_key")
        .to_owned();

    let resp = common::get_with_key(&h.client, &common::url(h, "/key/signing"), &verify_key).await;
    assert_eq!(
        resp.status(),
        403,
        "verify-only key (no 'read') must not list signing keys (M-2)"
    );
}
