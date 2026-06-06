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
