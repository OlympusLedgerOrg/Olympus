//! HTTP integration coverage for the account signing-key scope gates
//! (`src-tauri/src/api/keys.rs`).
//!
//! Audit M-2: register / list / revoke of account signing keys previously
//! accepted any authenticated key regardless of scope. They now require the
//! same capability as the rest of the API (`write` for mutations, `read` for
//! the listing), enforced *before* any possession-proof validation.
//!
//! The `register_list_revoke_round_trip` test below is the systemic gate the
//! audit recommended: a real pg_embed round-trip per `FromRow` read endpoint.
//! It exists because the `/key/signing/*` handlers shipped 500ing on *every*
//! call — `SigningKeyRow` decoded `VARCHAR(36)` / `TIMESTAMPTZ` columns into
//! `Uuid` / `NaiveDateTime`, which sqlx 0.9 rejects, and the binds encoded
//! `Uuid`s against `VARCHAR` columns. None of the M-2 scope-gate tests caught
//! it: they all stop at the 403 scope check, before any SQL runs. Asserting
//! `2xx` on the happy path is what keeps the next VARCHAR-vs-Uuid column from
//! shipping green.

use crate::common;

use serde_json::{json, Value};

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

/// Build the canonical Ed25519 possession-proof signature for a signing-key
/// registration. Mirrors `keys::common::signing_key_binding_payload`: the JSON
/// `{"domain":…,"label":…,"public_key":…,"purpose":…}` with keys
/// lexicographically sorted and no whitespace. The handler lowercases the
/// public key and trims the label *before* verifying, so callers must pass the
/// already-normalized forms here.
fn possession_proof(
    signing_key: &ed25519_dalek::SigningKey,
    pk_hex: &str,
    label: &str,
    purpose: &str,
) -> String {
    use ed25519_dalek::Signer;
    // All four values are plain strings with no JSON-special characters, so
    // manual construction is byte-identical to serde's BTreeMap serialization.
    let message = format!(
        r#"{{"domain":"OLYMPUS:SIGNING_KEY_BINDING:V1","label":"{label}","public_key":"{pk_hex}","purpose":"{purpose}"}}"#
    );
    hex::encode(signing_key.sign(message.as_bytes()).to_bytes())
}

/// Full happy-path round-trip with a `read`+`write` key: register → list →
/// idempotent re-register → revoke → list. Every step asserts `2xx`, so any
/// re-introduction of the `VARCHAR`/`TIMESTAMPTZ` decode-or-bind mismatch (which
/// 500s the whole route family) fails this test instead of shipping.
#[tokio::test]
async fn register_list_revoke_round_trip() {
    let h = common::boot().await;

    // A role='user' account (second registration), then a read+write key
    // minted for it via the operator path — the default registration scopes
    // are read+verify (no `write`), and registration alone can't grant it.
    let _first = common::register_user(h, "rt-first").await;
    let (user_id, _user_key) = common::register_user(h, "rt-user").await;
    let mint = common::post_admin_json(
        &h.client,
        &common::url(h, &format!("/admin/users/{user_id}/keys")),
        &h.admin_key,
        &json!({ "name": "rt-read-write", "scopes": ["read", "write"] }),
    )
    .await;
    assert_eq!(
        mint.status(),
        200,
        "operator mint of a read+write key should succeed"
    );
    let key = mint.json::<Value>().await.expect("mint JSON")["raw_key"]
        .as_str()
        .expect("raw_key")
        .to_owned();

    // Fresh Ed25519 keypair → unique public key, so this test never collides
    // on the `account_signing_keys.public_key` UNIQUE index across the shared
    // DB / repeated runs.
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let pk_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let label = "round-trip";
    let purpose = "dataset";
    let proof = possession_proof(&signing_key, &pk_hex, label, purpose);

    // ── Register (201) — exercises the INSERT binds. ──────────────────────────
    let reg = common::post_json_with_key(
        &h.client,
        &common::url(h, "/key/signing"),
        &key,
        &json!({
            "public_key": pk_hex,
            "label": label,
            "purpose": purpose,
            "proof_signature": proof,
        }),
    )
    .await;
    assert_eq!(
        reg.status(),
        201,
        "register signing key should be 201, not 500"
    );
    let reg_body: Value = reg.json().await.expect("register JSON");
    let key_id = reg_body["key_id"].as_str().expect("key_id").to_owned();
    assert_eq!(reg_body["user_id"].as_str(), Some(user_id.as_str()));
    assert_eq!(reg_body["public_key"].as_str(), Some(pk_hex.as_str()));
    assert!(
        reg_body["revoked_at"].is_null(),
        "freshly registered key is not revoked"
    );
    assert!(
        !reg_body["created_at"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "created_at must serialize to a non-empty timestamp"
    );

    // ── List (200) — exercises the `SigningKeyRow` FromRow decode (defect #1). ─
    let list = common::get_with_key(&h.client, &common::url(h, "/key/signing"), &key).await;
    assert_eq!(
        list.status(),
        200,
        "list signing keys should be 200, not 500"
    );
    let rows: Vec<Value> = list.json().await.expect("list JSON");
    assert!(
        rows.iter()
            .any(|r| r["key_id"].as_str() == Some(key_id.as_str())),
        "registered key must appear in the listing; got {rows:#?}"
    );

    // ── Idempotent re-register (200) — decodes the existing row + compares the
    //    String user_id against the caller's. ──────────────────────────────────
    let again = common::post_json_with_key(
        &h.client,
        &common::url(h, "/key/signing"),
        &key,
        &json!({
            "public_key": pk_hex,
            "label": label,
            "purpose": purpose,
            "proof_signature": proof,
        }),
    )
    .await;
    assert_eq!(
        again.status(),
        200,
        "re-registering the same key is an idempotent 200"
    );
    assert_eq!(
        again.json::<Value>().await.expect("re-register JSON")["key_id"].as_str(),
        Some(key_id.as_str()),
        "idempotent re-register returns the existing row"
    );

    // ── Revoke (200) — SELECT decode + UPDATE binds (defects #1 + #2). ────────
    let revoke = common::delete_with_key(
        &h.client,
        &common::url(h, &format!("/key/signing/{key_id}")),
        &key,
    )
    .await;
    assert_eq!(
        revoke.status(),
        200,
        "revoke signing key should be 200, not 500"
    );
    let revoke_body: Value = revoke.json().await.expect("revoke JSON");
    assert!(
        !revoke_body["revoked_at"].is_null(),
        "revoked key must carry a revoked_at timestamp"
    );

    // ── List again — the row now decodes with a non-null revoked_at. ──────────
    let list2 = common::get_with_key(&h.client, &common::url(h, "/key/signing"), &key).await;
    assert_eq!(list2.status(), 200);
    let rows2: Vec<Value> = list2.json().await.expect("list JSON");
    let revoked = rows2
        .iter()
        .find(|r| r["key_id"].as_str() == Some(key_id.as_str()))
        .expect("revoked key still listed");
    assert!(
        !revoked["revoked_at"].is_null(),
        "listing must reflect the revocation; got {revoked:#?}"
    );
}
