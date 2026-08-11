// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Authority-key registry + rotation (migration 0056, docs/key-rotation.md).
//!
//! Exercises `bootstrap::rotate_authority` — the sanctioned supersession
//! entry point reached from the env tier under
//! `OLYMPUS_AUTHORITY_ROTATION=confirm` — directly against the shared
//! cluster, plus the registry-driven trusted-issuer loader and the
//! single-active-authority index. The running server's in-memory issuer set
//! is intentionally untouched by registry writes (it is rebuilt at startup),
//! so post-rotation *resolution* semantics are asserted through
//! `TrustedIssuer::covers` on the freshly-loaded set, not through HTTP.

use crate::common;

use olympus_tauri_lib::api::trusted_issuers::load_trusted_issuers_with_registry;
use olympus_tauri_lib::bootstrap::rotate_authority;
use olympus_tauri_lib::zk::witness::baby_jubjub::BabyJubJubPubKey;
use serde_json::{json, Value};
use sqlx::PgPool;

async fn active_authority(pool: &PgPool) -> (String, String, String) {
    let (id, x, y): (String, String, String) = sqlx::query_as(
        "SELECT key_id, bjj_pubkey_x, bjj_pubkey_y FROM account_signing_keys
          WHERE purpose = 'authority' AND revoked_at IS NULL",
    )
    .fetch_one(pool)
    .await
    .expect("exactly one active authority row");
    (id, x, y)
}

#[tokio::test]
async fn rotate_authority_supersedes_append_only_and_windows_history() {
    let h = common::boot().await;
    let pool = PgPool::connect(&h.database_url).await.expect("pool");

    // A credential issued under the CURRENT authority, pre-rotation. Its
    // issued_at must stay inside the retired key's registry window later.
    let issue = common::post_json_with_key(
        &h.client,
        &common::url(h, "/credentials"),
        &h.api_key,
        &json!({
            "holder_key": common::unique_id("holder-rotation"),
            "credential_type": "court_observer",
        }),
    )
    .await;
    assert_eq!(issue.status(), 201);
    let issued: Value = issue.json().await.expect("JSON");
    let cred_id = issued["id"].as_str().expect("id").to_owned();
    let issued_unix = chrono::DateTime::parse_from_rfc3339(issued["issued_at"].as_str().unwrap())
        .expect("issued_at")
        .timestamp();

    let (old_id, old_x, old_y) = active_authority(&pool).await;

    // Rotate to key B, then to key C — the chain must stay append-only.
    let pk_b = BabyJubJubPubKey::from_private(&[0x5A; 32]).expect("key B");
    let b_id = rotate_authority(&pool, &pk_b).await.expect("rotate to B");

    /// `(revoked_at, valid_until, replaced_by_key_id, bjj_pubkey_x)`.
    type PredecessorRow = (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        String,
    );
    let row: PredecessorRow = sqlx::query_as(
        "SELECT revoked_at, valid_until, replaced_by_key_id, bjj_pubkey_x
               FROM account_signing_keys WHERE key_id = $1",
    )
    .bind(&old_id)
    .fetch_one(&pool)
    .await
    .expect("old row still present");
    assert!(row.0.is_some(), "predecessor must be revoked, not deleted");
    assert!(
        row.1.is_some(),
        "predecessor must be windowed (valid_until)"
    );
    assert_eq!(
        row.2.as_deref(),
        Some(b_id.as_str()),
        "supersession chain must link old → new"
    );
    assert_eq!(row.3, old_x, "historical pubkey must never be rewritten");

    let (active_id, _, _) = active_authority(&pool).await;
    assert_eq!(active_id, b_id, "successor must be the single active row");

    let pk_c = BabyJubJubPubKey::from_private(&[0x5B; 32]).expect("key C");
    let c_id = rotate_authority(&pool, &pk_c).await.expect("rotate to C");
    let (active_id, _, _) = active_authority(&pool).await;
    assert_eq!(active_id, c_id, "second rotation must chain");

    // The migration's partial unique index: a second ACTIVE authority row is
    // structurally impossible.
    let dup = sqlx::query(
        "INSERT INTO account_signing_keys
             (key_id, user_id, public_key, label, purpose, created_at)
         VALUES ($1, '00000000-0000-0000-0000-000000000001', '', 'dup', 'authority', NOW())",
    )
    .bind(common::unique_id("dup-authority"))
    .execute(&pool)
    .await;
    let err = format!(
        "{:?}",
        dup.expect_err("second active authority must be rejected")
    );
    assert!(
        err.contains("ix_account_signing_keys_single_active_authority"),
        "rejection must come from the single-active-authority index: {err}"
    );

    // Registry-driven trusted issuers: the retired original key must cover
    // the pre-rotation credential's issued_at but not the post-rotation
    // future; the active key C must cover now but not the distant past.
    let issuers = load_trusted_issuers_with_registry(None, Some(&pool)).await;
    let now = chrono::Utc::now().timestamp();
    let original = issuers
        .iter()
        .find(|t| t.x_dec == old_x && t.y_dec == old_y)
        .expect("retired original key must be in the registry-driven set");
    assert!(
        original.covers(issued_unix),
        "retired key window must cover its pre-rotation credential"
    );
    assert!(
        !original.covers(now + 86_400),
        "retired key must not cover the post-rotation future"
    );
    let active = issuers
        .iter()
        .find(|t| t.covers(now) && !t.covers(0))
        .expect("active key must be windowed from its rotation moment");
    assert!(
        active.x_dec != old_x || active.y_dec != old_y,
        "the now-covering bounded entry must be a successor, not the original"
    );

    // Key reuse (A→B→A shape): rotate back to B — the registry then holds
    // two disjoint intervals for B's coordinates. Every consumer scans the
    // whole set with `covers`, so both must surface, and the loader called
    // the way startup calls it (with the active primary) must tighten the
    // primary entry to the active registry window instead of leaving it
    // unbounded.
    rotate_authority(&pool, &pk_b)
        .await
        .expect("rotate back to B");
    let issuers = load_trusted_issuers_with_registry(Some(&pk_b), Some(&pool)).await;
    let now = chrono::Utc::now().timestamp();
    assert!(
        !issuers[0].covers(0),
        "active primary must not cover pre-adoption history (tightened window)"
    );
    assert!(issuers[0].covers(now), "active primary must cover now");
    let (bx, by) = (issuers[0].x_dec.clone(), issuers[0].y_dec.clone());
    let b_entries: Vec<_> = issuers
        .iter()
        .filter(|t| t.x_dec == bx && t.y_dec == by)
        .collect();
    assert_eq!(
        b_entries.len(),
        2,
        "re-adopted key must keep both registry intervals"
    );
    assert_eq!(
        b_entries.iter().filter(|t| t.covers(now + 86_400)).count(),
        1,
        "exactly one B interval may extend into the future"
    );

    // The pre-rotation credential row is untouched by rotation: the running
    // server (whose in-memory issuer set still anchors the original key)
    // must keep verifying it.
    let verify = common::post_json_with_key(
        &h.client,
        &common::url(h, &format!("/credentials/{cred_id}/verify")),
        &h.api_key,
        &json!({}),
    )
    .await;
    assert_eq!(verify.status(), 200);
    let verdict: Value = verify.json().await.expect("JSON");
    assert_eq!(
        verdict["valid"].as_bool(),
        Some(true),
        "pre-rotation credential must remain valid: {verdict}"
    );
}
