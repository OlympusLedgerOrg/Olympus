// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! `src-tauri/src/api/monitor/` (ADR-0021 Monitor API) HTTP coverage.
//!
//! `own_checkpoints` rows are inserted **directly via SQL** rather than
//! through `anchoring::own_checkpoint::build_and_persist` — that function
//! always checkpoints "the globally latest `ingest_records` row across the
//! whole database" (`ORDER BY ts DESC LIMIT 1`, no per-shard filter), which
//! would race every other concurrently-running test in this shared binary
//! that also ingests. Direct SQL inserts give each test full, deterministic
//! control over `shard_id`/`tree_size`/`checkpoint_timestamp` with zero
//! cross-test interference — the same reasoning `checkpoint_transition_
//! attestation.rs` documents for its own manual `ingest_records` inserts,
//! applied here to `own_checkpoints`. `/monitor/proof` needs no checkpoint
//! at all (it only reads the record's own frozen snapshot columns), so its
//! tests ingest a real file through `/ingest/files` like any other test here.

use crate::common;

use reqwest::multipart::{Form, Part};
use serde_json::Value;
use sqlx::PgPool;

fn file_form(shard_id: &str, body: &str) -> Form {
    Form::new()
        .part(
            "file",
            Part::bytes(body.as_bytes().to_vec()).file_name("test.txt"),
        )
        .text("shard_id", shard_id.to_owned())
}

async fn ingest_file(h: &common::TestHarness, shard_id: &str, body: &str) -> Value {
    let resp = h
        .client
        .post(common::url(h, "/ingest/files"))
        .header("x-api-key", &h.api_key)
        .multipart(file_form(shard_id, body))
        .send()
        .await
        .expect("POST /ingest/files");
    assert_eq!(resp.status(), 201, "file ingest must succeed");
    resp.json().await.expect("ingest JSON")
}

async fn register_shard(h: &common::TestHarness, shard_id: &str) {
    let resp = h
        .client
        .post(common::url(h, "/admin/shards"))
        .header("x-admin-key", &h.admin_key)
        .json(&serde_json::json!({ "shard_id": shard_id }))
        .send()
        .await
        .expect("POST /admin/shards");
    assert!(
        resp.status() == 201 || resp.status() == 409,
        "register_shard: unexpected status {}",
        resp.status()
    );
}

/// A minimal, schema-valid `own_checkpoints` row with placeholder (but
/// non-NULL, satisfying the monitor list/latest/covering queries'
/// `sig_* IS NOT NULL` filter) signature fields. This module never asserts
/// on signature *validity* — that is `own_checkpoint.rs`'s / `anchoring`'s
/// own test suite's job — only on whether the Monitor API serves and scopes
/// rows correctly.
async fn insert_checkpoint(
    pool: &PgPool,
    shard_id: &str,
    tree_size: i64,
    checkpoint_timestamp: i64,
) {
    sqlx::query(
        "INSERT INTO own_checkpoints
             (format_version, checkpoint_scope, shard_id, ledger_root, tree_size,
              checkpoint_timestamp, authority_pubkey_hash, authority_pubkey_x,
              authority_pubkey_y, sig_r8x, sig_r8y, sig_s, anchor_hash)
         VALUES (2, 'shard', $1, $2, $3, $4, 'ph', 'ph', 'ph', 'ph', 'ph', 'ph', $5)",
    )
    .bind(shard_id)
    .bind(format!("{tree_size}")) // ledger_root: placeholder decimal-shaped string
    .bind(tree_size)
    .bind(checkpoint_timestamp)
    .bind(vec![0u8; 32])
    .execute(pool)
    .await
    .expect("insert placeholder own_checkpoints row");
}

// ── GET /monitor/checkpoints, /monitor/checkpoints/latest ──────────────────

#[tokio::test]
async fn checkpoints_latest_and_list_scope_by_shard_newest_first() {
    let h = common::boot().await;
    let pool = PgPool::connect(&h.database_url).await.expect("pool");
    let shard = common::unique_id("monitor-cp");

    // No checkpoint yet for this never-before-seen shard.
    let resp = h
        .client
        .get(common::url(
            h,
            &format!("/monitor/checkpoints/latest?shard_id={shard}"),
        ))
        .send()
        .await
        .expect("GET latest (none yet)");
    assert_eq!(resp.status(), 404);

    insert_checkpoint(&pool, &shard, 10, 1_700_000_000).await;
    insert_checkpoint(&pool, &shard, 20, 1_700_000_100).await;
    insert_checkpoint(&pool, &shard, 30, 1_700_000_200).await;
    // A different shard's row must never leak into this shard's results.
    let other_shard = common::unique_id("monitor-cp-other");
    insert_checkpoint(&pool, &other_shard, 999, 1_700_000_999).await;

    let resp = h
        .client
        .get(common::url(
            h,
            &format!("/monitor/checkpoints/latest?shard_id={shard}"),
        ))
        .send()
        .await
        .expect("GET latest");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("JSON");
    assert_eq!(body["treeSize"], 30, "latest must be the newest tree_size");
    assert_eq!(body["checkpointTimestamp"], 1_700_000_200);
    assert_eq!(body["shardId"], shard);

    let resp = h
        .client
        .get(common::url(
            h,
            &format!("/monitor/checkpoints?shard_id={shard}&limit=2"),
        ))
        .send()
        .await
        .expect("GET list");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("JSON");
    let checkpoints = body["checkpoints"].as_array().expect("checkpoints array");
    assert_eq!(checkpoints.len(), 2, "limit=2 must cap the result");
    assert_eq!(checkpoints[0]["treeSize"], 30, "list must be newest-first");
    assert_eq!(checkpoints[1]["treeSize"], 20);
    assert!(
        checkpoints.iter().all(|c| c["shardId"] == shard),
        "no other shard's row may appear: {checkpoints:?}"
    );
}

#[tokio::test]
async fn checkpoints_reject_malformed_shard_id() {
    let h = common::boot().await;

    let resp = h
        .client
        .get(common::url(
            h,
            "/monitor/checkpoints/latest?shard_id=has%20a%20space",
        ))
        .send()
        .await
        .expect("GET with bad shard_id");
    assert_eq!(resp.status(), 422);
}

// ── GET /monitor/proof/{content_hash} ───────────────────────────────────────

#[tokio::test]
async fn proof_serves_an_independently_verifiable_witness() {
    let h = common::boot().await;
    let shard = common::unique_id("monitor-proof");
    register_shard(h, &shard).await;

    let body = common::unique_id("monitor-proof-body");
    let ingested = ingest_file(h, &shard, &body).await;
    let content_hash = ingested["content_hash"]
        .as_str()
        .expect("contentHash")
        .to_owned();

    let resp = h
        .client
        .get(common::url(h, &format!("/monitor/proof/{content_hash}")))
        .send()
        .await
        .expect("GET proof");
    assert_eq!(resp.status(), 200, "body: {:?}", resp.text().await);
    let proof: Value = {
        let resp = h
            .client
            .get(common::url(h, &format!("/monitor/proof/{content_hash}")))
            .send()
            .await
            .expect("GET proof (re-fetch for JSON)");
        resp.json().await.expect("JSON")
    };

    assert_eq!(proof["contentHash"], content_hash);
    assert_eq!(proof["shardId"], shard);
    assert_eq!(
        proof["serverReportsValid"], true,
        "a freshly ingested record's own witness must self-verify: {proof:?}"
    );
    let path_elements = proof["pathElementsHex"].as_array().expect("path array");
    assert_eq!(
        path_elements.len(),
        20,
        "SNAPSHOT_DEPTH is 20 — every witness must carry exactly that many siblings"
    );
    let path_indices = proof["pathIndices"].as_array().expect("indices array");
    assert_eq!(path_indices.len(), 20);

    // Independent re-verification: the offline crypto primitive, not this
    // server's own verdict, using the harness's authority pubkey directly.
    let snapshot = olympus_crypto::ledger_snapshot::LedgerSnapshot {
        snapshot_root: proof["snapshotRoot"].as_str().unwrap().to_owned(),
        snapshot_index: proof["snapshotIndex"].as_u64().unwrap(),
        snapshot_size: proof["snapshotSize"].as_u64().unwrap(),
        path_elements_hex: path_elements
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect(),
        path_indices: path_indices
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect(),
        signature_r8x: proof["signatureR8x"].as_str().unwrap().to_owned(),
        signature_r8y: proof["signatureR8y"].as_str().unwrap().to_owned(),
        signature_s: proof["signatureS"].as_str().unwrap().to_owned(),
        signed_at_unix: proof["signedAtUnix"].as_i64(),
    };
    let original_root = proof["originalRoot"].as_str().unwrap();
    assert!(
        olympus_crypto::ledger_snapshot::verify_snapshot(
            &snapshot,
            &content_hash,
            original_root,
            h.bjj_authority_pubkey.x,
            h.bjj_authority_pubkey.y,
        ),
        "the served witness must independently verify against the harness's own authority key"
    );
}

#[tokio::test]
async fn proof_rejects_malformed_hash_and_404s_on_unknown_hash() {
    let h = common::boot().await;

    let resp = h
        .client
        .get(common::url(h, "/monitor/proof/not-a-hash"))
        .send()
        .await
        .expect("GET malformed hash");
    assert_eq!(resp.status(), 422);

    let unknown = "ab".repeat(32);
    let resp = h
        .client
        .get(common::url(h, &format!("/monitor/proof/{unknown}")))
        .send()
        .await
        .expect("GET unknown hash");
    assert_eq!(resp.status(), 404);
}

// ── GET /monitor/proof/blake3/{content_hash} ────────────────────────────────

/// Reduce a 32-byte digest into the BJJ-EdDSA message scalar, mirroring
/// `anchoring::own_checkpoint::digest_to_subgroup_scalar` (private, so this
/// test replicates the "mod l then map into Fr" recipe rather than exercising
/// it directly — the point of this test is independent verification, not
/// reuse of the producer's own reduction code).
fn digest_to_subgroup_scalar(digest: &[u8; 32]) -> ark_bn254::Fr {
    use ark_ff::PrimeField;
    let l: num_bigint::BigUint = olympus_tauri_lib::zk::witness::baby_jubjub::BABYJ_SUBGROUP_ORDER
        .parse()
        .expect("static decimal");
    let reduced = num_bigint::BigUint::from_bytes_be(digest) % l;
    ark_bn254::Fr::from_le_bytes_mod_order(&reduced.to_bytes_le())
}

/// Insert an `own_checkpoints` row carrying a **real, verifiable**
/// `SmtRootAttestation` for `shard_id`'s *actual* current persisted BLAKE3
/// subtree root — signed with the test harness's own BJJ authority key, the
/// same key `/monitor/proof/blake3` checks incoming attestations against via
/// `state.bjj_trusted_issuers`. Returns the signed `blake3_smt_root` hex so
/// callers can assert on it.
async fn insert_checkpoint_with_smt_attestation(
    h: &common::TestHarness,
    pool: &PgPool,
    shard_id: &str,
    tree_size: i64,
    checkpoint_timestamp: i64,
) -> String {
    use olympus_tauri_lib::smt::{backend::PgBackend, tree::PersistentSmt};

    let tree = PersistentSmt::open_deferred(PgBackend::new(pool.clone()));
    let shard_root = tree
        .shard_subtree_root(shard_id)
        .await
        .expect("shard_subtree_root");
    // `own_checkpoints.ledger_root` is stored as hex (unlike `insert_checkpoint`'s
    // decimal-shaped Poseidon placeholder above) because
    // `verify_smt_root_attestation` parses it via `hex_to_bytes32` — this
    // attestation's `ledger_root` value doesn't need to correspond to a real
    // Poseidon root for this test, only to be valid, matching hex on both sides.
    let ledger_root_bytes = [0x42u8; 32];

    let attestation = olympus_crypto::SmtRootAttestation {
        shard_id: shard_id.as_bytes().to_vec(),
        ledger_root: ledger_root_bytes,
        tree_size,
        blake3_smt_root: shard_root,
    };
    let message = digest_to_subgroup_scalar(&attestation.message());
    let sig = olympus_tauri_lib::zk::witness::baby_jubjub::sign(&h.bjj_authority_key, message)
        .expect("sign smt root attestation");

    let shard_root_hex = hex::encode(shard_root);
    let ledger_root_hex = hex::encode(attestation.ledger_root);
    sqlx::query(
        "INSERT INTO own_checkpoints
             (format_version, checkpoint_scope, shard_id, ledger_root, tree_size,
              checkpoint_timestamp, authority_pubkey_hash, authority_pubkey_x,
              authority_pubkey_y, sig_r8x, sig_r8y, sig_s, anchor_hash,
              blake3_smt_root, blake3_smt_sig_r8x, blake3_smt_sig_r8y, blake3_smt_sig_s)
         VALUES (2, 'shard', $1, $2, $3, $4, 'ph', 'ph', 'ph', 'ph', 'ph', 'ph', $5,
                 $6, $7, $8, $9)",
    )
    .bind(shard_id)
    .bind(&ledger_root_hex)
    .bind(tree_size)
    .bind(checkpoint_timestamp)
    .bind(vec![0u8; 32])
    .bind(&shard_root_hex)
    .bind(olympus_tauri_lib::zk::proof::fr_to_decimal(&sig.r8x))
    .bind(olympus_tauri_lib::zk::proof::fr_to_decimal(&sig.r8y))
    .bind(olympus_tauri_lib::zk::proof::fr_to_decimal(&sig.s))
    .execute(pool)
    .await
    .expect("insert own_checkpoints row with smt root attestation");

    shard_root_hex
}

#[tokio::test]
async fn blake3_proof_serves_an_independently_verifiable_witness() {
    let h = common::boot().await;
    let pool = PgPool::connect(&h.database_url).await.expect("pool");
    let shard = common::unique_id("monitor-blake3");
    register_shard(h, &shard).await;

    let body = common::unique_id("monitor-blake3-body");
    let ingested = ingest_file(h, &shard, &body).await;
    let content_hash = ingested["content_hash"]
        .as_str()
        .expect("contentHash")
        .to_owned();

    let shard_root_hex =
        insert_checkpoint_with_smt_attestation(h, &pool, &shard, 1, 1_700_000_000).await;

    let resp = h
        .client
        .get(common::url(
            h,
            &format!("/monitor/proof/blake3/{content_hash}"),
        ))
        .send()
        .await
        .expect("GET blake3 proof");
    assert_eq!(resp.status(), 200, "body: {:?}", resp.text().await);
    let body: Value = {
        let resp = h
            .client
            .get(common::url(
                h,
                &format!("/monitor/proof/blake3/{content_hash}"),
            ))
            .send()
            .await
            .expect("GET blake3 proof (re-fetch for JSON)");
        resp.json().await.expect("JSON")
    };

    assert_eq!(body["contentHash"], content_hash);
    assert_eq!(body["shardId"], shard);
    assert_eq!(body["blake3SmtRoot"], shard_root_hex);
    assert_eq!(
        body["serverReportsValid"], true,
        "a freshly ingested record's own witness must self-verify: {body:?}"
    );

    // Independent re-verification: the offline crypto primitive, not this
    // server's own verdict.
    let proof: olympus_crypto::smt::Proof =
        serde_json::from_value(body["proof"].clone()).expect("proof deserializes");
    let shard_root: [u8; 32] = hex::decode(&shard_root_hex)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    assert!(
        olympus_crypto::smt::verify_proof_against_shard_root(&proof, &shard, &shard_root),
        "served proof must independently fold to the attested shard root"
    );
}

#[tokio::test]
async fn blake3_proof_rejects_malformed_hash_and_404s_on_unknown_hash() {
    let h = common::boot().await;

    let resp = h
        .client
        .get(common::url(h, "/monitor/proof/blake3/not-a-hash"))
        .send()
        .await
        .expect("GET malformed hash");
    assert_eq!(resp.status(), 422);

    let unknown = "cd".repeat(32);
    let resp = h
        .client
        .get(common::url(h, &format!("/monitor/proof/blake3/{unknown}")))
        .send()
        .await
        .expect("GET unknown hash");
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn blake3_proof_503s_when_shard_has_no_attestation_yet() {
    let h = common::boot().await;
    let shard = common::unique_id("monitor-blake3-noattest");
    register_shard(h, &shard).await;

    let body = common::unique_id("monitor-blake3-noattest-body");
    let ingested = ingest_file(h, &shard, &body).await;
    let content_hash = ingested["content_hash"]
        .as_str()
        .expect("contentHash")
        .to_owned();

    // No own_checkpoints row for this shard at all — the record exists and is
    // provable, but nothing has signed a BLAKE3 root covering it yet.
    let resp = h
        .client
        .get(common::url(
            h,
            &format!("/monitor/proof/blake3/{content_hash}"),
        ))
        .send()
        .await
        .expect("GET blake3 proof (no attestation)");
    assert_eq!(resp.status(), 503);
}

// ── GET /monitor/mmd/{content_hash} ─────────────────────────────────────────

#[tokio::test]
async fn mmd_reports_pending_then_covered_within_policy_then_breach() {
    let h = common::boot().await;
    let pool = PgPool::connect(&h.database_url).await.expect("pool");
    let shard = common::unique_id("monitor-mmd");
    register_shard(h, &shard).await;

    let body = common::unique_id("monitor-mmd-body");
    let ingested = ingest_file(h, &shard, &body).await;
    let content_hash = ingested["content_hash"].as_str().unwrap().to_owned();

    // No covering checkpoint exists yet: the record was just ingested, so
    // elapsed time is near-zero and well inside the default 24h MMD.
    let resp = h
        .client
        .get(common::url(h, &format!("/monitor/mmd/{content_hash}")))
        .send()
        .await
        .expect("GET mmd (pending)");
    assert_eq!(resp.status(), 200);
    let body_json: Value = resp.json().await.expect("JSON");
    assert_eq!(body_json["status"], "pending_within_policy");
    assert!(body_json["firstCoveringCheckpoint"].is_null());
    let snapshot_size = body_json["snapshotSize"].as_i64().expect("snapshotSize");
    let ingested_at = body_json["ingestedAtUnix"]
        .as_i64()
        .expect("ingestedAtUnix");

    // A checkpoint covering this record's snapshot_size, published well
    // within the default MMD.
    insert_checkpoint(&pool, &shard, snapshot_size, ingested_at + 30).await;
    let resp = h
        .client
        .get(common::url(h, &format!("/monitor/mmd/{content_hash}")))
        .send()
        .await
        .expect("GET mmd (covered)");
    assert_eq!(resp.status(), 200);
    let body_json: Value = resp.json().await.expect("JSON");
    assert_eq!(body_json["status"], "covered_within_policy");
    assert_eq!(body_json["elapsedSeconds"], 30);
    assert_eq!(
        body_json["firstCoveringCheckpoint"]["treeSize"],
        snapshot_size
    );

    // A second record, covered only long after the default 24h MMD: breach.
    let late_body = common::unique_id("monitor-mmd-late-body");
    let late_ingested = ingest_file(h, &shard, &late_body).await;
    let late_hash = late_ingested["content_hash"].as_str().unwrap().to_owned();
    let resp = h
        .client
        .get(common::url(h, &format!("/monitor/mmd/{late_hash}")))
        .send()
        .await
        .expect("GET mmd (late, pre-checkpoint)");
    let late_body_json: Value = resp.json().await.expect("JSON");
    let late_snapshot_size = late_body_json["snapshotSize"].as_i64().unwrap();
    let late_ingested_at = late_body_json["ingestedAtUnix"].as_i64().unwrap();

    insert_checkpoint(
        &pool,
        &shard,
        late_snapshot_size,
        late_ingested_at + 200_000, // far beyond DEFAULT_MMD_SECONDS (86_400)
    )
    .await;
    let resp = h
        .client
        .get(common::url(h, &format!("/monitor/mmd/{late_hash}")))
        .send()
        .await
        .expect("GET mmd (breach)");
    let body_json: Value = resp.json().await.expect("JSON");
    assert_eq!(body_json["status"], "covered_late_breach");
    assert_eq!(body_json["elapsedSeconds"], 200_000);
}

#[tokio::test]
async fn mmd_404s_on_unknown_content_hash() {
    let h = common::boot().await;
    let unknown = "cd".repeat(32);
    let resp = h
        .client
        .get(common::url(h, &format!("/monitor/mmd/{unknown}")))
        .send()
        .await
        .expect("GET mmd unknown");
    assert_eq!(resp.status(), 404);
}
