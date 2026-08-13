// SPDX-License-Identifier: Apache-2.0

//! ADR-0044 conformance: every own-checkpoint also carries a BJJ-signed
//! `SmtRootAttestation` binding the shard's BLAKE3 CD-HS-ST parser-bound SMT
//! subtree root to this checkpoint's `(ledger_root, tree_size)`, verifiable
//! offline against `olympus_crypto::smt_root_attest_message`.
//!
//! This is the test that ties the checkpoint producer back to the golden
//! signing message: it never re-derives the digest from the producer's
//! private helper — it recomputes it independently from the public
//! `olympus_crypto` primitive plus the documented "reduce mod l" recipe, then
//! checks the persisted signature verifies under the authority pubkey. It also
//! independently reads the shard's BLAKE3 SMT subtree root via
//! `PersistentSmt::shard_subtree_root` and asserts it equals what the producer
//! persisted, so the attestation is proven to describe the *actual* tree
//! state, not just an internally-consistent signature over an arbitrary value.
//!
//! Database: boots an embedded Postgres (pg_embed, as CI does) by default, or
//! connects to `OLYMPUS_TEST_PG_URL` when set (a throwaway database).

use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use sqlx::PgPool;

use olympus_tauri_lib::anchoring::own_checkpoint::{
    build_and_persist, verify_smt_root_attestation,
};
use olympus_tauri_lib::smt::{PersistentSmt, PgBackend};
use olympus_tauri_lib::zk::proof::parse_fr;
use olympus_tauri_lib::zk::witness::baby_jubjub::{
    verify_signature, BabyJubJubPubKey, BabyJubJubSignature, BABYJ_SUBGROUP_ORDER,
};

const SHARD: &str = "files";

/// Independently recompute the `Fr` message scalar the producer signs:
/// `smt_root_attest_message(shard_id, ledger_root, tree_size, blake3_smt_root)`
/// reduced mod l.
fn expected_signed_scalar(
    shard_id: &[u8],
    ledger_root: &[u8; 32],
    tree_size: i64,
    blake3_smt_root: &[u8; 32],
) -> Fr {
    let digest =
        olympus_crypto::smt_root_attest_message(shard_id, ledger_root, tree_size, blake3_smt_root);
    let l: BigUint = BABYJ_SUBGROUP_ORDER.parse().expect("static decimal");
    let reduced = BigUint::from_bytes_be(&digest) % l;
    Fr::from_le_bytes_mod_order(&reduced.to_bytes_le())
}

/// Insert a minimal but schema-valid ingest snapshot row that
/// `build_and_persist` will pick up as "the latest snapshot". `tag` must be a
/// single lowercase-hex nibble so the derived content/ledger hashes satisfy the
/// `^[0-9a-f]{64}$` CHECK constraints and stay unique per row.
async fn insert_snapshot(
    pool: &PgPool,
    tag: char,
    bjj_key: &[u8; 32],
    new_leaf: Fr,
    ts: &str,
) -> olympus_tauri_lib::zk::snapshot::LedgerSnapshot {
    assert!(tag.is_ascii_hexdigit() && !tag.is_ascii_uppercase());
    let content_hash: String = std::iter::repeat_n(tag, 64).collect();
    let ledger_entry_hash: String = std::iter::once('a')
        .chain(std::iter::repeat_n(tag, 63))
        .collect();
    let original_root_hex = olympus_tauri_lib::zk::chunk::fr_to_hex(new_leaf);
    let snapshot = olympus_tauri_lib::zk::snapshot::snapshot_new_record(
        bjj_key,
        &[],
        new_leaf,
        0,
        &content_hash,
        &original_root_hex,
        1_780_000_000,
    )
    .expect("build canonical snapshot");
    let path = serde_json::json!({
        "path_elements": snapshot.path_elements_hex.clone(),
        "path_indices": snapshot.path_indices.clone(),
    });
    let signature = serde_json::json!({
        "alg": "bjj-eddsa-poseidon",
        "r8x": snapshot.signature_r8x.clone(),
        "r8y": snapshot.signature_r8y.clone(),
        "s": snapshot.signature_s.clone(),
        "signed_at": snapshot.signed_at_unix,
    })
    .to_string();
    sqlx::query(
        "INSERT INTO ingest_records
            (proof_id, shard_id, record_type, record_id, version,
             content_hash, ledger_entry_hash,
             original_root, snapshot_root, snapshot_index, snapshot_size,
             snapshot_path, snapshot_sig, snapshot_committed, ts)
         VALUES ($1, $2, 'file', $1, 1, $3, $4, $5, $6, 0, 1, $7, $8, TRUE, $9::timestamp)",
    )
    .bind(format!("proof-smtroot-{tag}"))
    .bind(SHARD)
    .bind(&content_hash)
    .bind(&ledger_entry_hash)
    .bind(&original_root_hex)
    .bind(&snapshot.snapshot_root)
    .bind(&path)
    .bind(&signature)
    .bind(ts)
    .execute(pool)
    .await
    .expect("insert snapshot row");
    snapshot
}

#[tokio::test]
async fn checkpoint_smt_root_attestation_is_signed_and_verifies() {
    let (pool, _pg) = open_pool().await;
    // Isolation: this test is the sole producer of checkpoints and SMT leaves
    // in its binary, but TRUNCATE keeps it hermetic against any seeded rows.
    sqlx::query("TRUNCATE own_checkpoints, ingest_records, smt_leaves, smt_nodes CASCADE")
        .execute(&pool)
        .await
        .expect("clean slate");

    let bjj_key: [u8; 32] = {
        let mut k = [0u8; 32];
        k[0] = 0x09;
        k[31] = 0x3b;
        k
    };
    let pubkey = BabyJubJubPubKey::from_private(&bjj_key).expect("derive pubkey");

    insert_snapshot(&pool, 'c', &bjj_key, Fr::from(77u64), "2026-01-02 00:00:00").await;

    // Write a leaf into the BLAKE3 SMT for the same shard before checkpointing,
    // so the attestation describes a non-trivial (non-empty-subtree) root —
    // proving the producer reads the actual tree state, not a placeholder.
    let record_key = olympus_crypto::record_key("file", "smt-root-test-doc", 1);
    let leaf_key = olympus_crypto::smt::shard_record_key(SHARD, &record_key);
    let value_hash = olympus_crypto::hash_bytes(b"smt root attestation test payload");
    let mut writer = PersistentSmt::open(PgBackend::new(pool.clone()))
        .await
        .expect("open BLAKE3 SMT writer");
    writer
        .update(leaf_key, value_hash, SHARD, "test-parser", "v1", "none")
        .await
        .expect("write SMT leaf");
    let expected_subtree_root = writer
        .shard_subtree_root(SHARD)
        .await
        .expect("read shard subtree root after write");

    // proofs_dir = None → sign-only path (no Groth16), but both attestations
    // (Poseidon transition + BLAKE3 SMT root) are still built + signed because
    // a BJJ key is present.
    let row = build_and_persist(&pool, Some(&bjj_key), Some(&pubkey), None)
        .await
        .expect("build_and_persist ok")
        .expect("a snapshot row exists");

    let blake3_smt_root_hex = row
        .blake3_smt_root
        .as_deref()
        .expect("blake3_smt_root persisted");
    assert_eq!(
        blake3_smt_root_hex,
        hex::encode(expected_subtree_root),
        "persisted attestation root must equal the shard's actual BLAKE3 SMT subtree root"
    );
    let blake3_smt_root: [u8; 32] = hex::decode(blake3_smt_root_hex)
        .unwrap()
        .try_into()
        .unwrap();

    let ledger_root_fr = parse_fr(&row.ledger_root).expect("parse ledger_root");
    let ledger_root_hex = olympus_tauri_lib::zk::chunk::fr_to_hex(ledger_root_fr);
    let ledger_root: [u8; 32] = hex::decode(&ledger_root_hex).unwrap().try_into().unwrap();

    let r8x = row.blake3_smt_sig_r8x.clone().expect("r8x persisted");
    let r8y = row.blake3_smt_sig_r8y.clone().expect("r8y persisted");
    let s = row.blake3_smt_sig_s.clone().expect("s persisted");

    let verified_message = verify_smt_root_attestation(
        SHARD,
        &ledger_root_hex,
        row.tree_size,
        blake3_smt_root_hex,
        &pubkey,
        (&r8x, &r8y, &s),
    )
    .expect("persisted SMT root attestation must verify");

    let sig = BabyJubJubSignature {
        r8x: parse_fr(&r8x).expect("parse r8x"),
        r8y: parse_fr(&r8y).expect("parse r8y"),
        s: parse_fr(&s).expect("parse s"),
    };
    let msg = expected_signed_scalar(
        SHARD.as_bytes(),
        &ledger_root,
        row.tree_size,
        &blake3_smt_root,
    );
    assert_eq!(verified_message, msg);
    assert!(
        verify_signature(&pubkey, &sig, msg),
        "persisted SMT root signature must verify against smt_root_attest_message reduced mod l"
    );

    // Tamper sanity: the signature must NOT verify against a different root.
    let wrong_root = [0xffu8; 32];
    let wrong = expected_signed_scalar(SHARD.as_bytes(), &ledger_root, row.tree_size, &wrong_root);
    assert!(
        !verify_signature(&pubkey, &sig, wrong),
        "signature must be bound to the exact (shard, ledger_root, tree_size, blake3_smt_root) statement"
    );

    // Tamper sanity: verify_smt_root_attestation must reject a claimed root
    // that disagrees with what was actually signed.
    let err = verify_smt_root_attestation(
        SHARD,
        &ledger_root_hex,
        row.tree_size,
        &hex::encode(wrong_root),
        &pubkey,
        (&r8x, &r8y, &s),
    )
    .expect_err("attestation must not verify against a different claimed root");
    assert!(err.contains("does not verify"));
}

// ── Embedded Postgres boot (same pattern as tests/checkpoint_transition_attestation.rs) ──

async fn open_pool() -> (PgPool, Option<pg_embed::postgres::PgEmbed>) {
    if let Ok(url) = std::env::var("OLYMPUS_TEST_PG_URL") {
        let pool = PgPool::connect(&url)
            .await
            .expect("connect OLYMPUS_TEST_PG_URL");
        sqlx::migrate!("../migrations")
            .run(&pool)
            .await
            .expect("migrate provided db");
        return (pool, None);
    }
    let mut last_err = None;
    for _ in 0..5 {
        match try_boot_embedded().await {
            Ok(pair) => return pair,
            Err(e) => last_err = Some(e),
        }
    }
    panic!("embedded postgres failed to boot after retries: {last_err:?}");
}

async fn try_boot_embedded() -> anyhow::Result<(PgPool, Option<pg_embed::postgres::PgEmbed>)> {
    use pg_embed::pg_enums::PgAuthMethod;
    use pg_embed::pg_fetch::{PgFetchSettings, PG_V15};
    use pg_embed::postgres::{PgEmbed, PgSettings};
    use std::time::Duration;

    // Held through `PgEmbed::setup` (which only stages the binary/data dir,
    // it doesn't bind the port) so a concurrent test process picking a port
    // via the same `bind("127.0.0.1:0")` trick can't claim this one first;
    // released just before `start_db` actually needs it.
    let reserved = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = reserved.local_addr()?.port();
    let dir = std::env::temp_dir().join(format!("olympus-smtroot-pgtest-{port}")); // nosemgrep: rust.lang.security.temp-dir.temp-dir
    let settings = PgSettings {
        database_dir: dir.clone(),
        port,
        user: "olympus".into(),
        password: "olympus".into(),
        auth_method: PgAuthMethod::Plain,
        persistent: true,
        timeout: Some(Duration::from_secs(60)),
        migration_dir: None,
    };
    let fetch = PgFetchSettings {
        version: PG_V15,
        ..Default::default()
    };
    let mut pg = PgEmbed::new(settings, fetch).await?;
    pg.setup().await?;
    drop(reserved);
    {
        use std::io::Write;
        let conf = dir.join("postgresql.conf");
        let existing = std::fs::read_to_string(&conf).unwrap_or_default();
        if !existing.contains("listen_addresses = '127.0.0.1'") {
            let mut f = std::fs::OpenOptions::new().append(true).open(&conf)?;
            writeln!(f, "\nlisten_addresses = '127.0.0.1'\nport = {port}")?;
        }
    }
    pg.start_db().await?;
    if !pg.database_exists("olympus").await? {
        pg.create_database("olympus").await?;
    }
    let pool = PgPool::connect(&pg.full_db_uri("olympus")).await?;
    sqlx::migrate!("../migrations").run(&pool).await?;
    Ok((pool, Some(pg)))
}
