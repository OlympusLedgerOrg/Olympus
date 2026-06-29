//! Audit A1-03: federation equivocation detection must not be bypassable.
//!
//! Two problems were fixed:
//!   (a) TOCTOU — detection and store ran in *separate* committed
//!       transactions with no per-peer lock, so two concurrent conflicting
//!       pushes each detected-before-the-other-stored and both landed
//!       `equivocation_detected = false`. The fix runs detection + store in
//!       one transaction gated by a per-peer `pg_advisory_xact_lock`.
//!   (b) Narrow detection — conflicts were keyed only on
//!       `checkpoint_timestamp`, so two different roots at the same ledger
//!       height (`tree_size`) but different timestamps escaped detection.
//!       Detection is now `different ledger_root AND (same timestamp OR same
//!       tree_size)`.
//!
//! These tests drive the DB layer (`equivocation::check_and_flag` +
//! `checkpoint::store_peer_checkpoint`) directly, in the same
//! transaction-and-order `verify::verify_and_store` uses — that is where the
//! bug lived. They deliberately do NOT build a real Groth16 proof (the
//! upstream signature/proof gates are covered by the unit tests in
//! `verify.rs`); the point here is the detect+store interaction against live
//! Postgres.
//!
//! Database: boots an embedded Postgres (pg_embed, as CI does) by default, or
//! connects to `OLYMPUS_TEST_PG_URL` when set (a throwaway database).
//!
//! Gated on the `federation` feature: the code under test
//! (`olympus_tauri_lib::federation`) is only compiled with it. Run via
//! `cargo test -p olympus-desktop --features federation --test federation_equivocation`.
#![cfg(feature = "federation")]

use sqlx::PgPool;
use uuid::Uuid;

use olympus_tauri_lib::federation::checkpoint::{store_peer_checkpoint, PeerCheckpoint};
use olympus_tauri_lib::federation::equivocation::check_and_flag;

/// Insert a peer row so the `peer_checkpoints.peer_id` FK is satisfied, and
/// return its id. The BJJ pubkey columns are placeholders — these tests never
/// run signature verification (that's covered by the `verify.rs` unit tests).
async fn insert_peer(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO peer_nodes (id, name, onion_address, bjj_pubkey_x, bjj_pubkey_y)
         VALUES ($1, $2, $3, '1', '2')",
    )
    .bind(id)
    .bind(format!("peer-{id}"))
    .bind(format!("{}.onion", &id.simple().to_string()[..16]))
    .execute(pool)
    .await
    .expect("insert peer");
    id
}

/// A minimal checkpoint envelope. Only the fields the DB layer reads
/// (`ledger_root`, `tree_size`, `checkpoint_timestamp`) are meaningful here.
fn checkpoint(ledger_root: &str, tree_size: i64, ts: i64) -> PeerCheckpoint {
    PeerCheckpoint {
        wire_version: PeerCheckpoint::current_version(),
        ledger_root: ledger_root.to_owned(),
        tree_size,
        checkpoint_timestamp: ts,
        authority_pubkey_hash: "0".to_owned(),
        groth16_proof: serde_json::json!({"pi_a": []}),
        public_signals: vec![],
        bjj_signature: None,
    }
}

/// Run the DB half of `verify_and_store` for one checkpoint: take the per-peer
/// advisory lock, detect, then store — all in one transaction, exactly as the
/// production path does. Returns whether equivocation was detected.
async fn detect_and_store(pool: &PgPool, peer_id: Uuid, cp: &PeerCheckpoint) -> bool {
    let mut tx = pool.begin().await.expect("begin tx");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(peer_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("advisory lock");
    let equivocated = check_and_flag(
        &mut tx,
        peer_id,
        cp.checkpoint_timestamp,
        cp.tree_size,
        &cp.ledger_root,
    )
    .await
    .expect("check_and_flag");
    store_peer_checkpoint(&mut tx, peer_id, cp, true, equivocated)
        .await
        .expect("store");
    tx.commit().await.expect("commit");
    equivocated
}

async fn detected_count(pool: &PgPool, peer_id: Uuid) -> i64 {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM peer_checkpoints
         WHERE peer_id = $1 AND equivocation_detected = true",
    )
    .bind(peer_id)
    .fetch_one(pool)
    .await
    .expect("count");
    n
}

#[tokio::test]
async fn same_timestamp_different_root_is_flagged() {
    let (pool, _pg) = open_pool().await;
    let peer = insert_peer(&pool).await;

    // First root at ts=1700000000 — no prior conflict, not flagged.
    let detected_a = detect_and_store(&pool, peer, &checkpoint("11", 5, 1_700_000_000)).await;
    assert!(!detected_a, "first checkpoint must not be flagged");

    // Second root at the SAME timestamp but DIFFERENT root + DIFFERENT height
    // (height differs so this can ONLY match on timestamp). Must be flagged.
    let detected_b = detect_and_store(&pool, peer, &checkpoint("22", 6, 1_700_000_000)).await;
    assert!(
        detected_b,
        "conflicting root at the same timestamp must be flagged (audit A1-03)"
    );

    // Both the prior row AND the incoming row are flagged — not silently
    // stored. The pre-fix bug left both `equivocation_detected = false`.
    assert_eq!(
        detected_count(&pool, peer).await,
        2,
        "both conflicting checkpoints must be flagged, not silently stored"
    );
}

#[tokio::test]
async fn same_height_different_timestamp_is_flagged() {
    let (pool, _pg) = open_pool().await;
    let peer = insert_peer(&pool).await;

    // First root at tree_size=42, ts=1700000100.
    let detected_a = detect_and_store(&pool, peer, &checkpoint("aa", 42, 1_700_000_100)).await;
    assert!(!detected_a, "first checkpoint must not be flagged");

    // Different root at the SAME height (tree_size=42) but a DIFFERENT
    // timestamp. Under the old timestamp-only rule this escaped detection;
    // the broadened rule (audit A1-03(b)) flags it on the height match.
    let detected_b = detect_and_store(&pool, peer, &checkpoint("bb", 42, 1_700_000_999)).await;
    assert!(
        detected_b,
        "conflicting root at the same height (different timestamp) must be flagged (audit A1-03(b))"
    );
    assert_eq!(
        detected_count(&pool, peer).await,
        2,
        "both same-height conflicting checkpoints must be flagged"
    );
}

#[tokio::test]
async fn already_flagged_conflict_still_flags_continued_equivocation() {
    let (pool, _pg) = open_pool().await;
    let peer = insert_peer(&pool).await;

    // Two conflicting roots at the same timestamp → equivocation flagged.
    detect_and_store(&pool, peer, &checkpoint("01", 7, 1_700_001_000)).await;
    assert!(detect_and_store(&pool, peer, &checkpoint("02", 8, 1_700_001_000)).await);

    // A THIRD distinct root at the same (already-flagged) timestamp. The old
    // code filtered `AND equivocation_detected = false` in the detection
    // SELECT, so continued equivocation at a flagged timestamp was recorded
    // silently (returned false). The fix removed that filter, so it must
    // still report detected.
    let detected_third = detect_and_store(&pool, peer, &checkpoint("03", 9, 1_700_001_000)).await;
    assert!(
        detected_third,
        "continued equivocation at an already-flagged timestamp must still be detected (audit A1-03(b))"
    );
    assert_eq!(
        detected_count(&pool, peer).await,
        3,
        "all three conflicting checkpoints must be flagged"
    );
}

#[tokio::test]
async fn identical_recommit_is_not_equivocation() {
    let (pool, _pg) = open_pool().await;
    let peer = insert_peer(&pool).await;

    // Same root, same timestamp, same height committed twice: the dedup
    // UNIQUE index makes the second INSERT a no-op, and detection must NOT
    // fire (same ledger_root => no conflict).
    let cp = checkpoint("ff", 3, 1_700_002_000);
    assert!(!detect_and_store(&pool, peer, &cp).await);
    assert!(
        !detect_and_store(&pool, peer, &cp).await,
        "an identical re-commit must not be treated as equivocation"
    );
    assert_eq!(
        detected_count(&pool, peer).await,
        0,
        "identical re-commit must leave nothing flagged"
    );
}

// ── Embedded-Postgres harness (mirrors checkpoint_transition_attestation.rs) ──

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
    use pg_embed::pg_fetch::{PgFetchSettings, PG_V17};
    use pg_embed::postgres::{PgEmbed, PgSettings};
    use std::time::Duration;

    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let dir = std::env::temp_dir().join(format!("olympus-equiv-pgtest-{port}")); // nosemgrep: rust.lang.security.temp-dir.temp-dir
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
        version: PG_V17,
        ..Default::default()
    };
    let mut pg = PgEmbed::new(settings, fetch).await?;
    pg.setup().await?;
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
