//! PgBackend ↔ reference-tree parity against the packed node-path schema
//! (migration 0043).
//!
//! This is the round-trip guardrail for the packed `smt_nodes(depth, path_bits)`
//! layout: it drives the production `PersistentSmt<PgBackend>` through real
//! Postgres and asserts its root and proofs are byte-identical to the in-memory
//! `olympus_crypto::smt::SparseMerkleTree` for the same leaves — exercising the
//! rewritten `put_nodes` / `get_nodes` / `load_hot` SQL and the pack/unpack
//! codec against the live schema. Because the path is pure addressing (never
//! hashed), any divergence here means the physical encoding broke.
//!
//! Database: boots an embedded Postgres (pg_embed, as CI does) by default, or
//! connects to `OLYMPUS_TEST_PG_URL` when set (a throwaway database — the test
//! TRUNCATEs the SMT tables).

use olympus_crypto::smt::{shard_record_key, verify_proof, Proof, SparseMerkleTree};
use olympus_tauri_lib::smt::{LeafUpdate, PersistentSmt, PgBackend};
use sqlx::PgPool;

const PARSER_ID: &str = "pgtest-parser";
const CPV: &str = "v1";
const MODEL_HASH: &str = "pgtest-model";

fn shard_id(i: u64) -> String {
    format!("pgtest-shard-{}", i % 4)
}

/// A deterministic leaf, keyed by the full shard-prefixed tree key (ADR-0005).
fn leaf_update(i: u64) -> LeafUpdate {
    let mut rec = [0u8; 32];
    rec[..8].copy_from_slice(&i.to_le_bytes());
    rec[31] = 0x5A;
    let mut value_hash = [0u8; 32];
    value_hash[0] = i as u8;
    value_hash[31] = 0xAB;
    LeafUpdate {
        key: shard_record_key(&shard_id(i), &rec),
        value_hash,
        shard_id: shard_id(i),
        parser_id: PARSER_ID.to_string(),
        canonical_parser_version: CPV.to_string(),
        model_hash: MODEL_HASH.to_string(),
    }
}

/// The same leaf applied to the in-memory reference tree.
fn apply_reference(tree: &mut SparseMerkleTree, u: &LeafUpdate) {
    tree.update(
        u.key,
        u.value_hash,
        &u.shard_id,
        &u.parser_id,
        &u.canonical_parser_version,
        &u.model_hash,
    );
}

/// Open a pool against either a provided throwaway DB (`OLYMPUS_TEST_PG_URL`) or
/// a freshly-booted embedded Postgres, with all migrations applied. The
/// returned `PgEmbed` (when present) MUST be kept alive for the test's duration.
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

    // Picking an ephemeral port then handing it to pg_embed has a small
    // reserve-then-release race (another process could grab the freed port
    // before PG binds it). Retry the whole boot on a fresh port a few times so
    // a lost race can't flake the test under parallel CI.
    let mut last_err = None;
    for _ in 0..5 {
        match try_boot_embedded().await {
            Ok(pair) => return pair,
            Err(e) => last_err = Some(e),
        }
    }
    panic!("embedded postgres failed to boot after retries: {last_err:?}");
}

/// One attempt at booting an embedded Postgres on a freshly-picked ephemeral
/// port; returns `Err` (so the caller can retry on a new port) if the port was
/// stolen between reservation and `start_db`.
async fn try_boot_embedded() -> anyhow::Result<(PgPool, Option<pg_embed::postgres::PgEmbed>)> {
    use pg_embed::pg_enums::PgAuthMethod;
    use pg_embed::pg_fetch::{PgFetchSettings, PG_V17};
    use pg_embed::postgres::{PgEmbed, PgSettings};
    use std::time::Duration;

    // Reserve an ephemeral port, then let it go so pg_embed can bind it.
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let dir = std::env::temp_dir().join(format!("olympus-smt-pgtest-{port}"));
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
    // Mirror the server/test harness: force loopback-only listen_addresses so
    // PG doesn't try ::1 first and hang on some platforms before start_db.
    {
        use std::io::Write;
        let conf = dir.join("postgresql.conf");
        let existing = std::fs::read_to_string(&conf).unwrap_or_default();
        if !existing.contains("listen_addresses = '127.0.0.1'") {
            let mut f = std::fs::OpenOptions::new().append(true).open(&conf)?;
            writeln!(f, "\nlisten_addresses = '127.0.0.1'\nport = {port}")?;
        }
    }
    // The likely failure point if the port was stolen — propagate as Err to retry.
    pg.start_db().await?;
    if !pg.database_exists("olympus").await? {
        pg.create_database("olympus").await?;
    }
    let pool = PgPool::connect(&pg.full_db_uri("olympus")).await?;
    sqlx::migrate!("../migrations").run(&pool).await?;
    Ok((pool, Some(pg)))
}

#[tokio::test]
async fn pg_backend_packed_paths_match_reference_tree() {
    let (pool, _pg) = open_pool().await;
    sqlx::query("TRUNCATE smt_nodes, smt_leaves")
        .execute(&pool)
        .await
        .expect("clean slate");

    // Build the same multi-shard leaf set two ways.
    let updates: Vec<LeafUpdate> = (0..64u64).map(leaf_update).collect();
    let mut reference = SparseMerkleTree::new();
    for u in &updates {
        apply_reference(&mut reference, u);
    }
    let reference_root = reference.root();

    let mut smt = PersistentSmt::open(PgBackend::new(pool.clone()))
        .await
        .expect("open");
    let pg_root = smt.update_batch(&updates).await.expect("update_batch");

    // 1. Root parity — the packed-stored tree must hash to the reference root.
    //    (put_nodes wrote (depth, path_bits) rows; this proves the encoding is
    //    physical-only.)
    assert_eq!(
        pg_root, reference_root,
        "PgBackend root must equal the in-memory reference root"
    );

    // 2. load_hot — a fresh handle reloads the hot upper levels from the packed
    //    rows; it must reconstruct the identical root.
    let smt2 = PersistentSmt::open(PgBackend::new(pool.clone()))
        .await
        .expect("reopen");
    assert_eq!(
        smt2.root().await.expect("root"),
        reference_root,
        "load_hot must rebuild the same root from packed rows"
    );

    // 3. get_nodes / proof round-trip — existence + non-existence proofs read
    //    siblings back through the packed schema and verify against the root,
    //    and match the reference tree's proofs byte-for-byte.
    let key = updates[7].key;
    let proof = smt2.prove(&key).await.expect("prove existence");
    assert!(matches!(proof, Proof::Existence(_)));
    assert!(verify_proof(&proof, Some(&reference_root)));
    assert_eq!(
        proof,
        reference.prove(&key),
        "existence proof must match reference"
    );

    let absent = shard_record_key("pgtest-shard-0", &[0xEE; 32]);
    let nproof = smt2.prove(&absent).await.expect("prove non-existence");
    assert!(matches!(nproof, Proof::NonExistence(_)));
    assert!(verify_proof(&nproof, Some(&reference_root)));
    assert_eq!(
        nproof,
        reference.prove(&absent),
        "non-existence proof must match reference"
    );
}
