//! ADR-0031 §2 conformance: every own-checkpoint carries a BJJ-signed
//! `TransitionAttestation` binding `original_root → snapshot_root over
//! snapshot_size`, verifiable offline against PR1's `olympus_crypto::
//! persist_message`.
//!
//! This is the test that ties PR2 (the checkpoint producer) back to PR1's
//! golden signing message: it never re-derives the digest from the producer's
//! private helper — it recomputes it independently from the public
//! `olympus_crypto` primitive plus the documented "reduce mod l" recipe, then
//! checks the persisted signature verifies under the authority pubkey.
//!
//! Database: boots an embedded Postgres (pg_embed, as CI does) by default, or
//! connects to `OLYMPUS_TEST_PG_URL` when set (a throwaway database).

use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use sqlx::PgPool;

use olympus_tauri_lib::anchoring::own_checkpoint::build_and_persist;
use olympus_tauri_lib::zk::proof::parse_fr;
use olympus_tauri_lib::zk::witness::baby_jubjub::{
    verify_signature, BabyJubJubPubKey, BabyJubJubSignature,
};

/// BabyJubjub prime-subgroup order l — the modulus the transition digest is
/// reduced by before signing (mirrors `BABYJ_SUBGROUP_ORDER` in the producer).
const BABYJ_SUBGROUP_ORDER: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";

/// Independently recompute the `Fr` message scalar the producer signs:
/// `persist_message(original_root, snapshot_root, snapshot_size)` reduced mod l.
fn expected_signed_scalar(original_root: &[u8; 32], snapshot_root: &[u8; 32], size: i64) -> Fr {
    let att = olympus_crypto::TransitionAttestation {
        original_root: *original_root,
        snapshot_root: *snapshot_root,
        snapshot_size: size,
    };
    let digest = att.message();
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
    original_root_hex: &str,
    snapshot_root_hex: &str,
    size: i64,
    ts: &str,
) {
    assert!(tag.is_ascii_hexdigit() && !tag.is_ascii_uppercase());
    let content_hash: String = std::iter::repeat(tag).take(64).collect();
    let ledger_entry_hash: String = std::iter::once('a')
        .chain(std::iter::repeat(tag).take(63))
        .collect();
    sqlx::query(
        "INSERT INTO ingest_records
            (proof_id, shard_id, record_type, record_id, version,
             content_hash, ledger_entry_hash,
             original_root, snapshot_root, snapshot_index, snapshot_size,
             snapshot_path, ts)
         VALUES ($1, 'files', 'file', $1, 1, $2, $3, $4, $5, 0, $6, '{}'::jsonb, $7::timestamp)",
    )
    .bind(format!("proof-{tag}"))
    .bind(&content_hash)
    .bind(&ledger_entry_hash)
    .bind(original_root_hex)
    .bind(snapshot_root_hex)
    .bind(size)
    .bind(ts)
    .execute(pool)
    .await
    .expect("insert snapshot row");
}

#[tokio::test]
async fn checkpoint_transition_attestation_is_signed_and_verifies() {
    let (pool, _pg) = open_pool().await;
    // Isolation: this test is the sole producer of checkpoints in its binary,
    // but TRUNCATE keeps it hermetic against any seeded rows.
    sqlx::query("TRUNCATE own_checkpoints, ingest_records CASCADE")
        .execute(&pool)
        .await
        .expect("clean slate");

    // ── BJJ key present → the four transition columns are written, and the
    //    signature verifies offline against persist_message reduced mod l. ──
    let bjj_key: [u8; 32] = {
        let mut k = [0u8; 32];
        k[0] = 0x07;
        k[31] = 0x2a;
        k
    };
    let pubkey = BabyJubJubPubKey::from_private(&bjj_key).expect("derive pubkey");

    let original_root = [0x33u8; 32];
    let snapshot_root = [0x11u8; 32];
    let size: i64 = 5;
    insert_snapshot(
        &pool,
        'b',
        &hex::encode(original_root),
        &hex::encode(snapshot_root),
        size,
        "2026-01-01 00:00:00",
    )
    .await;

    // proofs_dir = None → sign-only path (no Groth16), but the transition
    // attestation is still built + signed because a BJJ key is present.
    let row = build_and_persist(&pool, Some(&bjj_key), Some(&pubkey), None)
        .await
        .expect("build_and_persist ok")
        .expect("a snapshot row exists");

    assert_eq!(
        row.transition_original_root.as_deref(),
        Some(hex::encode(original_root).as_str()),
        "transition_original_root must be persisted"
    );
    let r8x = row.transition_sig_r8x.expect("r8x present");
    let r8y = row.transition_sig_r8y.expect("r8y present");
    let s = row.transition_sig_s.expect("s present");

    let sig = BabyJubJubSignature {
        r8x: parse_fr(&r8x).expect("parse r8x"),
        r8y: parse_fr(&r8y).expect("parse r8y"),
        s: parse_fr(&s).expect("parse s"),
    };
    let msg = expected_signed_scalar(&original_root, &snapshot_root, size);
    assert!(
        verify_signature(&pubkey, &sig, msg),
        "persisted transition signature must verify against persist_message reduced mod l"
    );

    // Tamper sanity: the signature must NOT verify against a different transition.
    let wrong = expected_signed_scalar(&original_root, &snapshot_root, size + 1);
    assert!(
        !verify_signature(&pubkey, &sig, wrong),
        "signature must be bound to the exact (roots, size) transition"
    );

    // ── No BJJ key → the four transition columns are NULL, and the build must
    //    still succeed (the row stays valid + anchorable). ──
    insert_snapshot(
        &pool,
        'c',
        &hex::encode([0x44u8; 32]),
        &hex::encode([0x22u8; 32]),
        9,
        "2026-02-01 00:00:00",
    )
    .await;

    let row_nokey = build_and_persist(&pool, None, None, None)
        .await
        .expect("build_and_persist ok with no key")
        .expect("a snapshot row exists");
    // Sanity: the no-key build must have targeted the newer (unsigned) snapshot,
    // not deduped back onto the signed checkpoint.
    assert_eq!(
        row_nokey.ledger_root,
        hex::encode([0x22u8; 32]),
        "no-key build should target the latest (unsigned) snapshot"
    );
    assert!(
        row_nokey.transition_original_root.is_none()
            && row_nokey.transition_sig_r8x.is_none()
            && row_nokey.transition_sig_r8y.is_none()
            && row_nokey.transition_sig_s.is_none(),
        "no-BJJ-key build must leave all transition columns NULL"
    );
}

// ── Embedded Postgres boot (same pattern as tests/smt_pg_backend.rs) ──────────

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
    let dir = std::env::temp_dir().join(format!("olympus-ckpt-pgtest-{port}"));
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
