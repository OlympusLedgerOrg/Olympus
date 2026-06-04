//! Storage prototype: how much disk would a **packed bit-path** node key save?
//!
//! The persistent SMT stores `smt_nodes.path` as one byte per path bit (a node
//! at depth `d` is a `d`-byte array), so deep nodes carry ~250-byte keys and the
//! table + its primary-key index dominate on-disk size (~95% of the ledger's
//! bytes in the round-trip benchmark). This experiment measures what a packed
//! encoding would save, WITHOUT touching the production layout (changing it is a
//! breaking migration + both verifiers + vector regen).
//!
//! Method, per tree size N:
//!   1. Build the tree through the real `PersistentSmt<PgBackend>` → populates
//!      `smt_nodes` in the current one-byte-per-bit layout (this is the baseline
//!      on-disk number).
//!   2. Read every `(path, hash)` row, re-encode `path` as
//!      `u16(depth) ‖ ceil(depth/8) packed bits` (≤ 34 bytes vs ≤ 256), and bulk
//!      insert into a `smt_nodes_packed(packed_key bytea PRIMARY KEY, hash bytea)`
//!      table — same hash, same PK-index shape, so the comparison is apples-to-apples.
//!   3. Verify the encoding is losslessly reversible for every row.
//!   4. Compare `pg_total_relation_size` (heap + index + TOAST) of both tables.
//!
//! Gated on `OLYMPUS_BENCH_DATABASE_URL` (a THROWAWAY database — it
//! creates/drops `smt_nodes_packed` and TRUNCATEs `smt_nodes`). Never point it
//! at a real ledger.
//!
//! Run:
//!   OLYMPUS_BENCH_DATABASE_URL=postgres://user@host/throwaway \
//!     cargo run --release -p olympus-desktop --example smt_packed_path_storage -- 100 1000

use olympus_tauri_lib::smt::{LeafUpdate, PersistentSmt, PgBackend};
use sqlx::{PgPool, Row};

const PARSER_ID: &str = "bench-parser@1.0.0";
const CPV: &str = "v1";
const MODEL_HASH: &str = "blake3:bench-model";
const INSERT_CHUNK: usize = 500;

fn splitmix(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    for chunk in out.chunks_mut(8) {
        z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut x = z;
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^= x >> 31;
        chunk.copy_from_slice(&x.to_le_bytes());
    }
    out
}

fn shard_id(i: u64) -> String {
    format!("bench-shard-{:02}", i % 8)
}

fn leaf_update(i: u64) -> LeafUpdate {
    LeafUpdate {
        key: olympus_crypto::smt::shard_record_key(&shard_id(i), &splitmix(i)),
        value_hash: splitmix(i ^ 0xFFFF_FFFF_FFFF_FFFF),
        shard_id: shard_id(i),
        parser_id: PARSER_ID.to_string(),
        canonical_parser_version: CPV.to_string(),
        model_hash: MODEL_HASH.to_string(),
    }
}

/// Pack a one-byte-per-bit path (`len` = depth, each byte 0/1, `len` ≤ 256) into
/// `u16(depth, big-endian) ‖ ceil(depth/8) bytes` with bits MSB-first, the last
/// partial byte left-aligned (low bits zero). Length ≤ 2 + 32 = 34 bytes.
fn pack_path(path: &[u8]) -> Vec<u8> {
    let depth = path.len() as u16;
    let mut out = Vec::with_capacity(2 + path.len().div_ceil(8));
    out.extend_from_slice(&depth.to_be_bytes());
    let mut byte = 0u8;
    let mut nbits = 0u8;
    for &b in path {
        byte = (byte << 1) | (b & 1);
        nbits += 1;
        if nbits == 8 {
            out.push(byte);
            byte = 0;
            nbits = 0;
        }
    }
    if nbits > 0 {
        out.push(byte << (8 - nbits)); // left-align the final partial byte
    }
    out
}

/// Inverse of [`pack_path`]. Used only to prove the encoding is lossless.
fn unpack_path(packed: &[u8]) -> Vec<u8> {
    let depth = u16::from_be_bytes([packed[0], packed[1]]) as usize;
    let bits = &packed[2..];
    let mut out = Vec::with_capacity(depth);
    for i in 0..depth {
        out.push((bits[i / 8] >> (7 - (i % 8))) & 1);
    }
    out
}

fn fmt_bytes(bytes: i64) -> String {
    const KIB: f64 = 1024.0;
    let b = bytes as f64;
    if b >= KIB * KIB {
        format!("{:.2} MiB", b / (KIB * KIB))
    } else if b >= KIB {
        format!("{:.2} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}

async fn relation_size(pool: &PgPool, table: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query("SELECT pg_total_relation_size($1::regclass) AS s")
        .bind(table)
        .fetch_one(pool)
        .await?
        .get::<i64, _>("s"))
}

async fn run_size(pool: &PgPool, n: u64) -> anyhow::Result<()> {
    // Fresh baseline table; (re)create the packed table empty.
    sqlx::query("TRUNCATE smt_nodes, smt_leaves")
        .execute(pool)
        .await?;
    sqlx::query("DROP TABLE IF EXISTS smt_nodes_packed")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE TABLE smt_nodes_packed (packed_key bytea PRIMARY KEY, hash bytea NOT NULL)",
    )
    .execute(pool)
    .await?;

    // 1. Build through the production PgBackend path → current layout in smt_nodes.
    let mut smt = PersistentSmt::open(PgBackend::new(pool.clone())).await?;
    let mut i = 0u64;
    while i < n {
        let end = (i + INSERT_CHUNK as u64).min(n);
        let batch: Vec<LeafUpdate> = (i..end).map(leaf_update).collect();
        smt.update_batch(&batch).await?;
        i = end;
    }

    // 2. Read every node, pack its path, bulk insert into the packed table.
    //    Also verify the encoding round-trips losslessly for every row.
    let rows = sqlx::query("SELECT path, hash FROM smt_nodes")
        .fetch_all(pool)
        .await?;
    let node_count = rows.len();
    let mut max_path_len = 0usize;
    let mut max_packed_len = 0usize;
    let mut packed_keys: Vec<Vec<u8>> = Vec::with_capacity(node_count);
    let mut hashes: Vec<Vec<u8>> = Vec::with_capacity(node_count);
    for row in &rows {
        let path: Vec<u8> = row.get("path");
        let hash: Vec<u8> = row.get("hash");
        let packed = pack_path(&path);
        assert_eq!(
            unpack_path(&packed),
            path,
            "packed encoding must round-trip losslessly"
        );
        max_path_len = max_path_len.max(path.len());
        max_packed_len = max_packed_len.max(packed.len());
        packed_keys.push(packed);
        hashes.push(hash);
    }
    // Bulk insert in chunks via UNNEST (mirrors PgBackend::put_nodes).
    for chunk in (0..node_count).collect::<Vec<_>>().chunks(5000) {
        let ks: Vec<Vec<u8>> = chunk.iter().map(|&j| packed_keys[j].clone()).collect();
        let hs: Vec<Vec<u8>> = chunk.iter().map(|&j| hashes[j].clone()).collect();
        sqlx::query(
            "INSERT INTO smt_nodes_packed (packed_key, hash) \
             SELECT * FROM UNNEST($1::bytea[], $2::bytea[])",
        )
        .bind(&ks)
        .bind(&hs)
        .execute(pool)
        .await?;
    }

    // 3. Compare on-disk size (heap + PK index + TOAST).
    let current = relation_size(pool, "smt_nodes").await?;
    let packed = relation_size(pool, "smt_nodes_packed").await?;
    let leaves = relation_size(pool, "smt_leaves").await?;
    let saved = current - packed;
    let pct = 100.0 * saved as f64 / current as f64;
    let factor = current as f64 / packed as f64;

    println!("┌─ tree size: {n} leaves  ({node_count} internal nodes)");
    println!("│  max path length: current {max_path_len} B/key → packed {max_packed_len} B/key");
    println!(
        "│  smt_nodes        (current, 1 byte/bit) ... {:>11}  ({:.0} B/node)",
        fmt_bytes(current),
        current as f64 / node_count as f64
    );
    println!(
        "│  smt_nodes_packed (u16 depth + bits) ...... {:>11}  ({:.0} B/node)",
        fmt_bytes(packed),
        packed as f64 / node_count as f64
    );
    println!(
        "│  ── nodes saved ........................... {:>11}  ({pct:.1}% smaller, {factor:.2}× reduction)",
        fmt_bytes(saved)
    );
    println!(
        "│  smt_leaves (unchanged) ................... {:>11}",
        fmt_bytes(leaves)
    );
    let total_now = current + leaves;
    let total_packed = packed + leaves;
    println!(
        "│  TOTAL ledger nodes+leaves: {} → {}  ({:.1}% smaller)",
        fmt_bytes(total_now),
        fmt_bytes(total_packed),
        100.0 * (total_now - total_packed) as f64 / total_now as f64
    );
    println!("└─\n");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = match std::env::var("OLYMPUS_BENCH_DATABASE_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("Set OLYMPUS_BENCH_DATABASE_URL=postgres://… (a THROWAWAY database).");
            eprintln!("This experiment TRUNCATEs smt_nodes/smt_leaves and drops smt_nodes_packed.");
            std::process::exit(1);
        }
    };
    let sizes: Vec<u64> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .filter(|&n| n > 0)
        .collect();
    let sizes = if sizes.is_empty() {
        vec![100, 1_000]
    } else {
        sizes
    };

    println!("Olympus SMT packed-path storage prototype");
    println!("  target: {url}\n");

    let pool = PgPool::connect(&url).await?;
    sqlx::migrate!("../migrations").run(&pool).await?;

    for n in sizes {
        run_size(&pool, n).await?;
    }

    // Clean up: drop the experimental table, leave the SMT tables empty.
    sqlx::query("DROP TABLE IF EXISTS smt_nodes_packed")
        .execute(&pool)
        .await?;
    sqlx::query("TRUNCATE smt_nodes, smt_leaves")
        .execute(&pool)
        .await?;
    Ok(())
}
