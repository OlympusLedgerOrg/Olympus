//! Sizes the *next* SMT storage lever: how much would "persist only the shallow
//! `depth ≤ K` nodes and recompute deeper ones from leaves" actually save?
//!
//! Interior SMT nodes are a pure function of the leaves, so they need not all be
//! stored. Shallow nodes saturate (≤ `2^K` of them ever), while total nodes grow
//! ~linearly in leaf count — so a "leaves + shallow nodes" policy gets cheaper
//! per leaf as the ledger grows. This experiment measures it without writing any
//! recompute code:
//!
//!   1. Build the tree through the real `PersistentSmt<PgBackend>` (packed
//!      schema, migration 0043) → populates `smt_nodes(depth, …)`.
//!   2. Histogram: `SELECT depth, count(*) … GROUP BY depth`, and report the
//!      cumulative node count kept at several candidate `K` (per-leaf).
//!   3. Physically measure the hybrid on-disk size: `DELETE … WHERE depth > K`,
//!      `VACUUM FULL`, then compare `pg_total_relation_size` against the full
//!      tree. (Deleting deep rows is exactly what a recompute-deep design would
//!      never have stored.)
//!
//! Gated on `OLYMPUS_BENCH_DATABASE_URL` (a THROWAWAY database — it TRUNCATEs and
//! DELETEs from the SMT tables).
//!
//! Run:
//!   OLYMPUS_BENCH_DATABASE_URL=postgres://user@host/throwaway \
//!     cargo run --release -p olympus-desktop --example smt_node_depth_histogram -- 1000 5000

use olympus_crypto::smt::shard_record_key;
use olympus_tauri_lib::smt::{LeafUpdate, PersistentSmt, PgBackend};
use sqlx::{PgPool, Row};

const INSERT_CHUNK: usize = 500;
/// Persisted-depth cutoff for the physically-measured hybrid. Must clear the
/// 64-bit shard-prefix region (so per-shard subtree roots stay persisted rather
/// than being O(N)-recomputed) plus a within-shard margin so each recomputed
/// deep sibling covers few leaves.
const HYBRID_K: i16 = 72;

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
    format!("hist-shard-{:02}", i % 8)
}

fn leaf_update(i: u64) -> LeafUpdate {
    LeafUpdate {
        key: shard_record_key(&shard_id(i), &splitmix(i)),
        value_hash: splitmix(i ^ 0xFFFF_FFFF_FFFF_FFFF),
        shard_id: shard_id(i),
        parser_id: "hist-parser".into(),
        canonical_parser_version: "v1".into(),
        model_hash: "hist-model".into(),
    }
}

fn fmt_bytes(b: i64) -> String {
    const KIB: f64 = 1024.0;
    let f = b as f64;
    if f >= KIB * KIB {
        format!("{:.2} MiB", f / (KIB * KIB))
    } else if f >= KIB {
        format!("{:.2} KiB", f / KIB)
    } else {
        format!("{b} B")
    }
}

async fn total_size(pool: &PgPool, table: &str) -> anyhow::Result<i64> {
    Ok(
        sqlx::query("SELECT pg_total_relation_size($1::regclass) AS s")
            .bind(table)
            .fetch_one(pool)
            .await?
            .get::<i64, _>("s"),
    )
}

async fn run(pool: &PgPool, n: u64) -> anyhow::Result<()> {
    sqlx::query("TRUNCATE smt_nodes, smt_leaves")
        .execute(pool)
        .await?;

    // 1. Build the full tree.
    let mut smt = PersistentSmt::open(PgBackend::new(pool.clone())).await?;
    let mut i = 0u64;
    while i < n {
        let end = (i + INSERT_CHUNK as u64).min(n);
        let batch: Vec<LeafUpdate> = (i..end).map(leaf_update).collect();
        smt.update_batch(&batch).await?;
        i = end;
    }

    // 2. Depth histogram → cumulative "kept at depth ≤ K".
    let rows = sqlx::query("SELECT depth, count(*) AS c FROM smt_nodes GROUP BY depth")
        .fetch_all(pool)
        .await?;
    let mut per_depth = [0i64; 257];
    let mut total_nodes = 0i64;
    for row in &rows {
        let d: i16 = row.get("depth");
        let c: i64 = row.get("c");
        per_depth[d as usize] = c;
        total_nodes += c;
    }
    let cum_le = |k: usize| -> i64 { per_depth[..=k.min(256)].iter().sum() };

    println!(
        "┌─ {n} leaves  ({total_nodes} internal nodes, {:.1}/leaf)",
        total_nodes as f64 / n as f64
    );
    println!("│  nodes kept if we persist only depth ≤ K (deeper = recomputed):");
    for k in [20usize, 48, 64, 72, 80] {
        let kept = cum_le(k);
        println!(
            "│    K={k:<3} → {kept:>10} nodes  ({:>6.2}/leaf, {:>5.1}% of all nodes)",
            kept as f64 / n as f64,
            100.0 * kept as f64 / total_nodes as f64
        );
    }

    // 3. Physically measure the hybrid (leaves + depth ≤ CACHE_DEPTH) on disk.
    let full_nodes = total_size(pool, "smt_nodes").await?;
    let leaves = total_size(pool, "smt_leaves").await?;
    sqlx::query("DELETE FROM smt_nodes WHERE depth > $1")
        .bind(HYBRID_K)
        .execute(pool)
        .await?;
    sqlx::query("VACUUM FULL smt_nodes").execute(pool).await?;
    let hybrid_nodes = total_size(pool, "smt_nodes").await?;

    let full_total = full_nodes + leaves;
    let hybrid_total = hybrid_nodes + leaves;
    println!("│  ON DISK (pg_total_relation_size):");
    println!(
        "│    full     : nodes {} + leaves {} = {}  ({} / leaf)",
        fmt_bytes(full_nodes),
        fmt_bytes(leaves),
        fmt_bytes(full_total),
        fmt_bytes(full_total / n as i64)
    );
    println!(
        "│    hybrid K={HYBRID_K}: nodes {} + leaves {} = {}  ({} / leaf)",
        fmt_bytes(hybrid_nodes),
        fmt_bytes(leaves),
        fmt_bytes(hybrid_total),
        fmt_bytes(hybrid_total / n as i64)
    );
    println!(
        "│    └ {:.1}% smaller  ({:.1}× reduction on top of packed paths)",
        100.0 * (full_total - hybrid_total) as f64 / full_total as f64,
        full_total as f64 / hybrid_total.max(1) as f64
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
            std::process::exit(1);
        }
    };
    let sizes: Vec<u64> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .filter(|&n| n > 0)
        .collect();
    let sizes = if sizes.is_empty() {
        vec![1_000, 5_000]
    } else {
        sizes
    };

    println!("Olympus SMT node depth-distribution / hybrid-storage measurement\n");
    let pool = PgPool::connect(&url).await?;
    sqlx::migrate!("../migrations").run(&pool).await?;
    for n in sizes {
        run(&pool, n).await?;
    }
    sqlx::query("TRUNCATE smt_nodes, smt_leaves")
        .execute(&pool)
        .await?;
    Ok(())
}
