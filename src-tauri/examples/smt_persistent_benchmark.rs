//! Round-trip latency + storage-size benchmark for the **persistent** Sparse
//! Merkle Tree — `olympus_tauri_lib::smt::PersistentSmt`, the production
//! write/read path (batched `update_batch` upserts, prefetched `prove_batch`,
//! write-behind hot cache, cross-process write lock).
//!
//! This is the persistent counterpart to the pure-algorithm benchmark in
//! `olympus-crypto/examples/smt_benchmark.rs`. Roots and proofs are byte-for-byte
//! identical to that in-memory reference tree; what differs — and what this
//! measures — is the cost the storage layer adds: the async/batched code path
//! and, for Postgres, real DB round-trips and on-disk size.
//!
//! Two backends:
//!
//! * **MemBackend** — always runs. The real `PersistentSmt` code path
//!   (batching, shard-parallel recompute, hot cache, write lock) over in-RAM
//!   maps. No database needed, so it's the CI-safe baseline.
//! * **PgBackend** — runs only when `OLYMPUS_BENCH_DATABASE_URL` is set. This is
//!   the one that answers "what does storage actually cost": per-op latency
//!   includes Postgres round-trips, and the storage figure is the true on-disk
//!   `pg_total_relation_size` of `smt_nodes` / `smt_leaves`, not a RAM estimate.
//!
//!   ⚠️ DESTRUCTIVE: the Postgres pass `TRUNCATE`s `smt_nodes` and `smt_leaves`
//!   on the target database before each size so the storage number reflects
//!   exactly N leaves. Point `OLYMPUS_BENCH_DATABASE_URL` at a THROWAWAY
//!   database — never a real ledger. It is a separate variable from the app's
//!   `DATABASE_URL` precisely so a configured ledger is never clobbered by
//!   accident.
//!
//! Run (MemBackend only; default tree sizes 100 / 1 000):
//!   cargo run --release -p olympus-desktop --example smt_persistent_benchmark
//!
//! Run including the Postgres storage numbers, with custom sizes:
//!   OLYMPUS_BENCH_DATABASE_URL=postgres://user:pw@localhost/olympus_bench \
//!     cargo run --release -p olympus-desktop --example smt_persistent_benchmark -- 100 1000 5000
//!
//! NOTE: build with `--release`; debug timings are not representative. Postgres
//! inserts are heavy (≈ `SMT_DEPTH` node rows per leaf), so keep N modest there.

use std::time::{Duration, Instant};

use olympus_crypto::smt::{shard_record_key, verify_proof};
use olympus_tauri_lib::smt::{LeafUpdate, MemBackend, NodeBackend, PersistentSmt, PgBackend};
use sqlx::{PgPool, Row};

const PARSER_ID: &str = "bench-parser@1.0.0";
const CPV: &str = "v1";
const MODEL_HASH: &str = "blake3:bench-model";

/// How many records a single `update_batch` flushes — mirrors the ingest path
/// committing a chunk of files at once rather than one giant batch.
const INSERT_CHUNK: usize = 500;

/// Deterministic 32-byte record material from a counter (SplitMix64 avalanche),
/// so paths are well spread and runs are reproducible without an RNG dep.
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

/// The tree key for record `i`: the shard prefix folded into the high 64 bits
/// (ADR-0005). `LeafUpdate.key` is this fully-formed tree key — same as the
/// parity tests' `upd` helper — and `prove`/`get` query the identical value.
fn tree_key(i: u64) -> [u8; 32] {
    shard_record_key(&shard_id(i), &splitmix(i))
}

/// The `LeafUpdate` for record `i`.
fn leaf_update(i: u64, value_seed: u64) -> LeafUpdate {
    LeafUpdate {
        key: tree_key(i),
        value_hash: splitmix(value_seed ^ 0xFFFF_FFFF_FFFF_FFFF),
        shard_id: shard_id(i),
        parser_id: PARSER_ID.to_string(),
        canonical_parser_version: CPV.to_string(),
        model_hash: MODEL_HASH.to_string(),
    }
}

fn fmt_ns(ns: f64) -> String {
    if ns >= 1_000_000.0 {
        format!("{:.3} ms", ns / 1_000_000.0)
    } else if ns >= 1_000.0 {
        format!("{:.3} µs", ns / 1_000.0)
    } else {
        format!("{ns:.1} ns")
    }
}

/// Redact a Postgres DSN for printing: keep scheme + host[:port] + path, mask
/// the userinfo before `@`, and **drop the query/fragment entirely** (Postgres
/// DSNs can carry secrets there, e.g. `?password=…` / `?sslpassword=…`). Pure
/// string surgery — no `url` crate. The authority is bounded at the first
/// `/`, `?`, or `#`, so a `@` inside a query value can't be mistaken for
/// userinfo. On anything unparseable, fall back to a fully-masked `***`.
fn redact_db_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "***".to_string();
    };
    // Authority ends at the first '/', '?' or '#'; the rest is path/query/frag.
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(auth_end);
    let authority = match authority.rsplit_once('@') {
        Some((_userinfo, host)) => format!("***@{host}"),
        None => authority.to_string(),
    };
    // Keep only the path portion of the tail (everything before '?' / '#').
    let path = &tail[..tail.find(['?', '#']).unwrap_or(tail.len())];
    format!("{scheme}://{authority}{path}")
}

fn fmt_bytes(bytes: u64) -> String {
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

/// Bulk-load `n` distinct leaves in `INSERT_CHUNK`-sized batches; returns the
/// total wall-clock build time.
async fn build<B: NodeBackend>(smt: &mut PersistentSmt<B>, n: u64) -> Duration {
    let start = Instant::now();
    let mut i = 0u64;
    while i < n {
        let end = (i + INSERT_CHUNK as u64).min(n);
        let batch: Vec<LeafUpdate> = (i..end).map(|j| leaf_update(j, j)).collect();
        smt.update_batch(&batch).await.expect("update_batch");
        i = end;
    }
    start.elapsed()
}

/// Absolute per-proof latency ceiling (ADR-0022 locked decision): lazy deep-node
/// recompute may regress `prove` up to ~3×, **provided** the absolute time stays
/// strictly under this bound so proof generation can never stall block
/// validation. The benchmark reports PASS/FAIL against it (meaningful on the
/// PgBackend pass; MemBackend is in-RAM and always far below).
const PROVE_LATENCY_GATE_MS: f64 = 10.0;

/// Timed round-trip figures for a tree already holding `n` leaves. `iters` is
/// kept small for Postgres (each op is a real DB round-trip). Returns `true` if
/// both prove latencies are within `PROVE_LATENCY_GATE_MS`.
async fn round_trip<B: NodeBackend>(smt: &mut PersistentSmt<B>, n: u64, iters: usize) -> bool {
    let warmup = (iters / 5).max(2);
    let mut sink = 0u8;

    // update: overwrite an existing key (1-element batch) — same recompute +
    // flush cost as a fresh insert, but keeps the tree at size n.
    for w in 0..warmup {
        let upd = leaf_update((w as u64) % n, (w as u64) ^ 0xBEEF);
        smt.update_batch(std::slice::from_ref(&upd)).await.unwrap();
    }
    let t = Instant::now();
    for i in 0..iters {
        let upd = leaf_update((i as u64) % n, (i as u64) ^ 0xA5A5);
        smt.update_batch(std::slice::from_ref(&upd)).await.unwrap();
    }
    let update_ns = t.elapsed().as_nanos() as f64 / iters as f64;

    // prove (existence): every queried key is resident.
    let t = Instant::now();
    for i in 0..iters {
        let proof = smt.prove(&tree_key((i as u64) % n)).await.unwrap();
        sink ^= proof_tag(&proof);
    }
    let prove_exist_ns = t.elapsed().as_nanos() as f64 / iters as f64;

    // prove (non-existence): keys well past the populated range are all absent.
    let absent_base = n.wrapping_add(1_000_000);
    let t = Instant::now();
    for i in 0..iters {
        let proof = smt.prove(&tree_key(absent_base + i as u64)).await.unwrap();
        sink ^= proof_tag(&proof);
    }
    let prove_absent_ns = t.elapsed().as_nanos() as f64 / iters as f64;

    // verify (existence + non-existence): anchor each proof to the live root.
    let root = smt.root().await.unwrap();
    let exist_proof = smt.prove(&tree_key(0)).await.unwrap();
    let absent_proof = smt.prove(&tree_key(absent_base)).await.unwrap();
    // Self-check: the benchmark uses its own keys, so confirm the proofs are
    // the kind we expect and actually verify before we time verification —
    // otherwise a broken setup would silently benchmark rejected proofs.
    use olympus_crypto::smt::Proof;
    assert!(
        matches!(exist_proof, Proof::Existence(_)) && verify_proof(&exist_proof, Some(&root)),
        "resident key must produce a verifying existence proof"
    );
    assert!(
        matches!(absent_proof, Proof::NonExistence(_)) && verify_proof(&absent_proof, Some(&root)),
        "absent key must produce a verifying non-existence proof"
    );
    let t = Instant::now();
    for _ in 0..iters {
        sink ^= verify_proof(&exist_proof, Some(&root)) as u8;
    }
    let verify_exist_ns = t.elapsed().as_nanos() as f64 / iters as f64;
    let t = Instant::now();
    for _ in 0..iters {
        sink ^= verify_proof(&absent_proof, Some(&root)) as u8;
    }
    let verify_absent_ns = t.elapsed().as_nanos() as f64 / iters as f64;
    std::hint::black_box(sink);

    let roundtrip_ns = update_ns + prove_exist_ns + verify_exist_ns;

    println!("│  ROUND TRIP (mean of {iters} ops)");
    println!("│    update (overwrite) ........ {:>12}", fmt_ns(update_ns));
    println!(
        "│    prove   (existence) ....... {:>12}",
        fmt_ns(prove_exist_ns)
    );
    println!(
        "│    prove   (non-existence) ... {:>12}",
        fmt_ns(prove_absent_ns)
    );
    println!(
        "│    verify  (existence) ....... {:>12}",
        fmt_ns(verify_exist_ns)
    );
    println!(
        "│    verify  (non-existence) ... {:>12}",
        fmt_ns(verify_absent_ns)
    );
    println!(
        "│    └ update+prove+verify ..... {:>12}",
        fmt_ns(roundtrip_ns)
    );

    // Latency gate (ADR-0022): the worst of the two prove paths must stay under
    // the absolute ceiling.
    let gate_ns = PROVE_LATENCY_GATE_MS * 1_000_000.0;
    let worst_prove_ns = prove_exist_ns.max(prove_absent_ns);
    let gate_ok = worst_prove_ns < gate_ns;
    println!(
        "│  GATE prove < {PROVE_LATENCY_GATE_MS:.0} ms/proof ... {} (worst {})",
        if gate_ok { "PASS" } else { "FAIL" },
        fmt_ns(worst_prove_ns)
    );
    gate_ok
}

/// A cheap, branch-distinct byte derived from a proof so timed loops have an
/// observable side effect the optimiser cannot discard.
fn proof_tag(proof: &olympus_crypto::smt::Proof) -> u8 {
    use olympus_crypto::smt::Proof;
    match proof {
        Proof::Existence(p) => p.root_hash[0] ^ p.value_hash[0],
        Proof::NonExistence(p) => p.root_hash[0] ^ 0x80,
    }
}

// ── MemBackend pass ──────────────────────────────────────────────────────────

async fn bench_mem(sizes: &[u64]) -> bool {
    println!("=== MemBackend (production code path, in-RAM, no database) ===\n");
    let mut gate_ok = true;
    for &n in sizes {
        let mut smt = PersistentSmt::open(MemBackend::new()).await.expect("open");
        let build_time = build(&mut smt, n).await;

        println!("┌─ tree size: {n} leaves  [MemBackend]");
        println!(
            "│  build (bulk insert) ......... {:>12}  ({} / leaf)",
            fmt_ns(build_time.as_nanos() as f64),
            fmt_ns(build_time.as_nanos() as f64 / n as f64)
        );
        // MemBackend ops are cheap → afford more iterations for a stable mean.
        let iters = 500.min((n as usize).max(1) * 5).max(50);
        gate_ok &= round_trip(&mut smt, n, iters).await;

        let nodes = smt.mem_node_count();
        let leaves = smt.mem_leaf_count();
        println!("│  STORAGE (in-RAM node/leaf maps)");
        println!(
            "│    internal nodes ............ {nodes:>12}  ({:.1} / leaf)",
            nodes as f64 / n as f64
        );
        println!("│    leaf records .............. {leaves:>12}");
        println!("└─\n");
    }
    gate_ok
}

// ── PgBackend pass ───────────────────────────────────────────────────────────

async fn bench_pg(url: &str, sizes: &[u64]) -> anyhow::Result<bool> {
    println!("=== PgBackend (real Postgres: round-trips + on-disk storage) ===");
    println!("    target: {}", redact_db_url(url));
    println!("    ⚠️  TRUNCATEs smt_nodes / smt_leaves on this database before each size.\n");

    let pool = PgPool::connect(url).await?;
    // Ensure smt_nodes / smt_leaves (and the rest of the schema) exist, exactly
    // as the app does on startup.
    sqlx::migrate!("../migrations").run(&pool).await?;
    let mut gate_ok = true;

    for &n in sizes {
        // Fresh slate so the storage figure is exactly N leaves' worth.
        sqlx::query("TRUNCATE smt_nodes, smt_leaves")
            .execute(&pool)
            .await?;

        let mut smt = PersistentSmt::open(PgBackend::new(pool.clone())).await?;
        let build_time = build(&mut smt, n).await;

        println!("┌─ tree size: {n} leaves  [PgBackend]");
        println!(
            "│  build (bulk insert) ......... {:>12}  ({} / leaf)",
            fmt_ns(build_time.as_nanos() as f64),
            fmt_ns(build_time.as_nanos() as f64 / n as f64)
        );
        // Each Pg op is a round-trip → far fewer iterations.
        let iters = 50.min((n as usize).max(1)).max(10);
        gate_ok &= round_trip(&mut smt, n, iters).await;

        let nodes: i64 = sqlx::query("SELECT count(*) AS c FROM smt_nodes")
            .fetch_one(&pool)
            .await?
            .get("c");
        let leaves: i64 = sqlx::query("SELECT count(*) AS c FROM smt_leaves")
            .fetch_one(&pool)
            .await?
            .get("c");
        let nodes_bytes = pg_relation_size(&pool, "smt_nodes").await?;
        let leaves_bytes = pg_relation_size(&pool, "smt_leaves").await?;
        let total_bytes = nodes_bytes + leaves_bytes;
        println!("│  STORAGE (on-disk, pg_total_relation_size incl. indexes/TOAST)");
        println!(
            "│    smt_nodes rows ............ {nodes:>12}  ({:.1} / leaf)",
            nodes as f64 / n as f64
        );
        println!("│    smt_leaves rows ........... {leaves:>12}");
        println!(
            "│    smt_nodes on disk ......... {:>12}",
            fmt_bytes(nodes_bytes)
        );
        println!(
            "│    smt_leaves on disk ........ {:>12}",
            fmt_bytes(leaves_bytes)
        );
        println!(
            "│    total on disk ............. {:>12}  ({} / leaf)",
            fmt_bytes(total_bytes),
            fmt_bytes(total_bytes / n)
        );
        println!("└─\n");
    }

    // Leave the database clean.
    sqlx::query("TRUNCATE smt_nodes, smt_leaves")
        .execute(&pool)
        .await?;
    Ok(gate_ok)
}

async fn pg_relation_size(pool: &PgPool, table: &str) -> anyhow::Result<u64> {
    let row = sqlx::query("SELECT pg_total_relation_size($1::regclass) AS s")
        .bind(table)
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("s").max(0) as u64)
}

#[tokio::main]
async fn main() {
    let sizes: Vec<u64> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .collect();
    let sizes = if sizes.is_empty() {
        vec![100, 1_000]
    } else {
        sizes
    };

    println!("Olympus PERSISTENT SMT round-trip + storage benchmark");
    println!(
        "  build profile : {}",
        if cfg!(debug_assertions) {
            "DEBUG (run with --release for representative numbers!)"
        } else {
            "release"
        }
    );
    println!("  tree sizes    : {sizes:?}\n");

    let mut gate_ok = bench_mem(&sizes).await;

    match std::env::var("OLYMPUS_BENCH_DATABASE_URL") {
        Ok(url) if !url.is_empty() => match bench_pg(&url, &sizes).await {
            Ok(pg_gate_ok) => gate_ok &= pg_gate_ok,
            Err(e) => {
                eprintln!("PgBackend benchmark failed: {e:#}");
                std::process::exit(1);
            }
        },
        _ => {
            println!("=== PgBackend skipped ===");
            println!("    Set OLYMPUS_BENCH_DATABASE_URL=postgres://… (a THROWAWAY database)");
            println!("    to measure real Postgres round-trip latency and on-disk storage size.");
        }
    }

    // The latency gate is a release-build property; a debug run is far slower and
    // would trip it spuriously, so only enforce (non-zero exit) under --release.
    if !gate_ok {
        if cfg!(debug_assertions) {
            eprintln!(
                "\n⚠️  prove latency gate ({PROVE_LATENCY_GATE_MS:.0} ms) exceeded — \
                 ignored in DEBUG; re-run with --release to enforce."
            );
        } else {
            eprintln!(
                "\n❌ prove latency gate ({PROVE_LATENCY_GATE_MS:.0} ms/proof) exceeded \
                 (ADR-0022) — failing."
            );
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::redact_db_url;

    #[test]
    fn redact_masks_userinfo_and_drops_query_fragment() {
        assert_eq!(
            redact_db_url("postgres://user:s3cr3t@db.host:5432/olympus?sslmode=require&password=p"),
            "postgres://***@db.host:5432/olympus"
        );
        // secret only in query, no userinfo → still dropped.
        assert_eq!(
            redact_db_url("postgres://db.host/olympus?sslpassword=hunter2"),
            "postgres://db.host/olympus"
        );
        // '@' inside a query value must not be read as userinfo.
        assert_eq!(
            redact_db_url("postgres://db.host/db?opt=a@b"),
            "postgres://db.host/db"
        );
        // no query/userinfo → unchanged.
        assert_eq!(
            redact_db_url("postgres://db.host:5432/olympus"),
            "postgres://db.host:5432/olympus"
        );
        // unparseable (no scheme) → fully masked, never echoed.
        assert_eq!(redact_db_url("user:pw@host/db"), "***");
    }
}
