//! Worst-case read-path stress benchmark for the persistent Sparse Merkle Tree,
//! focused on the ADR-0022 `CANOPY_RECOMPUTE_CAP` (1024) boundary.
//!
//! **Thundering herd** — thousands of *concurrent* `prove` reads against a
//! single tree whose one hot canopy hovers right around the cap (1000 / 1024 /
//! 1025 / 1050 leaves). Just below the cap each read recomputes the deep region
//! from the leaf canopy; just above it each read falls back to the persisted
//! deep nodes. The sweep brackets that switch so you can see the
//! latency/throughput step across it under contention.
//!
//! This is a deliberate **worst case, not typical load.** Production record keys
//! are uniform BLAKE3 hashes, so a 72-bit canopy prefix doesn't collide until
//! ~`2^36` leaves — real canopies are singletons and reads are cheap. A
//! near-cap *single* canopy only arises under prefix collisions or
//! non-hashed/adversarial keys; this bench exists to characterise that pessimal
//! point and confirm the cap bounds it (the just-*under*-cap case folds the
//! whole ≤1024-leaf canopy on every read — the actual hot spot — while the
//! just-*over*-cap case flips to the cheap persisted-node fallback).
//!
//! Runs against MemBackend (pure read-path algorithm) and, when
//! `OLYMPUS_BENCH_DATABASE_URL` is set, against real Postgres (the over-cap
//! fallback then does real DB round-trips under concurrency).
//!
//! Run:
//!
//!     cargo run --release -p olympus-desktop --example smt_read_stress_benchmark
//!     OLYMPUS_BENCH_DATABASE_URL=postgres://…  cargo run --release -p olympus-desktop \
//!         --example smt_read_stress_benchmark
//!
//! Env knobs (all optional):
//!   OLYMPUS_BENCH_HERD_TASKS    concurrent reader tasks  (default 512)
//!   OLYMPUS_BENCH_HERD_OPS      proves per task          (default 8)
//!   OLYMPUS_BENCH_DATABASE_URL  throwaway Postgres DSN (enables the Pg pass)

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use olympus_crypto::smt::{shard_record_key, verify_proof, Proof};
use olympus_tauri_lib::smt::{LeafUpdate, MemBackend, NodeBackend, PersistentSmt, PgBackend};
use sqlx::postgres::PgPoolOptions;

const PARSER_ID: &str = "herd-parser@1.0.0";
const CPV: &str = "v1";
const MODEL_HASH: &str = "blake3:herd-model";

/// Mirror of `tree::CANOPY_RECOMPUTE_CAP` (ADR-0022). The herd sweep brackets it.
const CANOPY_RECOMPUTE_CAP: usize = 1024;

/// Records committed per `update_batch` while populating a canopy.
const INSERT_CHUNK: usize = 512;

// ── deterministic key material ────────────────────────────────────────────────

/// SplitMix64 avalanche — reproducible 64-bit spread without an RNG dependency.
fn splitmix(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A leaf in the single hot canopy `shard`/`canopy_byte`: all keys share the
/// first 9 bytes (shard prefix + `record[0]`), so they fall in one canopy and
/// branch only below `LAZY_DEPTH` (72). The counter lives in record bytes 1.. so
/// it never perturbs the canopy prefix.
fn canopy_leaf(shard: &str, canopy_byte: u8, i: u64) -> LeafUpdate {
    let mut rec = [0u8; 32];
    rec[0] = canopy_byte;
    rec[1..9].copy_from_slice(&i.to_be_bytes());
    let mut value_hash = [0u8; 32];
    value_hash[..8].copy_from_slice(&splitmix(i).to_le_bytes());
    value_hash[31] = 0xAB;
    LeafUpdate {
        key: shard_record_key(shard, &rec),
        value_hash,
        shard_id: shard.to_string(),
        parser_id: PARSER_ID.to_string(),
        canonical_parser_version: CPV.to_string(),
        model_hash: MODEL_HASH.to_string(),
    }
}

async fn insert_all<B: NodeBackend>(smt: &mut PersistentSmt<B>, updates: &[LeafUpdate]) {
    for chunk in updates.chunks(INSERT_CHUNK) {
        smt.update_batch(chunk).await.expect("update_batch");
    }
}

// ── formatting / env ──────────────────────────────────────────────────────────

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

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ── latency stats ─────────────────────────────────────────────────────────────

struct Stats {
    wall: Duration,
    ops: usize,
    p50: u64,
    p90: u64,
    p99: u64,
    max: u64,
}

impl Stats {
    /// `lat` is per-op latency in ns (consumed/sorted); `wall` is the whole-herd
    /// wall-clock so throughput reflects realised concurrency, not the serial sum.
    fn from(mut lat: Vec<u64>, wall: Duration) -> Self {
        lat.sort_unstable();
        let pick = |q: f64| {
            if lat.is_empty() {
                0
            } else {
                lat[(((lat.len() as f64) * q) as usize).min(lat.len() - 1)]
            }
        };
        Stats {
            wall,
            ops: lat.len(),
            p50: pick(0.50),
            p90: pick(0.90),
            p99: pick(0.99),
            max: *lat.last().unwrap_or(&0),
        }
    }

    fn throughput(&self) -> f64 {
        self.ops as f64 / self.wall.as_secs_f64().max(f64::MIN_POSITIVE)
    }

    fn print(&self, label: &str) {
        println!(
            "│    {label:<26} {:>9.0} proofs/s  p50 {:>10}  p90 {:>10}  p99 {:>10}  max {:>10}",
            self.throughput(),
            fmt_ns(self.p50 as f64),
            fmt_ns(self.p90 as f64),
            fmt_ns(self.p99 as f64),
            fmt_ns(self.max as f64),
        );
    }
}

/// Generate a *concrete* herd runner. `tokio::spawn` requires the spawned future
/// to be `Send`; the backend's `async fn`-in-trait futures are only provably
/// `Send` for a concrete backend, not through a generic `B`, so the spawn site
/// must be monomorphic. This macro stamps out one runner per backend.
///
/// Each fires `tasks` concurrent reader tasks, each issuing `ops` `prove`s
/// against random keys in `keys`; the tree is shared by `Arc` (reads take no
/// write lock), so this is genuine read concurrency. Every proof is verified —
/// the benchmark must never time rejected proofs.
macro_rules! make_herd {
    ($name:ident, $backend:ty) => {
        async fn $name(
            smt: Arc<PersistentSmt<$backend>>,
            keys: Arc<Vec<[u8; 32]>>,
            root: [u8; 32],
            tasks: usize,
            ops: usize,
        ) -> Stats {
            let start = Instant::now();
            let mut handles = Vec::with_capacity(tasks);
            for t in 0..tasks {
                let smt = Arc::clone(&smt);
                let keys = Arc::clone(&keys);
                handles.push(tokio::spawn(async move {
                    let mut lat = Vec::with_capacity(ops);
                    let mut bad = 0u64;
                    for op in 0..ops {
                        let idx = (splitmix(((t as u64) << 32) | op as u64) as usize) % keys.len();
                        let key = keys[idx];
                        let op_start = Instant::now();
                        let proof = smt.prove(&key).await.expect("prove");
                        lat.push(op_start.elapsed().as_nanos() as u64);
                        if !(matches!(proof, Proof::Existence(_))
                            && verify_proof(&proof, Some(&root)))
                        {
                            bad += 1;
                        }
                    }
                    (lat, bad)
                }));
            }
            let mut all = Vec::with_capacity(tasks * ops);
            let mut bad_total = 0u64;
            for h in handles {
                let (lat, bad) = h.await.expect("join");
                all.extend(lat);
                bad_total += bad;
            }
            assert_eq!(bad_total, 0, "every concurrent proof must verify");
            Stats::from(all, start.elapsed())
        }
    };
}

make_herd!(herd_mem, MemBackend);
make_herd!(herd_pg, PgBackend);

// ── scenario 1: thundering herd ───────────────────────────────────────────────

/// Build a single hot canopy of exactly `n` leaves and return the queryable keys.
async fn build_canopy<B: NodeBackend>(smt: &mut PersistentSmt<B>, n: usize) -> Vec<[u8; 32]> {
    let updates: Vec<LeafUpdate> = (0..n as u64)
        .map(|i| canopy_leaf("herd-shard", 0x5C, i))
        .collect();
    insert_all(smt, &updates).await;
    updates.into_iter().map(|u| u.key).collect()
}

/// Build a hot canopy of each bracketing size and run the herd. `make` opens a
/// fresh tree; `run` is the concrete herd runner for that backend (the orchestration
/// here only awaits sequentially, so it stays generic).
async fn herd_pass<B, Mk, MkFut, Run, RunFut>(
    label: &str,
    tasks: usize,
    ops: usize,
    mut make: Mk,
    run: Run,
) where
    B: NodeBackend,
    Mk: FnMut() -> MkFut,
    MkFut: Future<Output = PersistentSmt<B>>,
    Run: Fn(Arc<PersistentSmt<B>>, Arc<Vec<[u8; 32]>>, [u8; 32], usize, usize) -> RunFut,
    RunFut: Future<Output = Stats>,
{
    // Sizes bracketing CANOPY_RECOMPUTE_CAP: recompute path (≤ cap) → fallback
    // path (> cap). `> cap` is the over-cap trigger, so 1024 is still recompute.
    let sizes = [
        CANOPY_RECOMPUTE_CAP - 24, // 1000
        CANOPY_RECOMPUTE_CAP,      // 1024
        CANOPY_RECOMPUTE_CAP + 1,  // 1025
        CANOPY_RECOMPUTE_CAP + 26, // 1050
    ];
    println!("┌─ thundering herd  [{label}]  ({tasks} tasks × {ops} proofs)");
    for &n in &sizes {
        let mut smt = make().await;
        let keys = Arc::new(build_canopy(&mut smt, n).await);
        let root = smt.root().await.expect("root");
        let stats = run(Arc::new(smt), keys, root, tasks, ops).await;
        let regime = if n > CANOPY_RECOMPUTE_CAP {
            "over-cap fallback"
        } else {
            "under-cap recompute"
        };
        stats.print(&format!("{n:>4} leaves {regime}"));
    }
    println!("└─\n");
}

// ── Postgres pool helper ──────────────────────────────────────────────────────

async fn pg_smt(url: &str, max_conns: u32) -> anyhow::Result<PersistentSmt<PgBackend>> {
    let pool = PgPoolOptions::new()
        .max_connections(max_conns)
        .connect(url)
        .await?;
    sqlx::migrate!("../migrations").run(&pool).await?;
    sqlx::query("TRUNCATE smt_nodes, smt_leaves")
        .execute(&pool)
        .await?;
    PersistentSmt::open(PgBackend::new(pool)).await
}

/// Pool width: wide enough that the herd contends on the tree, not a 1-conn neck.
fn pool_conns(tasks: usize) -> u32 {
    (tasks as u32 / 8).clamp(8, 64)
}

// ── main ──────────────────────────────────────────────────────────────────────

fn main() {
    let herd_tasks = env_usize("OLYMPUS_BENCH_HERD_TASKS", 512);
    let herd_ops = env_usize("OLYMPUS_BENCH_HERD_OPS", 8);
    let db_url = std::env::var("OLYMPUS_BENCH_DATABASE_URL")
        .ok()
        .filter(|u| !u.is_empty());

    println!("Olympus SMT read-path stress benchmark (ADR-0022 cap = {CANOPY_RECOMPUTE_CAP})");
    println!(
        "  build profile : {}",
        if cfg!(debug_assertions) {
            "DEBUG (use --release for representative numbers!)"
        } else {
            "release"
        }
    );
    println!(
        "  thundering herd: {herd_tasks} tasks × {herd_ops} proofs  (worst-case near-cap canopy)\n"
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("herd runtime");
    rt.block_on(async {
        herd_pass(
            "MemBackend",
            herd_tasks,
            herd_ops,
            || async { PersistentSmt::open(MemBackend::new()).await.expect("open") },
            herd_mem,
        )
        .await;

        if let Some(url) = &db_url {
            println!("    Postgres target: {}\n", redact_db_url(url));
            let conns = pool_conns(herd_tasks);
            herd_pass(
                "PgBackend",
                herd_tasks,
                herd_ops,
                || {
                    let url = url.clone();
                    async move { pg_smt(&url, conns).await.expect("pg open") }
                },
                herd_pg,
            )
            .await;
        } else {
            println!("    (PgBackend herd skipped — set OLYMPUS_BENCH_DATABASE_URL)\n");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::redact_db_url;

    #[test]
    fn redact_masks_userinfo_and_drops_query_fragment() {
        // userinfo masked, query (with secret) dropped, path kept.
        assert_eq!(
            redact_db_url("postgres://user:s3cr3t@db.host:5432/olympus?sslmode=require&password=p"),
            "postgres://***@db.host:5432/olympus"
        );
        // secret only in query, no userinfo → still dropped.
        assert_eq!(
            redact_db_url("postgres://db.host/olympus?sslpassword=hunter2"),
            "postgres://db.host/olympus"
        );
        // a '@' inside a query value must not be read as userinfo.
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
