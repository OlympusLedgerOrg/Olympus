//! Round-trip latency + storage-size benchmark for the in-memory
//! [`SparseMerkleTree`](olympus_crypto::smt::SparseMerkleTree).
//!
//! Two questions, one harness:
//!
//! 1. **Round trip** — how long does a record's full lifecycle cost as the tree
//!    grows: `update` (the 256-level read-modify-write hot path), `prove`
//!    (collect the 256 siblings + assemble the proof), and `verify` (the
//!    relying-party fold back to the root), for both existence and
//!    non-existence. The combined `update → prove → verify` figure is the
//!    end-to-end round trip a single record sees.
//! 2. **Storage size** — what does the tree cost to hold in memory at each
//!    size: materialised internal-node count (≈ `SMT_DEPTH` per leaf minus
//!    shared prefixes), bytes per leaf, and total estimated heap footprint.
//!
//! No external benchmark framework: timings use `std::time::Instant` over a
//! fixed iteration budget so the example builds and runs offline with only the
//! workspace's own crates, mirroring the `gen_ssmf_vectors` example.
//!
//! Run with (defaults to tree sizes 100, 1 000, 10 000):
//!   cargo run --release -p olympus-crypto --example smt_benchmark --features smt
//!
//! Override the sizes (memory grows ≈ `SMT_DEPTH` nodes per leaf, so large N is
//! heavy — 10 000 leaves is on the order of a few hundred MB):
//!   cargo run --release -p olympus-crypto --example smt_benchmark --features smt -- 100 1000 50000
//!
//! NOTE: build with `--release`; a debug build's timings are not representative
//! of the crypto hot path.

use std::time::{Duration, Instant};

use olympus_crypto::smt::{shard_record_key, verify_proof, Proof, SparseMerkleTree, SMT_DEPTH};

const PARSER_ID: &str = "bench-parser@1.0.0";
const CPV: &str = "v1";
const MODEL_HASH: &str = "blake3:bench-model";

/// Deterministic 32-byte record key from a counter — a SplitMix64-style
/// avalanche so successive indices land on well-spread tree paths (no external
/// RNG dependency, fully reproducible run to run).
fn record_key(i: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut z = i.wrapping_add(0x9E37_79B9_7F4A_7C15);
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

/// A per-record shard id, spread across a handful of shards so the benchmark
/// exercises the 64-bit shard-prefix partitioning rather than a single subtree.
fn shard_id(i: u64) -> String {
    format!("bench-shard-{:02}", i % 8)
}

/// Tree key for record `i`, with its shard prefix folded into the high 64 bits
/// (the form `update`/`prove` require).
fn tree_key(i: u64) -> [u8; 32] {
    shard_record_key(&shard_id(i), &record_key(i))
}

fn value_hash(i: u64) -> [u8; 32] {
    record_key(i ^ 0xFFFF_FFFF_FFFF_FFFF)
}

/// Build a tree pre-loaded with `n` distinct leaves and return it plus the
/// wall-clock build time (the bulk-insert cost is itself a useful data point).
fn build_tree(n: u64) -> (SparseMerkleTree, Duration) {
    let mut tree = SparseMerkleTree::new();
    let start = Instant::now();
    for i in 0..n {
        tree.update(
            tree_key(i),
            value_hash(i),
            &shard_id(i),
            PARSER_ID,
            CPV,
            MODEL_HASH,
        );
    }
    (tree, start.elapsed())
}

/// Run `op` `iters` times, returning mean nanoseconds per call. A short
/// untimed warm-up primes caches/branch predictors so the first call's cold
/// cost doesn't skew small `iters`.
fn time_ns<F: FnMut(usize)>(iters: usize, warmup: usize, mut op: F) -> f64 {
    for w in 0..warmup {
        op(w);
    }
    let start = Instant::now();
    for i in 0..iters {
        op(i);
    }
    let elapsed = start.elapsed();
    elapsed.as_nanos() as f64 / iters as f64
}

/// Format nanoseconds as a compact, unit-scaled string.
fn fmt_ns(ns: f64) -> String {
    if ns >= 1_000_000.0 {
        format!("{:.3} ms", ns / 1_000_000.0)
    } else if ns >= 1_000.0 {
        format!("{:.3} µs", ns / 1_000.0)
    } else {
        format!("{ns:.1} ns")
    }
}

/// Format a byte count with binary unit scaling.
fn fmt_bytes(bytes: usize) -> String {
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

fn bench_size(n: u64) {
    let (mut tree, build) = build_tree(n);
    assert_eq!(tree.len() as u64, n, "every key must be distinct");

    // ── round trip (steady-state, at tree size n) ──────────────────────────
    // `iters` is bounded so even N=100 has a stable sample without N inflating
    // run time; ops cycle over the resident keys via modulo.
    let iters = 2_000.min((n as usize).max(1) * 20).max(200);
    let warmup = (iters / 10).max(16);

    // update: overwrite an existing key with a fresh value. Same 256-level
    // read-modify-write cost as a first insert, but keeps the tree at size n so
    // the measurement is steady-state (no unbounded growth mid-benchmark).
    let update_ns = time_ns(iters, warmup, |i| {
        let idx = (i as u64) % n;
        tree.update(
            tree_key(idx),
            value_hash(idx ^ 0xA5A5),
            &shard_id(idx),
            PARSER_ID,
            CPV,
            MODEL_HASH,
        );
    });

    // prove (existence): every queried key is resident.
    let mut sink = 0u8; // keep the optimiser from eliding the proof
    let prove_exist_ns = time_ns(iters, warmup, |i| {
        let idx = (i as u64) % n;
        let proof = tree.prove(&tree_key(idx));
        sink ^= proof_tag(&proof);
    });

    // prove (non-existence): keys past the populated range are all absent.
    let absent_base = n.wrapping_add(1_000_000);
    let prove_absent_ns = time_ns(iters, warmup, |i| {
        let proof = tree.prove(&tree_key(absent_base + i as u64));
        sink ^= proof_tag(&proof);
    });

    // verify (existence + non-existence): anchor each proof to the live root.
    let root = tree.root();
    let exist_proof = tree.prove(&tree_key(0));
    let absent_proof = tree.prove(&tree_key(absent_base));
    let verify_exist_ns = time_ns(iters, warmup, |_| {
        sink ^= verify_proof(&exist_proof, Some(&root)) as u8;
    });
    let verify_absent_ns = time_ns(iters, warmup, |_| {
        sink ^= verify_proof(&absent_proof, Some(&root)) as u8;
    });
    std::hint::black_box(sink);

    let roundtrip_ns = update_ns + prove_exist_ns + verify_exist_ns;

    // ── storage size ───────────────────────────────────────────────────────
    let nodes = tree.node_count();
    let heap = tree.heap_bytes_estimate();
    let nodes_per_leaf = nodes as f64 / n as f64;
    let bytes_per_leaf = heap as f64 / n as f64;

    println!("┌─ tree size: {n} leaves");
    println!(
        "│  build (bulk insert) ......... {:>12}  ({} / leaf)",
        fmt_ns(build.as_nanos() as f64),
        fmt_ns(build.as_nanos() as f64 / n as f64)
    );
    println!("│  ROUND TRIP");
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
    println!("│  STORAGE");
    println!("│    internal nodes ............ {nodes:>12}  ({nodes_per_leaf:.1} / leaf)");
    println!(
        "│    est. heap footprint ....... {:>12}  ({} / leaf)",
        fmt_bytes(heap),
        fmt_bytes(bytes_per_leaf as usize)
    );
    println!("└─");
    println!();
}

/// A cheap, branch-distinct byte derived from a proof so timed closures have an
/// observable side effect the optimiser cannot discard.
fn proof_tag(proof: &Proof) -> u8 {
    match proof {
        Proof::Existence(p) => p.root_hash[0] ^ p.value_hash[0],
        Proof::NonExistence(p) => p.root_hash[0] ^ 0x80,
    }
}

fn main() {
    let sizes: Vec<u64> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .collect();
    let sizes = if sizes.is_empty() {
        vec![100, 1_000, 10_000]
    } else {
        sizes
    };

    println!("Olympus SMT round-trip + storage benchmark");
    println!("  tree depth (SMT_DEPTH) : {SMT_DEPTH}");
    println!(
        "  build profile          : {}",
        if cfg!(debug_assertions) {
            "DEBUG (run with --release for representative numbers!)"
        } else {
            "release"
        }
    );
    println!();

    for n in sizes {
        bench_size(n);
    }
}
