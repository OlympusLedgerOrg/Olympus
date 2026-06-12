//! Throughput benchmark for dataset-manifest commit + proof generation.
//!
//! Usage:
//!   cargo run --release -p olympus-manifest --example bench_manifest -- [N] [SHARDS]
//!
//! Builds a synthetic dataset of `N` records across `SHARDS` shards, then times:
//!   * sealing (SMT build → manifest_root over all records), and
//!   * a single inclusion and a single exclusion proof.
//!
//! Reports wall-clock and records/sec. Content hashes are derived
//! deterministically so the run is reproducible. This is the harness behind the
//! published figures in `docs/benchmarks/manifest-throughput.md`.

use std::time::Instant;

use olympus_manifest::commit::seal;
use olympus_manifest::{DatasetMetadata, RecordEntry, RecordIndex, ShardRecords};

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let shards: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(8);

    // Guard the args used below: `i % shards` divides by `shards`, and the proof
    // sampling needs at least one record in "shard-000".
    if shards == 0 || n == 0 {
        eprintln!("usage: bench_manifest [N>=1] [SHARDS>=1]");
        std::process::exit(2);
    }

    eprintln!("generating {n} records across {shards} shards…");
    let gen_start = Instant::now();
    let mut shard_recs: Vec<ShardRecords> = (0..shards)
        .map(|s| ShardRecords {
            shard_id: format!("shard-{s:03}"),
            records: Vec::with_capacity(n / shards + 1),
        })
        .collect();
    for i in 0..n {
        let s = i % shards;
        // Deterministic 32-byte content hash from the record index.
        let ch = blake3::hash(&(i as u64).to_le_bytes());
        shard_recs[s].records.push(RecordEntry {
            record_id: format!("rec-{i:09}"),
            content_hash: ch.to_hex().to_string(),
            version: 1,
            byte_size: Some(4096),
        });
    }
    let index = RecordIndex { shards: shard_recs };
    let gen = gen_start.elapsed();
    eprintln!("  generated in {:.2}s", gen.as_secs_f64());

    // ── seal: build the SMT over all records, compute manifest_root ───────────
    let seal_start = Instant::now();
    let sealed = seal("bench", 1, 0, DatasetMetadata::default(), &index).expect("seal");
    let seal_dur = seal_start.elapsed();
    let rps = n as f64 / seal_dur.as_secs_f64();

    // ── proofs: one inclusion (present) + one exclusion (absent) ──────────────
    let inc_start = Instant::now();
    let inc = sealed
        .prove_inclusion("shard-000", "rec-000000000", 1)
        .expect("inclusion");
    let inc_dur = inc_start.elapsed();

    let exc_start = Instant::now();
    let exc = sealed
        .prove_exclusion("shard-000", "definitely-absent", 1)
        .expect("exclusion");
    let exc_dur = exc_start.elapsed();

    let inc_bytes = serde_json::to_vec(&inc).unwrap().len();
    let exc_bytes = serde_json::to_vec(&exc).unwrap().len();

    println!("records:            {n}");
    println!("shards:             {shards}");
    println!("manifest_root:      {}", sealed.manifest.manifest_root);
    println!(
        "seal (commit):      {:.3}s  ({:.0} records/sec)",
        seal_dur.as_secs_f64(),
        rps
    );
    println!(
        "inclusion proof:    {:.2}ms  ({inc_bytes} bytes JSON)",
        inc_dur.as_secs_f64() * 1e3
    );
    println!(
        "exclusion proof:    {:.2}ms  ({exc_bytes} bytes JSON)",
        exc_dur.as_secs_f64() * 1e3
    );
}
