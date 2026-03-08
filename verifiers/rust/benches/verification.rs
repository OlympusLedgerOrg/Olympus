use criterion::{criterion_group, criterion_main, Criterion};
use olympus_verifier::{compute_blake3, merkle_leaf_hash, compute_merkle_root};

fn benchmark_blake3(c: &mut Criterion) {
    let data = b"benchmark data for blake3";
    c.bench_function("blake3_hash", |b| b.iter(|| compute_blake3(data)));
}

fn benchmark_merkle_root(c: &mut Criterion) {
    let leaves: Vec<Vec<u8>> = (0..8).map(|i| format!("leaf{}", i).into_bytes()).collect();
    c.bench_function("merkle_root_8_leaves", |b| b.iter(|| compute_merkle_root(&leaves)));
}

criterion_group!(benches, benchmark_blake3, benchmark_merkle_root);
criterion_main!(benches);
