# Olympus Performance Benchmarks

This directory contains performance benchmarks for the Olympus ledger system.

## Running Benchmarks

Run all benchmarks:
```bash
python benchmarks/run_all.py
```

Run individual benchmarks:
```bash
python benchmarks/bench_poseidon.py
python benchmarks/bench_merkle.py
python benchmarks/bench_proofs.py
python benchmarks/bench_memory.py
```

## Benchmark Results

Results are saved to `benchmarks/results/` in JSON format for easy graphing and analysis.

## What We Measure

1. **Poseidon Hash Throughput**: Hashes per second for BN128 Poseidon hash function
2. **Merkle Tree Generation**: Time complexity showing O(n log n) scaling
3. **Proof Generation Latency**: Time to generate inclusion proofs
4. **Memory Usage**: Peak memory consumption for various operations

## Performance Goals

These benchmarks help demonstrate that Olympus is production-ready by showing:
- Competitive hash performance
- Linear scaling for tree generation
- Fast proof generation
- Reasonable memory footprint
