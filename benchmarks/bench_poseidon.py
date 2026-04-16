#!/usr/bin/env python3
"""Benchmark for Poseidon hash throughput.

Measures hashes per second for the BN128 Poseidon hash function.
"""

import json
import time
from pathlib import Path

from protocol.hashes import SNARK_SCALAR_FIELD
from protocol.poseidon import poseidon_hash_bn128


def benchmark_poseidon_throughput(iterations: int = 10000) -> dict[str, float]:
    """Benchmark Poseidon hash throughput.

    Args:
        iterations: Number of hashes to compute

    Returns:
        Dictionary with benchmark results
    """
    # Use fixed inputs to ensure consistent measurements
    left = 12345
    right = 67890

    start = time.perf_counter()
    for _ in range(iterations):
        _ = poseidon_hash_bn128(left, right)
    elapsed = time.perf_counter() - start

    hashes_per_second = iterations / elapsed

    return {
        "operation": "poseidon_hash_bn128",
        "iterations": iterations,
        "elapsed_seconds": elapsed,
        "hashes_per_second": hashes_per_second,
        "avg_microseconds_per_hash": (elapsed / iterations) * 1_000_000,
    }


def benchmark_poseidon_batch(batch_sizes: list[int]) -> list[dict[str, float]]:
    """Benchmark Poseidon hashing with different batch sizes.

    Args:
        batch_sizes: List of batch sizes to test

    Returns:
        List of benchmark results for each batch size
    """
    results = []

    for batch_size in batch_sizes:
        # Generate test data
        pairs = [(i % SNARK_SCALAR_FIELD, (i + 1) % SNARK_SCALAR_FIELD) for i in range(batch_size)]

        start = time.perf_counter()
        for left, right in pairs:
            _ = poseidon_hash_bn128(left, right)
        elapsed = time.perf_counter() - start

        results.append(
            {
                "operation": "poseidon_batch",
                "batch_size": batch_size,
                "elapsed_seconds": elapsed,
                "hashes_per_second": batch_size / elapsed,
            }
        )

    return results


def main():
    """Run Poseidon benchmarks and save results."""
    print("=" * 60)
    print("Poseidon Hash Throughput Benchmark")
    print("=" * 60)

    # Single hash throughput
    print("\n[1/2] Measuring single-hash throughput...")
    throughput_result = benchmark_poseidon_throughput(iterations=10000)
    print(f"  Iterations: {throughput_result['iterations']}")
    print(f"  Total time: {throughput_result['elapsed_seconds']:.3f}s")
    print(f"  Throughput: {throughput_result['hashes_per_second']:.0f} hashes/sec")
    print(f"  Avg latency: {throughput_result['avg_microseconds_per_hash']:.2f} μs/hash")

    # Batch sizes
    print("\n[2/2] Measuring throughput for different batch sizes...")
    batch_sizes = [10, 100, 1000, 5000, 10000]
    batch_results = benchmark_poseidon_batch(batch_sizes)

    print("\n  Batch Size | Hashes/Sec")
    print("  " + "-" * 30)
    for result in batch_results:
        print(f"  {result['batch_size']:>10} | {result['hashes_per_second']:>10.0f}")

    # Save results
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)

    output_file = results_dir / "poseidon_benchmark.json"
    with open(output_file, "w") as f:
        json.dump(
            {"throughput": throughput_result, "batch_results": batch_results},
            f,
            indent=2,
        )

    print(f"\n✓ Results saved to {output_file}")


if __name__ == "__main__":
    main()
