#!/usr/bin/env python3
"""Benchmark for Merkle tree generation time.

Demonstrates O(n log n) scaling behavior for tree construction.
"""

import json
import math
import time
from pathlib import Path

from protocol.merkle import MerkleTree
from protocol.poseidon_tree import PoseidonMerkleTree


def benchmark_merkle_generation(tree_sizes: list[int]) -> list[dict]:
    """Benchmark BLAKE3 Merkle tree generation for different sizes.

    Args:
        tree_sizes: List of tree sizes (number of leaves) to test

    Returns:
        List of benchmark results
    """
    results = []

    print("\n  Tree Size | Time (ms) | Ops/sec | Expected O(n log n)")
    print("  " + "-" * 60)

    for size in tree_sizes:
        # Generate test leaves
        leaves = [f"leaf_{i}".encode("utf-8") for i in range(size)]

        # Measure tree construction
        start = time.perf_counter()
        tree = MerkleTree(leaves)
        _ = tree.get_root()
        elapsed = time.perf_counter() - start

        # Calculate expected complexity factor
        expected_factor = size * math.log2(max(size, 2))

        results.append(
            {
                "tree_type": "BLAKE3_Merkle",
                "num_leaves": size,
                "elapsed_seconds": elapsed,
                "elapsed_milliseconds": elapsed * 1000,
                "trees_per_second": 1 / elapsed if elapsed > 0 else float("inf"),
                "expected_complexity_factor": expected_factor,
            }
        )

        print(
            f"  {size:>9} | {elapsed * 1000:>9.2f} | "
            f"{1/elapsed:>7.1f} | {expected_factor:>8.0f}"
        )

    return results


def benchmark_poseidon_merkle_generation(tree_sizes: list[int]) -> list[dict]:
    """Benchmark Poseidon Merkle tree generation for different sizes.

    Args:
        tree_sizes: List of tree sizes (number of leaves) to test

    Returns:
        List of benchmark results
    """
    results = []

    print("\n  Tree Size | Time (ms) | Ops/sec | Expected O(n log n)")
    print("  " + "-" * 60)

    for size in tree_sizes:
        # Generate test leaves
        leaves = [f"leaf_{i}".encode("utf-8") for i in range(size)]

        # Measure tree construction
        start = time.perf_counter()
        tree = PoseidonMerkleTree(leaves)
        _ = tree.get_root()
        elapsed = time.perf_counter() - start

        # Calculate expected complexity factor
        expected_factor = size * math.log2(max(size, 2))

        results.append(
            {
                "tree_type": "Poseidon_Merkle",
                "num_leaves": size,
                "elapsed_seconds": elapsed,
                "elapsed_milliseconds": elapsed * 1000,
                "trees_per_second": 1 / elapsed if elapsed > 0 else float("inf"),
                "expected_complexity_factor": expected_factor,
            }
        )

        print(
            f"  {size:>9} | {elapsed * 1000:>9.2f} | "
            f"{1/elapsed:>7.1f} | {expected_factor:>8.0f}"
        )

    return results


def main():
    """Run Merkle tree benchmarks and save results."""
    print("=" * 60)
    print("Merkle Tree Generation Benchmark")
    print("=" * 60)

    # Test with exponentially increasing sizes to show O(n log n) scaling
    tree_sizes = [8, 16, 32, 64, 128, 256, 512, 1024, 2048]

    print("\n[1/2] BLAKE3 Merkle Trees:")
    blake3_results = benchmark_merkle_generation(tree_sizes)

    print("\n[2/2] Poseidon Merkle Trees:")
    poseidon_results = benchmark_poseidon_merkle_generation(tree_sizes)

    # Save results
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)

    output_file = results_dir / "merkle_benchmark.json"
    with open(output_file, "w") as f:
        json.dump(
            {"blake3_merkle": blake3_results, "poseidon_merkle": poseidon_results},
            f,
            indent=2,
        )

    print(f"\n✓ Results saved to {output_file}")
    print("\nNote: Times should scale approximately as O(n log n).")
    print("Compare elapsed_seconds with expected_complexity_factor ratios.")


if __name__ == "__main__":
    main()
