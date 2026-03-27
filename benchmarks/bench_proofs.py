#!/usr/bin/env python3
"""Benchmark for proof generation latency.

Measures time to generate Merkle inclusion proofs.
"""

import json
import time
from pathlib import Path

from protocol.merkle import MerkleTree
from protocol.poseidon_tree import PoseidonMerkleTree


def benchmark_blake3_proof_generation(
    tree_sizes: list[int], proofs_per_size: int = 100
) -> list[dict]:
    """Benchmark BLAKE3 Merkle proof generation.

    Args:
        tree_sizes: List of tree sizes to test
        proofs_per_size: Number of proofs to generate per tree size

    Returns:
        List of benchmark results
    """
    results = []

    print("\n  Tree Size | Avg Proof Time (μs) | Proofs/sec")
    print("  " + "-" * 50)

    for size in tree_sizes:
        # Generate test tree
        leaves = [f"leaf_{i}".encode() for i in range(size)]
        tree = MerkleTree(leaves)

        # Measure proof generation
        start = time.perf_counter()
        for i in range(proofs_per_size):
            leaf_index = i % size
            _ = tree.generate_proof(leaf_index)
        elapsed = time.perf_counter() - start

        avg_time = elapsed / proofs_per_size
        proofs_per_second = proofs_per_size / elapsed

        results.append(
            {
                "tree_type": "BLAKE3_Merkle",
                "num_leaves": size,
                "proofs_generated": proofs_per_size,
                "total_elapsed_seconds": elapsed,
                "avg_proof_time_seconds": avg_time,
                "avg_proof_time_microseconds": avg_time * 1_000_000,
                "proofs_per_second": proofs_per_second,
            }
        )

        print(f"  {size:>9} | {avg_time * 1_000_000:>19.2f} | {proofs_per_second:>11.0f}")

    return results


def benchmark_poseidon_proof_generation(
    tree_sizes: list[int], proofs_per_size: int = 100
) -> list[dict]:
    """Benchmark Poseidon Merkle proof generation.

    Args:
        tree_sizes: List of tree sizes to test
        proofs_per_size: Number of proofs to generate per tree size

    Returns:
        List of benchmark results
    """
    results = []

    print("\n  Tree Size | Avg Proof Time (μs) | Proofs/sec")
    print("  " + "-" * 50)

    for size in tree_sizes:
        # Generate test tree
        leaves = [f"leaf_{i}".encode() for i in range(size)]
        tree = PoseidonMerkleTree(leaves)

        # Measure proof generation
        start = time.perf_counter()
        for i in range(proofs_per_size):
            leaf_index = i % size
            _ = tree.get_proof(leaf_index)
        elapsed = time.perf_counter() - start

        avg_time = elapsed / proofs_per_size
        proofs_per_second = proofs_per_size / elapsed

        results.append(
            {
                "tree_type": "Poseidon_Merkle",
                "num_leaves": size,
                "proofs_generated": proofs_per_size,
                "total_elapsed_seconds": elapsed,
                "avg_proof_time_seconds": avg_time,
                "avg_proof_time_microseconds": avg_time * 1_000_000,
                "proofs_per_second": proofs_per_second,
            }
        )

        print(f"  {size:>9} | {avg_time * 1_000_000:>19.2f} | {proofs_per_second:>11.0f}")

    return results


def main():
    """Run proof generation benchmarks and save results."""
    print("=" * 60)
    print("Proof Generation Latency Benchmark")
    print("=" * 60)

    tree_sizes = [16, 64, 256, 1024, 4096]
    proofs_per_size = 100

    print(f"\n[1/2] BLAKE3 Merkle Proof Generation ({proofs_per_size} proofs per tree):")
    blake3_results = benchmark_blake3_proof_generation(tree_sizes, proofs_per_size)

    print(f"\n[2/2] Poseidon Merkle Proof Generation ({proofs_per_size} proofs per tree):")
    poseidon_results = benchmark_poseidon_proof_generation(tree_sizes, proofs_per_size)

    # Save results
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)

    output_file = results_dir / "proof_benchmark.json"
    with open(output_file, "w") as f:
        json.dump(
            {"blake3_proofs": blake3_results, "poseidon_proofs": poseidon_results},
            f,
            indent=2,
        )

    print(f"\n✓ Results saved to {output_file}")
    print("\nNote: Proof generation should scale as O(log n) with tree size.")


if __name__ == "__main__":
    main()
