#!/usr/bin/env python3
"""Benchmark for memory usage profiling.

Measures peak memory consumption for various operations.
"""

import json
import tracemalloc
from pathlib import Path

from protocol.merkle import MerkleTree
from protocol.poseidon_tree import PoseidonMerkleTree


def measure_memory(operation_name: str, operation_func) -> dict:
    """Measure peak memory usage of an operation.

    Args:
        operation_name: Name of the operation
        operation_func: Callable that performs the operation

    Returns:
        Dictionary with memory usage statistics
    """
    tracemalloc.start()
    tracemalloc.reset_peak()

    # Run the operation
    operation_func()

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "operation": operation_name,
        "current_memory_bytes": current,
        "peak_memory_bytes": peak,
        "current_memory_mb": current / (1024 * 1024),
        "peak_memory_mb": peak / (1024 * 1024),
    }


def benchmark_merkle_tree_memory(num_leaves: int) -> dict:
    """Measure memory usage for BLAKE3 Merkle tree construction.

    Args:
        num_leaves: Number of leaves in the tree

    Returns:
        Memory usage statistics
    """

    def build_tree():
        leaves = [f"leaf_{i}".encode() for i in range(num_leaves)]
        tree = MerkleTree(leaves)
        _ = tree.get_root()

    return measure_memory(f"MerkleTree({num_leaves} leaves)", build_tree)


def benchmark_poseidon_tree_memory(num_leaves: int) -> dict:
    """Measure memory usage for Poseidon Merkle tree construction.

    Args:
        num_leaves: Number of leaves in the tree

    Returns:
        Memory usage statistics
    """

    def build_tree():
        leaves = [f"leaf_{i}".encode() for i in range(num_leaves)]
        tree = PoseidonMerkleTree(leaves)
        _ = tree.get_root()

    return measure_memory(f"PoseidonMerkleTree({num_leaves} leaves)", build_tree)


def benchmark_proof_memory(num_leaves: int) -> dict:
    """Measure memory usage for proof generation.

    Args:
        num_leaves: Number of leaves in the tree

    Returns:
        Memory usage statistics
    """
    leaves = [f"leaf_{i}".encode() for i in range(num_leaves)]
    tree = MerkleTree(leaves)

    def generate_proofs():
        for i in range(min(100, num_leaves)):
            _ = tree.generate_proof(i % num_leaves)

    return measure_memory(f"MerkleProofs({num_leaves} leaves)", generate_proofs)


def main():
    """Run memory benchmarks and save results."""
    print("=" * 60)
    print("Memory Usage Profiling")
    print("=" * 60)

    tree_sizes = [100, 500, 1000, 5000, 10000]

    print("\n[1/3] BLAKE3 Merkle Tree Memory Usage:")
    print("\n  Tree Size | Peak Memory (MB)")
    print("  " + "-" * 35)

    merkle_results = []
    for size in tree_sizes:
        result = benchmark_merkle_tree_memory(size)
        merkle_results.append(result)
        print(f"  {size:>9} | {result['peak_memory_mb']:>15.2f}")

    print("\n[2/3] Poseidon Merkle Tree Memory Usage:")
    print("\n  Tree Size | Peak Memory (MB)")
    print("  " + "-" * 35)

    poseidon_results = []
    for size in tree_sizes:
        result = benchmark_poseidon_tree_memory(size)
        poseidon_results.append(result)
        print(f"  {size:>9} | {result['peak_memory_mb']:>15.2f}")

    print("\n[3/3] Proof Generation Memory Usage:")
    print("\n  Tree Size | Peak Memory (MB)")
    print("  " + "-" * 35)

    proof_results = []
    for size in tree_sizes:
        result = benchmark_proof_memory(size)
        proof_results.append(result)
        print(f"  {size:>9} | {result['peak_memory_mb']:>15.2f}")

    # Save results
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)

    output_file = results_dir / "memory_benchmark.json"
    with open(output_file, "w") as f:
        json.dump(
            {
                "merkle_tree_memory": merkle_results,
                "poseidon_tree_memory": poseidon_results,
                "proof_generation_memory": proof_results,
            },
            f,
            indent=2,
        )

    print(f"\n✓ Results saved to {output_file}")
    print("\nNote: Memory usage should scale linearly with tree size.")


if __name__ == "__main__":
    main()
