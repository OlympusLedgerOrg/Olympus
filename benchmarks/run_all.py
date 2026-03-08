#!/usr/bin/env python3
"""Run all Olympus performance benchmarks."""

import subprocess
import sys
from pathlib import Path


def run_benchmark(script_name: str) -> int:
    """Run a benchmark script.

    Args:
        script_name: Name of the benchmark script

    Returns:
        Exit code from the script
    """
    script_path = Path(__file__).parent / script_name
    print(f"\n{'=' * 70}")
    print(f"Running {script_name}...")
    print(f"{'=' * 70}")

    result = subprocess.run([sys.executable, str(script_path)], check=False)
    return result.returncode


def main():
    """Run all benchmarks in sequence."""
    print("\n" + "=" * 70)
    print(" " * 20 + "OLYMPUS PERFORMANCE BENCHMARKS")
    print("=" * 70)

    benchmarks = [
        "bench_poseidon.py",
        "bench_merkle.py",
        "bench_proofs.py",
        "bench_memory.py",
    ]

    failed = []

    for benchmark in benchmarks:
        exit_code = run_benchmark(benchmark)
        if exit_code != 0:
            failed.append(benchmark)

    print("\n" + "=" * 70)
    print("BENCHMARK SUMMARY")
    print("=" * 70)

    if failed:
        print(f"\n❌ {len(failed)} benchmark(s) failed:")
        for name in failed:
            print(f"  - {name}")
        sys.exit(1)
    else:
        print("\n✓ All benchmarks completed successfully!")
        print(f"\nResults saved to: {Path(__file__).parent / 'results'}/")
        print("\nTo graph these results, use your favorite plotting tool with the JSON data.")


if __name__ == "__main__":
    main()
