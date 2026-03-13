#!/usr/bin/env python3
"""Benchmark Groth16 proof generation, circuit size, and gas estimates."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from proofs.proof_generator import ProofGenerator


REPO_ROOT = Path(__file__).resolve().parent.parent
PROOFS_DIR = REPO_ROOT / "proofs"
BUILD_DIR = PROOFS_DIR / "build"
RESULTS_DIR = Path(__file__).resolve().parent / "results"


def _snarkjs_command(snarkjs_bin: str, *args: str) -> list[str]:
    if snarkjs_bin == "npx":
        return ["npx", "snarkjs", *args]
    return [snarkjs_bin, *args]


def _snarkjs_available(snarkjs_bin: str) -> bool:
    return shutil.which(snarkjs_bin) is not None


def _load_inputs(circuit: str) -> dict[str, Any] | None:
    input_path = BUILD_DIR / f"{circuit}_input.json"
    if not input_path.exists():
        return None
    return json.loads(input_path.read_text(encoding="utf-8"))


def _maybe_generate_inputs(circuits: list[str]) -> None:
    if all((BUILD_DIR / f"{circuit}_input.json").exists() for circuit in circuits):
        return
    if shutil.which("node") is None:
        return
    script = PROOFS_DIR / "test_inputs" / "generate_inputs.js"
    if not script.exists():
        return
    subprocess.run(["node", str(script)], check=True, cwd=REPO_ROOT)


def _parse_constraints(output: str) -> int | None:
    for line in output.splitlines():
        if "Constraints" in line and ":" in line:
            value = line.split(":", maxsplit=1)[1].strip().split()[0]
            try:
                return int(value)
            except ValueError:
                return None
    return None


def _estimate_gas(constraints: int | None) -> dict[str, Any]:
    if constraints is None:
        return {"estimate": None, "method": "heuristic_constraints", "note": "constraints unavailable"}
    base_gas = 21_000
    per_constraint = 18
    return {
        "estimate": base_gas + constraints * per_constraint,
        "method": "heuristic_constraints",
        "note": "Approximate Ethereum gas estimate derived from constraint count.",
    }


def _measure_circuit_metrics(circuit: str, snarkjs_bin: str) -> dict[str, Any]:
    r1cs_path = BUILD_DIR / f"{circuit}.r1cs"
    metrics: dict[str, Any] = {"r1cs_bytes": None, "constraints": None}
    if not r1cs_path.exists():
        return metrics
    metrics["r1cs_bytes"] = r1cs_path.stat().st_size

    if _snarkjs_available(snarkjs_bin):
        result = subprocess.run(
            _snarkjs_command(snarkjs_bin, "r1cs", "info", str(r1cs_path)),
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            metrics["constraints"] = _parse_constraints(result.stdout)
    return metrics


def _measure_proof_generation(
    circuit: str,
    inputs: dict[str, Any] | None,
    snarkjs_bin: str,
    iterations: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "witness_seconds": None,
        "proof_seconds": None,
        "status": "skipped",
    }
    if inputs is None:
        result["status"] = "missing_inputs"
        return result
    if shutil.which("node") is None:
        result["status"] = "node_missing"
        return result
    if not _snarkjs_available(snarkjs_bin):
        result["status"] = "snarkjs_missing"
        return result

    generator = ProofGenerator(circuit, snarkjs_bin=snarkjs_bin)
    witness_times: list[float] = []
    prove_times: list[float] = []

    for _ in range(iterations):
        start = time.perf_counter()
        witness = generator.generate_witness(**inputs)
        witness_times.append(time.perf_counter() - start)

        if witness.witness_path is None or not witness.witness_path.exists():
            result["status"] = "missing_wasm"
            return result

        start = time.perf_counter()
        generator.prove(witness)
        prove_times.append(time.perf_counter() - start)

    result["status"] = "ok"
    result["witness_seconds"] = sum(witness_times) / len(witness_times)
    result["proof_seconds"] = sum(prove_times) / len(prove_times)
    return result


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark Olympus Groth16 circuits.")
    parser.add_argument(
        "--circuits",
        nargs="+",
        default=["document_existence", "non_existence", "redaction_validity"],
        help="Circuit names to benchmark.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Number of proof generations to average.",
    )
    parser.add_argument(
        "--snarkjs-bin",
        default="npx",
        help="snarkjs launcher (default: npx).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=RESULTS_DIR / "zk_proof_benchmark.json",
        help="Output JSON file for benchmark results.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    circuits = list(args.circuits)
    _maybe_generate_inputs(circuits)

    results: dict[str, Any] = {
        "circuits": {},
        "snarkjs_bin": args.snarkjs_bin,
        "iterations": args.iterations,
    }

    for circuit in circuits:
        inputs = _load_inputs(circuit)
        metrics = _measure_circuit_metrics(circuit, args.snarkjs_bin)
        proof_bench = _measure_proof_generation(
            circuit,
            inputs,
            args.snarkjs_bin,
            args.iterations,
        )
        results["circuits"][circuit] = {
            "inputs_available": inputs is not None,
            "metrics": metrics,
            "proof_generation": proof_bench,
            "gas_estimate": _estimate_gas(metrics.get("constraints")),
        }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Wrote benchmark results to {args.output}")


if __name__ == "__main__":
    main()
