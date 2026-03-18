#!/usr/bin/env python3
"""Cross-language determinism harness for Olympus verifiers.

Generates deterministic random records, hashes them with Python/Go/Rust/JavaScript
implementations, and fails on any divergence.
"""

from __future__ import annotations

import base64
import json
import os
import random
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from protocol.hashes import blake3_hash  # noqa: E402


VECTORS_PATH = REPO_ROOT / "verifiers" / "test_vectors" / "vectors.json"
RANDOM_CASES = int(os.environ.get("OLYMPUS_DETERMINISM_CASES", "5000"))
SEED = 0xC0FFEE
MAX_RECORD_BYTES = 512


def _load_canonical_vectors() -> list[bytes]:
    with open(VECTORS_PATH, encoding="utf-8") as f:
        vectors = json.load(f)
    return [vec["input_utf8"].encode("utf-8") for vec in vectors["blake3_raw"]]


def _generate_random_records(count: int) -> list[bytes]:
    rng = random.Random(SEED)
    records: list[bytes] = []
    for _ in range(count):
        size = rng.randint(0, MAX_RECORD_BYTES)
        records.append(bytes(rng.getrandbits(8) for _ in range(size)))
    return records


def _python_hashes(records: list[bytes]) -> list[str]:
    return [blake3_hash([record]).hex() for record in records]


def _run_batch(command: list[str], records: list[bytes], cwd: Path) -> list[str]:
    request = {
        "records_b64": [base64.b64encode(record).decode("ascii") for record in records]
    }
    proc = subprocess.run(
        command,
        input=json.dumps(request),
        text=True,
        capture_output=True,
        cwd=cwd,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command {' '.join(command)!r} failed with exit code {proc.returncode}:\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )

    response = json.loads(proc.stdout)
    hashes = response.get("hashes")
    if not isinstance(hashes, list):
        raise RuntimeError(f"Invalid response from {' '.join(command)!r}: {proc.stdout}")
    return hashes


def _assert_match(label: str, got: list[str], expected: list[str]) -> None:
    if len(got) != len(expected):
        raise AssertionError(
            f"{label} produced {len(got)} hashes, expected {len(expected)}"
        )
    for idx, (actual, exp) in enumerate(zip(got, expected, strict=True)):
        if actual != exp:
            raise AssertionError(
                f"{label} diverged at index={idx}: got={actual}, expected={exp}"
            )


def main() -> None:
    canonical_records = _load_canonical_vectors()
    random_records = _generate_random_records(RANDOM_CASES)
    records = canonical_records + random_records

    print(
        "Running cross-language determinism harness "
        f"(seed={SEED}, canonical={len(canonical_records)}, random={RANDOM_CASES})"
    )

    expected = _python_hashes(records)

    go_hashes = _run_batch(
        ["go", "run", "./cmd/hash_batch"],
        records,
        cwd=REPO_ROOT / "verifiers" / "go",
    )
    rust_hashes = _run_batch(
        ["cargo", "run", "--quiet", "--bin", "hash_batch"],
        records,
        cwd=REPO_ROOT / "verifiers" / "rust",
    )
    js_hashes = _run_batch(
        ["node", "hash_batch.js"],
        records,
        cwd=REPO_ROOT / "verifiers" / "javascript",
    )

    _assert_match("Go", go_hashes, expected)
    _assert_match("Rust", rust_hashes, expected)
    _assert_match("JavaScript", js_hashes, expected)

    print(f"✓ Cross-language determinism confirmed for {len(records)} records")


if __name__ == "__main__":
    main()
