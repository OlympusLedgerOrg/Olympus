#!/usr/bin/env python3
"""
tools/ceremony_contribute.py — CLI for Groth16 trusted-setup Phase 2 contributions.

Guides a single participant through contributing randomness to the Groth16
trusted setup ceremony.  Wraps snarkjs under the hood and produces a JSON
metadata sidecar alongside the output .zkey file.

Usage:
    python tools/ceremony_contribute.py \\
        --ptau path/to/phase1.ptau \\
        --circuit path/to/circuit.circom \\
        --participant "Alice" \\
        --output path/to/contribution.zkey

The tool:
    1. Verifies snarkjs is available.
    2. Runs ``snarkjs groth16 setup`` to produce an intermediate .zkey.
    3. Runs ``snarkjs zkey contribute`` to fold the participant's entropy.
    4. Always removes the intermediate .zkey (sensitive material) in a
       try/finally block, even if step 3 fails.
    5. Writes a JSON metadata file alongside the output .zkey.

Exit codes:
    0 — success
    1 — failure (snarkjs unavailable, subprocess error, etc.)
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path

import blake3 as _blake3

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _hash_file(path: Path) -> str:
    """Compute BLAKE3 hash of a file. Used to verify ceremony artifacts.

    Uses BLAKE3 per project policy (not SHA-256) so hashes are consistent
    with the rest of the Olympus toolchain.

    Args:
        path: Path to the file to hash.

    Returns:
        Lowercase hex-encoded BLAKE3 digest (64 characters).
    """
    hasher = _blake3.blake3()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            hasher.update(chunk)
    return hasher.hexdigest()


def _check_snarkjs() -> bool:
    """Return True if snarkjs is available via npx, False otherwise."""
    try:
        result = subprocess.run(
            ["npx", "snarkjs", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _utc_now() -> str:
    """Return current UTC time as RFC3339 with Z suffix."""
    try:
        from protocol.timestamps import current_timestamp

        return current_timestamp()
    except ImportError:
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def contribute(
    *,
    ptau_path: Path,
    circuit_path: Path,
    participant_name: str,
    output_path: Path,
) -> dict:
    """Run a Groth16 Phase 2 contribution for the given circuit.

    Args:
        ptau_path: Path to the Phase 1 Powers of Tau file.
        circuit_path: Path to the .circom source file (used for provenance hash).
        participant_name: Human-readable name of the contributor.
        output_path: Destination path for the final .zkey file.

    Returns:
        Metadata dict written to the sidecar JSON file.

    Raises:
        FileNotFoundError: If ptau_path or circuit_path do not exist.
        RuntimeError: If snarkjs groth16 setup or zkey contribute fails.
    """
    if not ptau_path.exists():
        raise FileNotFoundError(f"PTAU file not found: {ptau_path}")
    if not circuit_path.exists():
        raise FileNotFoundError(f"Circuit not found: {circuit_path}")

    r1cs_path = circuit_path.with_suffix(".r1cs")
    if not r1cs_path.exists():
        raise FileNotFoundError(
            f"R1CS file not found: {r1cs_path} — compile the circuit first"
        )

    output_path = output_path.resolve()
    initial_zkey = output_path.parent / "initial_DONOTCOMMIT.zkey"

    try:
        # Step 1: groth16 setup — produces the initial (pre-contribution) .zkey
        setup_result = subprocess.run(
            [
                "npx",
                "snarkjs",
                "groth16",
                "setup",
                str(r1cs_path),
                str(ptau_path),
                str(initial_zkey),
            ],
            capture_output=True,
            text=True,
            timeout=1800,  # 30 minutes max
        )
        if setup_result.returncode != 0:
            raise RuntimeError(
                f"groth16 setup failed (exit {setup_result.returncode}): "
                f"{setup_result.stderr}"
            )

        # Step 2: zkey contribute — folds participant's entropy
        contribute_result = subprocess.run(
            [
                "npx",
                "snarkjs",
                "zkey",
                "contribute",
                str(initial_zkey),
                str(output_path),
                f"--name={participant_name}",
                "-v",
            ],
            capture_output=True,
            text=True,
            timeout=3600,  # 60 minutes max
        )
        if contribute_result.returncode != 0:
            raise RuntimeError(
                f"zkey contribute failed (exit {contribute_result.returncode}): "
                f"{contribute_result.stderr}"
            )

    finally:
        # Always attempt to remove the intermediate key — it's sensitive material
        # even if the ceremony failed. Log a warning if removal fails.
        if initial_zkey.exists():
            try:
                initial_zkey.unlink()
                logger.info("Removed intermediate key: %s", initial_zkey)
            except OSError:
                logger.warning(
                    "Could not remove intermediate key %s — delete it manually",
                    initial_zkey,
                    exc_info=True,
                )

    zkey_hash = _hash_file(output_path)
    circuit_hash = _hash_file(circuit_path)

    metadata: dict = {
        "participant": participant_name,
        "timestamp": _utc_now(),
        "zkey_blake3_hex": zkey_hash,       # hash of the output .zkey file
        "circuit_blake3_hex": circuit_hash,  # hash of the circuit source
        "ptau_path": str(ptau_path),
        "circuit_path": str(circuit_path),
        "output_path": str(output_path),
    }

    sidecar = output_path.with_suffix(".metadata.json")
    sidecar.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    logger.info("Wrote metadata sidecar: %s", sidecar)

    return metadata


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """Entry point for the ceremony contribution CLI.

    Guides a participant through contributing to the Groth16 trusted setup.
    Exits 0 on success, 1 on failure.
    """
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Contribute randomness to the Groth16 trusted-setup ceremony."
    )
    parser.add_argument(
        "--ptau",
        required=True,
        type=Path,
        metavar="FILE",
        help="Path to the Phase 1 Powers of Tau (.ptau) file.",
    )
    parser.add_argument(
        "--circuit",
        required=True,
        type=Path,
        metavar="FILE",
        help="Path to the compiled circuit (.circom source for provenance).",
    )
    parser.add_argument(
        "--participant",
        required=True,
        metavar="NAME",
        help="Your name or pseudonym for the ceremony transcript.",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        metavar="FILE",
        help="Destination path for the contribution .zkey file.",
    )
    args = parser.parse_args()

    if not _check_snarkjs():
        logger.error(
            "snarkjs not found — install it with: npm install -g snarkjs"
        )
        return 1

    try:
        metadata = contribute(
            ptau_path=args.ptau,
            circuit_path=args.circuit,
            participant_name=args.participant,
            output_path=args.output,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        logger.error("%s", exc)
        return 1

    print(f"Contribution complete: {args.output}")
    print(f"  zkey_blake3_hex:    {metadata['zkey_blake3_hex']}")
    print(f"  circuit_blake3_hex: {metadata['circuit_blake3_hex']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
