#!/usr/bin/env python3
"""
Olympus Groth16 Trusted Setup Ceremony — Contribution Tool

What this does:
  Guides a participant through contributing to the Groth16 trusted setup.
  Each participant adds randomness to the proving key. As long as ONE participant
  is honest (destroys their secret), no one can forge proofs — not even us.

Usage:
  python tools/ceremony_contribute.py --help

Security note:
  After running this tool, you MUST securely delete the toxic waste file.
  Use `shred -u <file>` on Linux or secure-erase on macOS.
  The tool will remind you.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


logger = logging.getLogger(__name__)


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 of a file. Used to verify ceremony artifacts."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _check_snarkjs() -> bool:
    """Check if snarkjs is available."""
    try:
        result = subprocess.run(
            ["npx", "snarkjs", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except FileNotFoundError:
        logger.debug("snarkjs not found in PATH (npx/node not installed)")
        return False
    except subprocess.TimeoutExpired:
        logger.debug("snarkjs version check timed out — snarkjs may be installed but unresponsive")
        return False


def contribute(
    ptau_path: Path,
    circuit_path: Path,
    participant_name: str,
    output_path: Path,
    entropy: str | None = None,
) -> dict:
    """
    Contribute to the Groth16 trusted setup.

    Args:
        ptau_path: Path to the Phase 1 Powers of Tau file.
        circuit_path: Path to the Circom circuit source.
        participant_name: Human-readable name for this contribution.
        output_path: Where to write the contribution .zkey file.
        entropy: Optional additional entropy string (leave None for random).

    Returns:
        Dict with contribution metadata (hash, name, timestamp).
    """
    if not ptau_path.exists():
        raise FileNotFoundError(f"Phase 1 ptau not found: {ptau_path}")
    if not circuit_path.exists():
        raise FileNotFoundError(f"Circuit not found: {circuit_path}")
    if not _check_snarkjs():
        raise RuntimeError("snarkjs not found. Install with: npm install -g snarkjs")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate entropy if not provided.
    # This is your secret contribution — it MUST be destroyed after the ceremony.
    contribution_entropy = entropy or secrets.token_hex(64)

    logger.info("Starting Groth16 contribution for participant: %s", participant_name)
    logger.info("Circuit: %s", circuit_path)
    logger.info("Phase 1 ptau: %s", ptau_path)

    # Phase 2: contribute
    # snarkjs groth16 setup <circuit_r1cs> <ptau> <zkey_0>
    # snarkjs zkey contribute <zkey_0> <zkey_1> --name="<name>" -e="<entropy>"
    r1cs_path = circuit_path.with_suffix(".r1cs")
    if not r1cs_path.exists():
        raise FileNotFoundError(
            f"Compiled circuit R1CS not found: {r1cs_path}\n"
            "Compile the circuit first: circom circuit.circom --r1cs --wasm"
        )

    # Use a fixed, obviously-temporary name so cleanup scripts can reliably find it.
    # WARNING: this file contains toxic waste — it MUST be securely deleted after use.
    initial_zkey = output_path.parent / "initial_DONOTCOMMIT.zkey"

    # Step 1: Generate initial phase 2 key
    setup_result = subprocess.run(
        ["npx", "snarkjs", "groth16", "setup", str(r1cs_path), str(ptau_path), str(initial_zkey)],
        capture_output=True,
        text=True,
    )
    if setup_result.returncode != 0:
        raise RuntimeError(
            f"snarkjs groth16 setup failed (exit {setup_result.returncode}):\n{setup_result.stderr}"
        )

    # Step 2: Contribute
    contribute_result = subprocess.run(
        [
            "npx",
            "snarkjs",
            "zkey",
            "contribute",
            str(initial_zkey),
            str(output_path),
            f"--name={participant_name}",
            f"-e={contribution_entropy}",
        ],
        capture_output=True,
        text=True,
    )
    if contribute_result.returncode != 0:
        raise RuntimeError(
            f"snarkjs zkey contribute failed (exit {contribute_result.returncode}):\n"
            f"{contribute_result.stderr}"
        )

    # Compute contribution hash for public attestation
    contribution_hash = _sha256_file(output_path)
    circuit_hash = _sha256_file(circuit_path)

    metadata = {
        "participant": participant_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "contribution_hash": contribution_hash,
        "circuit_hash": circuit_hash,
        "output_path": str(output_path),
    }

    # Write metadata alongside the zkey
    meta_path = output_path.with_suffix(".json")
    meta_path.write_text(json.dumps(metadata, indent=2))

    logger.info("=== CONTRIBUTION COMPLETE ===")
    logger.info("Contribution hash (PUBLISH THIS): %s", contribution_hash)
    logger.info("Metadata written to: %s", meta_path)
    logger.warning(
        "\n*** SECURITY: You must now securely destroy your toxic waste ***\n"
        "Run: shred -u %s (Linux) or use secure-erase (macOS)\n"
        "The entropy used for your contribution must never be reconstructed.",
        initial_zkey,
    )

    return metadata


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(
        description="Contribute to the Olympus Groth16 trusted setup ceremony."
    )
    parser.add_argument(
        "--ptau", required=True, type=Path, help="Path to Phase 1 Powers of Tau file"
    )
    parser.add_argument("--circuit", required=True, type=Path, help="Path to Circom circuit source")
    parser.add_argument(
        "--participant-name", required=True, help="Your name or organization (will be published)"
    )
    parser.add_argument(
        "--output", required=True, type=Path, help="Output path for your .zkey contribution"
    )
    parser.add_argument(
        "--entropy", default=None, help="Additional entropy string (optional, random by default)"
    )
    args = parser.parse_args()

    try:
        metadata = contribute(
            ptau_path=args.ptau,
            circuit_path=args.circuit,
            participant_name=args.participant_name,
            output_path=args.output,
            entropy=args.entropy,
        )
        logger.info("\nContribution hash: %s", metadata["contribution_hash"])
        logger.info("Please publish this hash publicly (tweet, GitHub issue, etc.)")
        return 0
    except Exception as exc:
        logger.error("Ceremony contribution failed: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
