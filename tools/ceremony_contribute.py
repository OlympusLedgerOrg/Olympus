#!/usr/bin/env python3
"""
tools/ceremony_contribute.py — CLI for Groth16 trusted-setup Phase 2 contributions.

Guides a single participant through contributing randomness to the Groth16
trusted setup ceremony. Wraps snarkjs under the hood and produces a JSON
metadata sidecar alongside the output .zkey file.

Usage:
    python tools/ceremony_contribute.py \
        --ptau path/to/phase1.ptau \
        --circuit path/to/circuit.circom \
        --participant "Alice" \
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
    1 — failure (snarkjs unavailable, subprocess error, timeout, etc.)
"""

from __future__ import annotations

import argparse
import json
import logging
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


# Standalone tools are often invoked from outside the repository root.
# Make internal imports deterministic instead of silently falling back.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from protocol.hashes import hash_hex  # noqa: E402


try:
    from protocol.timestamps import current_timestamp  # noqa: E402
except ImportError:  # pragma: no cover - exercised only when repo imports are unavailable
    current_timestamp = None

logger = logging.getLogger(__name__)

INITIAL_ZKEY_PREFIX = "_tmp_setup_"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _hash_file(path: Path) -> str:
    """Compute BLAKE3 hash of a file. Used to verify ceremony artifacts.

    Uses the canonical project hashing API so hashes are consistent with the
    rest of the Olympus toolchain.

    Args:
        path: Path to the file to hash.

    Returns:
        Lowercase hex-encoded BLAKE3 digest (64 characters).
    """
    return hash_hex(path.read_bytes())


def _format_timeout_error(step: str, timeout: subprocess.TimeoutExpired) -> RuntimeError:
    """Return a RuntimeError with details from a timed-out snarkjs command."""

    def _decode_output(value: bytes | str | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    stdout = _decode_output(timeout.output)
    stderr = _decode_output(timeout.stderr)
    details = [f"{step} timed out after {timeout.timeout} seconds"]
    if stdout:
        details.append(f"stdout: {stdout}")
    if stderr:
        details.append(f"stderr: {stderr}")
    return RuntimeError("; ".join(details))


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
    except FileNotFoundError:
        logger.debug("snarkjs not found in PATH (npx/node not installed)")
        return False
    except subprocess.TimeoutExpired:
        logger.debug("snarkjs version check timed out")
        return False


def _utc_now() -> str:
    """Return current UTC time as RFC3339 with Z suffix."""
    if current_timestamp is not None:
        return current_timestamp()
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
    entropy: str | None = None,
) -> dict[str, str]:
    """Run a Groth16 Phase 2 contribution for the given circuit.

    Args:
        ptau_path: Path to the Phase 1 Powers of Tau file.
        circuit_path: Path to the .circom source file (used for provenance hash).
        participant_name: Human-readable name of the contributor.
        output_path: Destination path for the final .zkey file.
        entropy: Optional entropy string. If omitted, a random value is generated.

    Returns:
        Metadata dict written to the sidecar JSON file.

    Raises:
        FileNotFoundError: If ptau_path, circuit_path, or the sibling .r1cs do not exist.
        RuntimeError: If snarkjs is unavailable or a subprocess exits non-zero.
    """
    if not ptau_path.exists():
        raise FileNotFoundError(f"PTAU file not found: {ptau_path}")
    if not circuit_path.exists():
        raise FileNotFoundError(f"Circuit not found: {circuit_path}")
    if not _check_snarkjs():
        raise RuntimeError("snarkjs not found. Install with: npm install -g snarkjs")

    r1cs_path = circuit_path.with_suffix(".r1cs")
    if not r1cs_path.exists():
        raise FileNotFoundError(f"R1CS file not found: {r1cs_path} — compile the circuit first")

    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    contribution_entropy = entropy or secrets.token_hex(64)
    initial_zkey = output_path.parent / f"{INITIAL_ZKEY_PREFIX}{secrets.token_hex(8)}.zkey"

    logger.info("Starting Groth16 contribution for participant: %s", participant_name)
    logger.info("Circuit source: %s", circuit_path)
    logger.info("Phase 1 ptau: %s", ptau_path)

    try:
        # Step 1: groth16 setup — produces the initial (pre-contribution) .zkey.
        try:
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
        except subprocess.TimeoutExpired as exc:
            raise _format_timeout_error("groth16 setup", exc) from exc
        if setup_result.returncode != 0:
            raise RuntimeError(
                f"groth16 setup failed (exit {setup_result.returncode}): {setup_result.stderr}"
            )

        # Step 2: zkey contribute — pass entropy via -e so snarkjs is
        # non-interactive while stdout/stderr are captured.
        try:
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
                timeout=3600,  # 60 minutes max
            )
        except subprocess.TimeoutExpired as exc:
            raise _format_timeout_error("zkey contribute", exc) from exc
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

    metadata: dict[str, str] = {
        "participant": participant_name,
        "timestamp": _utc_now(),
        "zkey_blake3_hex": zkey_hash,
        "circuit_blake3_hex": circuit_hash,
        "ptau_path": str(ptau_path),
        "circuit_path": str(circuit_path),
        "output_path": str(output_path),
    }

    sidecar = output_path.with_suffix(".metadata.json")
    sidecar.write_text(
        json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    logger.info("=== CONTRIBUTION COMPLETE ===")
    logger.info("zkey BLAKE3 hash (publish this): %s", zkey_hash)
    logger.info("Metadata written to: %s", sidecar)

    return metadata


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """Entry point for the ceremony contribution CLI.

    Guides a participant through contributing to the Groth16 trusted setup.
    Exits 0 on success, 1 on failure.
    """
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
        help="Path to the Circom source (.circom); sibling .r1cs must already exist.",
    )
    parser.add_argument(
        "--participant",
        "--participant-name",
        dest="participant_name",
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
    parser.add_argument(
        "--entropy",
        default=None,
        help="Additional entropy string (optional, random by default).",
    )
    args = parser.parse_args()

    try:
        contribute(
            ptau_path=args.ptau,
            circuit_path=args.circuit,
            participant_name=args.participant_name,
            output_path=args.output,
            entropy=args.entropy,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        logger.error("Ceremony contribution failed: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
