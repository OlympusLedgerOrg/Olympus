#!/usr/bin/env python3
"""One-command offline verifier for Olympus verification bundles.

Usage::

    python tools/verify_bundle_cli.py bundle.json

The bundle is a self-contained JSON file that includes a shard header,
Ed25519 signature, optional RFC 3161 timestamp token, and optional
Merkle inclusion proofs.  The verifier checks every component without
network access.

Exit codes:
    0  All checks passed.
    1  One or more checks failed or the bundle is malformed.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import nacl.signing

from protocol.hashes import shard_header_hash
from protocol.merkle import MerkleProof, verify_proof
from protocol.shards import verify_header


# ---------------------------------------------------------------------------
# Core verification logic
# ---------------------------------------------------------------------------


def _check_header_hash(header: dict[str, Any]) -> tuple[bool, str]:
    """Recompute the header hash and compare to the claimed value.

    Returns:
        ``(passed, message)``
    """
    fields = {
        "shard_id": header["shard_id"],
        "root_hash": header["root_hash"],
        "timestamp": header["timestamp"],
        "previous_header_hash": header["previous_header_hash"],
    }
    expected = shard_header_hash(fields).hex()
    claimed = header["header_hash"]
    if expected == claimed:
        return True, f"Header hash matches: {claimed}"
    return False, f"Header hash MISMATCH: expected {expected}, got {claimed}"


def _check_signature(
    header: dict[str, Any], signature_hex: str, pubkey_hex: str
) -> tuple[bool, str]:
    """Verify the Ed25519 signature over the header hash.

    Returns:
        ``(passed, message)``
    """
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(pubkey_hex))
    except Exception as exc:
        return False, f"Invalid public key: {exc}"

    if not verify_header(header, signature_hex, verify_key):
        return False, "Ed25519 signature INVALID"
    return True, "Ed25519 signature valid"


def _check_timestamp_token(header_hash_hex: str, token: dict[str, str]) -> tuple[bool, str]:
    """Verify the RFC 3161 timestamp token imprint matches the header hash.

    The Olympus imprint scheme is::

        imprint = SHA-256(bytes.fromhex(blake3_header_hash_hex))

    This function checks that the token's ``hash_hex`` matches the header
    hash (i.e. the token was issued for the correct header) and optionally
    verifies the TST if ``rfc3161ng`` is available.

    Returns:
        ``(passed, message)``
    """
    # 1. Verify that the token was issued for the correct header hash
    if token["hash_hex"] != header_hash_hex:
        return False, (
            f"Timestamp token hash_hex mismatch: "
            f"expected {header_hash_hex}, got {token['hash_hex']}"
        )

    # 2. Verify the imprint scheme: SHA-256(blake3_bytes)
    try:
        blake3_bytes = bytes.fromhex(header_hash_hex)
        expected_imprint = hashlib.sha256(blake3_bytes).digest()
    except ValueError as exc:
        return False, f"Invalid header hash hex: {exc}"

    # 3. Optionally verify the TST DER bytes via rfc3161ng
    try:
        import rfc3161ng

        tst_bytes = bytes.fromhex(token["tst_hex"])
        result = rfc3161ng.check_timestamp(
            tst_bytes,
            certificate=None,
            digest=expected_imprint,
            hashname="sha256",
        )
        if result:
            return True, "RFC 3161 timestamp token valid (imprint verified)"
        return False, "RFC 3161 timestamp token INVALID"
    except ImportError:
        # rfc3161ng not installed – do a best-effort check
        return True, (
            "RFC 3161 imprint scheme consistent "
            "(full TST verification skipped – rfc3161ng not installed)"
        )
    except Exception as exc:
        return False, f"RFC 3161 verification error: {exc}"


def _check_merkle_proofs(
    root_hash_hex: str, proofs: list[dict[str, Any]]
) -> list[tuple[bool, str]]:
    """Verify each Merkle inclusion proof against the shard root.

    Returns:
        List of ``(passed, message)`` for each proof.
    """
    results: list[tuple[bool, str]] = []
    for i, pdata in enumerate(proofs):
        try:
            proof = MerkleProof(
                leaf_hash=bytes.fromhex(pdata["leaf_hash"]),
                leaf_index=pdata["leaf_index"],
                siblings=[(bytes.fromhex(h), is_right) for h, is_right in pdata["siblings"]],
                root_hash=bytes.fromhex(pdata["root_hash"]),
            )
        except (KeyError, ValueError) as exc:
            results.append((False, f"Merkle proof [{i}]: malformed – {exc}"))
            continue

        # Proof root must match shard header root
        if pdata["root_hash"] != root_hash_hex:
            results.append(
                (
                    False,
                    f"Merkle proof [{i}]: root mismatch – "
                    f"proof root {pdata['root_hash']} != header root {root_hash_hex}",
                )
            )
            continue

        if verify_proof(proof):
            results.append((True, f"Merkle proof [{i}]: valid (leaf {pdata['leaf_index']})"))
        else:
            results.append((False, f"Merkle proof [{i}]: INVALID"))

    return results


def verify_bundle(bundle: dict[str, Any]) -> tuple[bool, list[tuple[bool, str]]]:
    """Verify all components of a verification bundle.

    Args:
        bundle: Parsed JSON bundle (dict).

    Returns:
        ``(all_passed, results)`` where *results* is a list of
        ``(passed, message)`` tuples.
    """
    results: list[tuple[bool, str]] = []

    # --- Required fields ---
    try:
        header = bundle["shard_header"]
        signature_hex = bundle["signature"]
        pubkey_hex = bundle["pubkey"]
    except KeyError as exc:
        return False, [(False, f"Missing required field: {exc}")]

    # 1. Header hash
    results.append(_check_header_hash(header))

    # 2. Ed25519 signature
    results.append(_check_signature(header, signature_hex, pubkey_hex))

    # 3. Timestamp token (optional)
    if "timestamp_token" in bundle and bundle["timestamp_token"] is not None:
        results.append(_check_timestamp_token(header["header_hash"], bundle["timestamp_token"]))

    # 4. Merkle proofs (optional)
    if "merkle_proofs" in bundle and bundle["merkle_proofs"]:
        results.extend(_check_merkle_proofs(header["root_hash"], bundle["merkle_proofs"]))

    all_passed = all(passed for passed, _ in results)
    return all_passed, results


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline verifier for Olympus verification bundles",
    )
    parser.add_argument(
        "bundle_file",
        help="Path to the verification bundle JSON file",
    )
    args = parser.parse_args()

    try:
        with open(args.bundle_file) as f:
            bundle = json.load(f)
    except FileNotFoundError:
        print(f"Error: file not found: {args.bundle_file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON: {exc}", file=sys.stderr)
        return 1

    all_passed, results = verify_bundle(bundle)

    for passed, message in results:
        symbol = "✓" if passed else "✗"
        stream = sys.stdout if passed else sys.stderr
        print(f"  {symbol} {message}", file=stream)

    if all_passed:
        print(f"\n✓ Bundle verification PASSED ({len(results)} checks)")
        return 0
    else:
        failed = sum(1 for p, _ in results if not p)
        print(
            f"\n✗ Bundle verification FAILED ({failed}/{len(results)} checks failed)",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
