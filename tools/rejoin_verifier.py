#!/usr/bin/env python3
"""
Safe rejoin verifier for Olympus nodes.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import nacl.exceptions
import nacl.signing


sys.path.insert(0, str(Path(__file__).parent.parent))

from protocol.canonical_json import canonical_json_bytes
from protocol.epochs import signed_tree_head_hash
from protocol.merkle import ct_merkle_root, merkle_leaf_hash, verify_consistency_proof


def _fetch_json(node_url: str, path: str, params: dict[str, Any]) -> Any:
    query = urllib.parse.urlencode(params)
    url = f"{node_url.rstrip('/')}{path}?{query}" if query else f"{node_url.rstrip('/')}{path}"
    with urllib.request.urlopen(url) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def _parse_sth(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "epoch_id": int(raw["epoch_id"]),
        "tree_size": int(raw["tree_size"]),
        "merkle_root": str(raw["merkle_root"]),
        "timestamp": str(raw["timestamp"]),
        "signature": str(raw["signature"]),
        "signer_pubkey": str(raw["signer_pubkey"]),
    }


def _verify_sth_signature(sth: dict[str, Any]) -> bool:
    try:
        payload_hash = signed_tree_head_hash(
            epoch_id=sth["epoch_id"],
            tree_size=sth["tree_size"],
            merkle_root=sth["merkle_root"],
            timestamp=sth["timestamp"],
        )
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(sth["signer_pubkey"]))
        verify_key.verify(payload_hash, bytes.fromhex(sth["signature"]))
        return True
    except (ValueError, nacl.exceptions.BadSignatureError):
        return False


def _entries_to_leaf_hashes(entries: list[dict[str, Any]]) -> list[bytes]:
    leaves: list[bytes] = []
    for entry in entries:
        canonical = canonical_json_bytes(entry)
        leaves.append(merkle_leaf_hash(canonical))
    return leaves


def verify_rejoin(*, node_url: str, shard_id: str, verbose: bool = False) -> str:
    """
    Verify remote ledger consistency for safe node rejoin.

    Args:
        node_url: Base URL for the remote Olympus node.
        shard_id: Shard identifier to verify.
        verbose: Whether to print progress diagnostics.

    Returns:
        One of: ``HEALTHY``, ``CATCHING_UP``, ``DIVERGED``.
    """
    history_payload = _fetch_json(node_url, "/protocol/sth/history", {"shard_id": shard_id, "n": 100})
    raw_sths = history_payload.get("sths", [])
    if not raw_sths:
        return "CATCHING_UP"

    sths = sorted((_parse_sth(item) for item in raw_sths), key=lambda item: item["epoch_id"])

    for sth in sths:
        if not _verify_sth_signature(sth):
            if verbose:
                print(f"Invalid STH signature at epoch {sth['epoch_id']}")
            return "DIVERGED"

    for previous, current in zip(sths, sths[1:]):
        if current["tree_size"] < previous["tree_size"]:
            if verbose:
                print("STH tree_size rollback detected")
            return "DIVERGED"
        if current["tree_size"] == previous["tree_size"] and current["merkle_root"] != previous["merkle_root"]:
            if verbose:
                print("STH root mismatch at equal tree_size")
            return "DIVERGED"

        proof_payload = _fetch_json(
            node_url,
            "/ledger/consistency_proof",
            {"from_size": previous["tree_size"], "to_size": current["tree_size"]},
        )
        proof_hex = proof_payload.get("proof", [])
        proof = [bytes.fromhex(item) for item in proof_hex]
        if not verify_consistency_proof(
            bytes.fromhex(previous["merkle_root"]),
            bytes.fromhex(current["merkle_root"]),
            proof,
            previous["tree_size"],
            current["tree_size"],
        ):
            if verbose:
                print("Consistency proof verification failed")
            return "DIVERGED"

    latest = sths[-1]
    entries_payload = _fetch_json(
        node_url,
        "/ledger/entries",
        {"start": 0, "shard_id": shard_id},
    )
    entries = entries_payload.get("entries", entries_payload if isinstance(entries_payload, list) else [])
    if not isinstance(entries, list):
        return "DIVERGED"

    if len(entries) < latest["tree_size"]:
        return "CATCHING_UP"
    if latest["tree_size"] == 0:
        return "HEALTHY"

    leaf_hashes = _entries_to_leaf_hashes(entries[: latest["tree_size"]])
    if not leaf_hashes:
        return "DIVERGED"
    recomputed_root = ct_merkle_root(leaf_hashes).hex()
    if recomputed_root != latest["merkle_root"]:
        if verbose:
            print("Recomputed Merkle root does not match latest STH")
        return "DIVERGED"
    return "HEALTHY"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Olympus shard state before node rejoin")
    parser.add_argument("--node-url", required=True, help="Base URL for the Olympus node")
    parser.add_argument("--shard-id", required=True, help="Shard identifier")
    parser.add_argument("--verbose", action="store_true", help="Print detailed verification steps")
    args = parser.parse_args()

    try:
        status = verify_rejoin(node_url=args.node_url, shard_id=args.shard_id, verbose=args.verbose)
    except Exception as exc:  # pragma: no cover - CLI guard
        print(f"DIVERGED ({exc})", file=sys.stderr)
        return 1

    print(status)
    return 0 if status != "DIVERGED" else 2


if __name__ == "__main__":
    sys.exit(main())
