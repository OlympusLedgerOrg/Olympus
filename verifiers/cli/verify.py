#!/usr/bin/env python3
"""
Olympus CLI Verification Tool

Standalone command-line tool for verifying Olympus commitments.
"""

import argparse
import json
import sys
from pathlib import Path


# Add parent directory to path to import protocol modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from protocol.hashes import blake3_hash
from protocol.merkle import (
    MERKLE_VERSION,
    PROOF_VERSION,
    MerkleTree,
    deserialize_merkle_proof,
    verify_proof,
)
from protocol.poseidon_tree import PoseidonMerkleTree


def verify_blake3_command(args):
    """Verify a BLAKE3 hash."""
    if args.stdin:
        data = sys.stdin.buffer.read()
    elif args.data:
        data = args.data.encode("utf-8")
    elif args.file:
        data = Path(args.file).read_bytes()
    else:
        print("Error: Must provide --stdin, --data, or --file", file=sys.stderr)
        sys.exit(1)

    # Compute actual hash
    actual_hash = blake3_hash([data]).hex()

    # Compare with expected
    is_valid = actual_hash == args.hash.lower()

    if args.json:
        result = {
            "command": "blake3",
            "valid": is_valid,
            "actual_hash": actual_hash,
            "expected_hash": args.hash.lower(),
        }
        print(json.dumps(result, indent=2))
    else:
        print(f"Expected: {args.hash.lower()}")
        print(f"Actual:   {actual_hash}")
        print(f"Valid:    {'✓ YES' if is_valid else '✗ NO'}")

    sys.exit(0 if is_valid else 1)


def merkle_root_command(args):
    """Compute Merkle root from leaves."""
    leaves = []

    if args.stdin:
        # Read leaves from stdin (one per line)
        for line in sys.stdin:
            leaves.append(line.rstrip("\n").encode("utf-8"))
    elif args.leaves:
        # Read leaves from files
        for leaf_path in args.leaves:
            leaves.append(Path(leaf_path).read_bytes())
    else:
        print("Error: Must provide --stdin or --leaves", file=sys.stderr)
        sys.exit(1)

    if not leaves:
        print("Error: No leaves provided", file=sys.stderr)
        sys.exit(1)

    # Compute Merkle root
    tree = MerkleTree(leaves)
    root = tree.get_root().hex()

    if args.json:
        result = {
            "command": "merkle-root",
            "num_leaves": len(leaves),
            "root": root,
        }
        print(json.dumps(result, indent=2))
    else:
        print(f"Merkle Root: {root}")
        print(f"Leaves: {len(leaves)}")

    sys.exit(0)


def merkle_proof_command(args):
    """Verify a Merkle inclusion proof."""
    proof_data = json.loads(Path(args.proof).read_text())

    # Reconstruct proof object, handling both legacy and current sibling formats.
    # Legacy proofs use a list-of-dicts siblings format; current proofs use
    # [hash, is_right] pairs.  deserialize_merkle_proof handles both via its
    # existing normalisation logic for the [hash, is_right] form; the
    # dict-of-{hash, position} form used by this verifier is normalized here.
    siblings = proof_data.get("siblings") or []
    if siblings and isinstance(siblings[0], dict):
        # Convert {"hash": ..., "position": ...} → [hash_hex, position]
        proof_data = dict(proof_data)
        proof_data["siblings"] = [[s["hash"], s["position"]] for s in siblings]
    proof = deserialize_merkle_proof(proof_data)

    # Verify the proof
    is_valid = verify_proof(proof)

    if args.json:
        result = {
            "command": "merkle-proof",
            "valid": is_valid,
            "leaf_index": proof.leaf_index,
            "root_hash": proof.root_hash.hex(),
            "proof_version": proof.proof_version,
            "tree_version": proof.tree_version,
            "epoch": proof.epoch,
            "tree_size": proof.tree_size,
        }
        print(json.dumps(result, indent=2))
    else:
        print(f"Leaf Index:    {proof.leaf_index}")
        print(f"Root Hash:     {proof.root_hash.hex()}")
        print(f"proof_version: {proof.proof_version}")
        print(f"tree_version:  {proof.tree_version}")
        print(f"epoch:         {proof.epoch}")
        print(f"tree_size:     {proof.tree_size}")
        if proof.proof_version != PROOF_VERSION:
            print(
                f"Warning: proof_version '{proof.proof_version}' does not match "
                f"current '{PROOF_VERSION}'",
                file=sys.stderr,
            )
        if proof.tree_version != MERKLE_VERSION:
            print(
                f"Warning: tree_version '{proof.tree_version}' does not match "
                f"current '{MERKLE_VERSION}'",
                file=sys.stderr,
            )
        print(f"Valid:         {'✓ YES' if is_valid else '✗ NO'}")

    sys.exit(0 if is_valid else 1)


def poseidon_command(args):
    """Verify a Poseidon commitment."""
    if args.stdin:
        data = sys.stdin.buffer.read()
    elif args.file:
        data = Path(args.file).read_bytes()
    else:
        print("Error: Must provide --stdin or --file", file=sys.stderr)
        sys.exit(1)

    # Split data into chunks if needed
    chunk_size = args.chunk_size
    leaves = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]

    # Build Poseidon tree
    tree = PoseidonMerkleTree(leaves)
    actual_root = tree.get_root()

    # Compare with expected
    is_valid = actual_root == args.root

    if args.json:
        result = {
            "command": "poseidon",
            "valid": is_valid,
            "actual_root": actual_root,
            "expected_root": args.root,
            "num_leaves": len(leaves),
        }
        print(json.dumps(result, indent=2))
    else:
        print(f"Expected Root: {args.root}")
        print(f"Actual Root:   {actual_root}")
        print(f"Leaves:        {len(leaves)}")
        print(f"Valid:         {'✓ YES' if is_valid else '✗ NO'}")

    sys.exit(0 if is_valid else 1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Olympus CLI Verification Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--json", action="store_true", help="Output JSON format")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # blake3 command
    blake3_parser = subparsers.add_parser("blake3", help="Verify a BLAKE3 hash")
    blake3_parser.add_argument("--data", help="Data string to hash")
    blake3_parser.add_argument("--file", help="File to hash")
    blake3_parser.add_argument("--stdin", action="store_true", help="Read data from stdin")
    blake3_parser.add_argument("--hash", required=True, help="Expected hash (hex)")

    # merkle-root command
    merkle_parser = subparsers.add_parser("merkle-root", help="Compute Merkle root")
    merkle_parser.add_argument("--leaves", nargs="+", help="Leaf files")
    merkle_parser.add_argument(
        "--stdin", action="store_true", help="Read leaves from stdin (one per line)"
    )

    # merkle-proof command
    proof_parser = subparsers.add_parser("merkle-proof", help="Verify Merkle proof")
    proof_parser.add_argument("--proof", required=True, help="Proof JSON file")

    # poseidon command
    poseidon_parser = subparsers.add_parser("poseidon", help="Verify Poseidon commitment")
    poseidon_parser.add_argument("--file", help="File to commit")
    poseidon_parser.add_argument("--stdin", action="store_true", help="Read data from stdin")
    poseidon_parser.add_argument("--root", required=True, help="Expected Poseidon root")
    poseidon_parser.add_argument(
        "--chunk-size", type=int, default=256, help="Chunk size (default: 256)"
    )

    args = parser.parse_args()

    if args.command == "blake3":
        verify_blake3_command(args)
    elif args.command == "merkle-root":
        merkle_root_command(args)
    elif args.command == "merkle-proof":
        merkle_proof_command(args)
    elif args.command == "poseidon":
        poseidon_command(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
