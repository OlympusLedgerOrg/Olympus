#!/usr/bin/env python3
"""
Verification CLI for Olympus

This tool verifies proofs and commitments in the Olympus protocol.
"""

import argparse
import json
import sys
from pathlib import Path


# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from protocol.ledger import Ledger, LedgerEntry
from protocol.merkle import (
    MERKLE_VERSION,
    PROOF_VERSION,
    MerkleProof,
    deserialize_merkle_proof,
    verify_proof,
)
from protocol.redaction import RedactionProof, RedactionProtocol


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


def verify_merkle_proof(args: argparse.Namespace) -> int:
    """Verify a Merkle inclusion proof."""
    try:
        with open(args.proof_file) as f:
            proof_data = json.load(f)

        # Reconstruct proof object, preserving versioning fields
        proof = deserialize_merkle_proof(proof_data)

        # Warn on unknown proof or tree versions so operators notice format drift
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

        if verify_proof(proof):
            print("✓ Merkle proof is VALID")
            print(f"  proof_version : {proof.proof_version}")
            print(f"  tree_version  : {proof.tree_version}")
            print(f"  epoch         : {proof.epoch}")
            print(f"  tree_size     : {proof.tree_size}")
            return 0
        else:
            print("✗ Merkle proof is INVALID", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Error verifying Merkle proof: {e}", file=sys.stderr)
        return 1


def verify_ledger_chain(args: argparse.Namespace) -> int:
    """Verify integrity of a ledger chain."""
    try:
        with open(args.ledger_file) as f:
            ledger_data = json.load(f)

        # Reconstruct ledger
        ledger = Ledger()
        for entry_data in ledger_data["entries"]:
            entry = LedgerEntry.from_dict(entry_data)
            ledger.entries.append(entry)

        if ledger.verify_chain():
            print(f"✓ Ledger chain is VALID ({len(ledger.entries)} entries)")
            return 0
        else:
            print("✗ Ledger chain is INVALID", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Error verifying ledger: {e}", file=sys.stderr)
        return 1


def verify_redaction(args: argparse.Namespace) -> int:
    """Verify a redaction proof."""
    try:
        with open(args.proof_file) as f:
            proof_data = json.load(f)

        with open(args.content_file) as f:
            content_data = json.load(f)

        # Reconstruct proof
        merkle_proofs = []
        for mp_data in proof_data["merkle_proofs"]:
            mp = MerkleProof(
                leaf_hash=bytes.fromhex(mp_data["leaf_hash"]),
                leaf_index=mp_data["leaf_index"],
                siblings=[(bytes.fromhex(h), pos) for h, pos in mp_data["siblings"]],
                root_hash=bytes.fromhex(mp_data["root_hash"]),
            )
            merkle_proofs.append(mp)

        proof = RedactionProof(
            original_root=proof_data["original_root"],
            revealed_indices=proof_data["revealed_indices"],
            revealed_hashes=proof_data["revealed_hashes"],
            merkle_proofs=merkle_proofs,
        )

        revealed_content = content_data["revealed_content"]

        if RedactionProtocol.verify_redaction_proof(proof, revealed_content):
            print(f"✓ Redaction proof is VALID ({len(revealed_content)} parts revealed)")
            return 0
        else:
            print("✗ Redaction proof is INVALID", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Error verifying redaction: {e}", file=sys.stderr)
        return 1


def verify_smt_proof(args: argparse.Namespace) -> int:
    """Verify an SMT existence or non-existence proof.

    If the proof file is a verification bundle that includes a signed shard
    header, the root hash is extracted from the header and used as the
    expected_root for secure proof verification. An explicit --expected-root
    flag overrides the bundle root.
    """
    try:
        from protocol.ssmf import (
            ExistenceProof,
            NonExistenceProof,
            verify_nonexistence_proof,
            verify_proof,
        )

        with open(args.proof_file) as f:
            data = json.load(f)

        expected_root: bytes | None = None

        # If the user provided an explicit expected root, use it
        if args.expected_root:
            expected_root = bytes.fromhex(args.expected_root)
        elif "signed_shard_header" in data:
            # Extract root from signed shard header in verification bundle
            header = data["signed_shard_header"]
            header_root = header.get("shard_root") or header.get("root_hash")
            if header_root:
                expected_root = bytes.fromhex(header_root)
                print(f"  Using root from signed shard header: {header_root}")

        # Determine proof type from data
        proof_data = data.get("proof", data)
        is_existence = proof_data.get("exists", True)

        if is_existence:
            raw_parser_id = proof_data.get("parser_id")
            raw_cpv = proof_data.get("canonical_parser_version")
            if not isinstance(raw_parser_id, str) or not raw_parser_id:
                raise ValueError("proof.parser_id is required and must be a non-empty string")
            if not isinstance(raw_cpv, str) or not raw_cpv:
                raise ValueError(
                    "proof.canonical_parser_version is required and must be a non-empty string"
                )
            proof = ExistenceProof(
                key=bytes.fromhex(proof_data["key"]),
                value_hash=bytes.fromhex(proof_data["value_hash"]),
                parser_id=raw_parser_id,
                canonical_parser_version=raw_cpv,
                siblings=[bytes.fromhex(s) for s in proof_data["siblings"]],
                root_hash=bytes.fromhex(proof_data["root_hash"]),
            )
            is_valid = verify_proof(proof, expected_root=expected_root)
        else:
            proof = NonExistenceProof(
                key=bytes.fromhex(proof_data["key"]),
                siblings=[bytes.fromhex(s) for s in proof_data["siblings"]],
                root_hash=bytes.fromhex(proof_data["root_hash"]),
            )
            is_valid = verify_nonexistence_proof(proof, expected_root=expected_root)

        proof_type = "existence" if is_existence else "non-existence"
        if is_valid:
            print(f"✓ SMT {proof_type} proof is VALID")
            if expected_root:
                print(f"  Root authenticated: {expected_root.hex()}")
            return 0
        else:
            print(f"✗ SMT {proof_type} proof is INVALID", file=sys.stderr)
            if expected_root:
                print(f"  Expected root: {expected_root.hex()}", file=sys.stderr)
                print(f"  Proof root:    {proof_data['root_hash']}", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Error verifying SMT proof: {e}", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify proofs and commitments in Olympus protocol"
    )

    subparsers = parser.add_subparsers(dest="command", help="Verification command")

    # Merkle proof verification
    merkle_parser = subparsers.add_parser("merkle", help="Verify Merkle inclusion proof")
    merkle_parser.add_argument("proof_file", help="Path to proof JSON file")

    # Ledger chain verification
    ledger_parser = subparsers.add_parser("ledger", help="Verify ledger chain integrity")
    ledger_parser.add_argument("ledger_file", help="Path to ledger JSON file")

    # Redaction proof verification
    redaction_parser = subparsers.add_parser("redaction", help="Verify redaction proof")
    redaction_parser.add_argument("proof_file", help="Path to redaction proof JSON file")
    redaction_parser.add_argument("content_file", help="Path to revealed content JSON file")

    # SMT proof verification (RT-M4)
    smt_parser = subparsers.add_parser("smt", help="Verify SMT existence/non-existence proof")
    smt_parser.add_argument("proof_file", help="Path to SMT proof or verification bundle JSON")
    smt_parser.add_argument(
        "--expected-root",
        help="Expected root hash (hex). If the proof file is a verification bundle "
        "with a signed shard header, the root is extracted automatically.",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "merkle":
        return verify_merkle_proof(args)
    elif args.command == "ledger":
        return verify_ledger_chain(args)
    elif args.command == "redaction":
        return verify_redaction(args)
    elif args.command == "smt":
        return verify_smt_proof(args)
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
