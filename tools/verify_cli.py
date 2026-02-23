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
from protocol.merkle import MerkleProof, verify_proof
from protocol.redaction import RedactionProof, RedactionProtocol


def verify_merkle_proof(args: argparse.Namespace) -> int:
    """Verify a Merkle inclusion proof."""
    try:
        with open(args.proof_file) as f:
            proof_data = json.load(f)

        # Reconstruct proof object
        proof = MerkleProof(
            leaf_hash=bytes.fromhex(proof_data["leaf_hash"]),
            leaf_index=proof_data["leaf_index"],
            siblings=[(bytes.fromhex(h), pos) for h, pos in proof_data["siblings"]],
            root_hash=bytes.fromhex(proof_data["root_hash"]),
        )

        if verify_proof(proof):
            print("✓ Merkle proof is VALID")
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
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
