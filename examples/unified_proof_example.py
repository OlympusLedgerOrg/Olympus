#!/usr/bin/env python3
"""
Example: Using the unified prove() method for both existence and non-existence proofs

This example demonstrates how the new prove() method allows callers to handle
both existence and non-existence cases without exception handling.
"""

import os
import sys


# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol.hashes import hash_bytes, record_key
from protocol.ssmf import (
    SparseMerkleTree,
    is_existence_proof,
    is_nonexistence_proof,
    verify_unified_proof,
)


def main():
    print("=" * 70)
    print("Olympus: Non-Existence Proof Semantics Example")
    print("=" * 70)
    print()

    # Create a sparse Merkle tree
    tree = SparseMerkleTree()
    print("1. Created empty sparse Merkle tree")
    print(f"   Root hash: {tree.get_root().hex()[:16]}...")
    print()

    # Add some records
    records = [
        ("document", "invoice-2024-001", 1),
        ("document", "invoice-2024-002", 1),
        ("transaction", "payment-tx-001", 1),
    ]

    print("2. Adding records to tree:")
    for record_type, record_id, version in records:
        key = record_key(record_type, record_id, version)
        value_hash = hash_bytes(f"content-of-{record_id}".encode())
        tree.update(key, value_hash)
        print(f"   ✓ {record_type}/{record_id} v{version}")
    print()

    print(f"   New root hash: {tree.get_root().hex()[:16]}...")
    print()

    # Query for existing record using unified prove()
    print("3. Query for EXISTING record (no exception!):")
    existing_key = record_key("document", "invoice-2024-001", 1)
    proof = tree.prove(existing_key)

    if is_existence_proof(proof):
        print("   ✓ Record EXISTS")
        print(f"   - Key: {proof.key.hex()[:16]}...")
        print(f"   - Value hash: {proof.value_hash.hex()[:16]}...")
        print(f"   - Root: {proof.root_hash.hex()[:16]}...")
        print(f"   - Siblings: {len(proof.siblings)} hashes")
        print(f"   - Valid: {verify_unified_proof(proof)}")
    print()

    # Query for NON-EXISTING record using unified prove()
    # CRITICAL: This does NOT raise an exception!
    print("4. Query for NON-EXISTING record (no exception!):")
    missing_key = record_key("document", "invoice-2024-999", 1)
    proof = tree.prove(missing_key)

    if is_nonexistence_proof(proof):
        print("   ✓ Record DOES NOT EXIST")
        print(f"   - Key: {proof.key.hex()[:16]}...")
        print(f"   - Root: {proof.root_hash.hex()[:16]}...")
        print(f"   - Siblings: {len(proof.siblings)} hashes")
        print(f"   - Valid: {verify_unified_proof(proof)}")
    print()

    # Demonstrate API/service pattern
    print("5. API/Service pattern (no exception handling needed):")
    print()

    def get_record_proof(tree, record_type, record_id, version):
        """
        API handler pattern: returns structured response without exceptions.

        This is the pattern that was broken before the fix - previously,
        missing keys would raise ValueError, forcing HTTP 500 responses.
        """
        key = record_key(record_type, record_id, version)
        proof = tree.prove(key)  # Never raises for valid absence

        response = {
            "record_type": record_type,
            "record_id": record_id,
            "version": version,
            "key": proof.key.hex(),
            "root": proof.root_hash.hex(),
            "siblings": [s.hex() for s in proof.siblings],
            "exists": is_existence_proof(proof),
        }

        if is_existence_proof(proof):
            response["value_hash"] = proof.value_hash.hex()

        return response

    # Test with existing record
    response1 = get_record_proof(tree, "document", "invoice-2024-001", 1)
    print("   Request: document/invoice-2024-001")
    print(f"   Response: exists={response1['exists']}")
    print("   HTTP Status: 200 OK")
    print()

    # Test with non-existing record (critical case!)
    response2 = get_record_proof(tree, "document", "nonexistent-doc", 1)
    print("   Request: document/nonexistent-doc")
    print(f"   Response: exists={response2['exists']}")
    print("   HTTP Status: 200 OK (not 500!)")
    print()

    print("=" * 70)
    print("Summary:")
    print("  • Non-existence is a valid cryptographic response")
    print("  • Both cases return deterministic proofs")
    print("  • No exception handling needed for missing keys")
    print("  • API can return HTTP 200 for both existence and non-existence")
    print("=" * 70)


if __name__ == "__main__":
    main()
