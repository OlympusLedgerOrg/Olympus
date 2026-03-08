#!/usr/bin/env python3
"""
Conformance tests for the Olympus Python CLI verifier.

Validates that the Python protocol implementation produces outputs that match
the committed test vectors in verifiers/test_vectors/vectors.json.
"""

import json
import sys
from pathlib import Path

# Add repository root to path
REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from protocol.hashes import blake3_hash, NODE_PREFIX, HASH_SEPARATOR
from protocol.merkle import MerkleTree, merkle_leaf_hash, verify_proof, MerkleProof

VECTORS_PATH = Path(__file__).parent.parent / "test_vectors" / "vectors.json"
_SEP = HASH_SEPARATOR.encode("utf-8")


def load_vectors() -> dict:
    with open(VECTORS_PATH) as f:
        return json.load(f)


def test_blake3_raw(vectors: dict) -> None:
    for vec in vectors["blake3_raw"]:
        data = vec["input_utf8"].encode("utf-8")
        got = blake3_hash([data]).hex()
        assert got == vec["hash"], (
            f"blake3_raw failed for {repr(vec['input_utf8'])!r}: "
            f"got {got}, want {vec['hash']}"
        )
    print(f"  ✓ blake3_raw: {len(vectors['blake3_raw'])} vectors")


def test_merkle_leaf_hash(vectors: dict) -> None:
    for vec in vectors["merkle_leaf_hash"]:
        data = vec["input_utf8"].encode("utf-8")
        got = merkle_leaf_hash(data).hex()
        assert got == vec["hash"], (
            f"merkle_leaf_hash failed for {repr(vec['input_utf8'])}: "
            f"got {got}, want {vec['hash']}"
        )
    print(f"  ✓ merkle_leaf_hash: {len(vectors['merkle_leaf_hash'])} vectors")


def test_merkle_parent_hash(vectors: dict) -> None:
    for vec in vectors["merkle_parent_hash"]:
        left = bytes.fromhex(vec["left_hash"])
        right = bytes.fromhex(vec["right_hash"])
        parent = blake3_hash([NODE_PREFIX, _SEP, left, _SEP, right]).hex()
        assert parent == vec["parent_hash"], (
            f"merkle_parent_hash failed: got {parent}, want {vec['parent_hash']}"
        )
    print(f"  ✓ merkle_parent_hash: {len(vectors['merkle_parent_hash'])} vectors")


def test_merkle_root(vectors: dict) -> None:
    for vec in vectors["merkle_root"]:
        leaves = [s.encode("utf-8") for s in vec["leaves_utf8"]]
        tree = MerkleTree(leaves)
        got = tree.get_root().hex()
        assert got == vec["root"], (
            f"merkle_root failed for {vec['leaves_utf8']}: "
            f"got {got}, want {vec['root']}"
        )
    print(f"  ✓ merkle_root: {len(vectors['merkle_root'])} vectors")


def test_merkle_proof(vectors: dict) -> None:
    for vec in vectors["merkle_proof"]:
        proof = MerkleProof(
            leaf_hash=bytes.fromhex(vec["leaf_hash"]),
            leaf_index=vec["leaf_index"],
            siblings=[
                (bytes.fromhex(s["hash"]), s["position"])
                for s in vec["siblings"]
            ],
            root_hash=bytes.fromhex(vec["root_hash"]),
        )
        got = verify_proof(proof)
        assert got == vec["expected_valid"], (
            f"merkle_proof verification failed: got {got}, want {vec['expected_valid']}"
        )
    print(f"  ✓ merkle_proof: {len(vectors['merkle_proof'])} vectors")


def main() -> None:
    print("Running Python conformance tests against vectors.json\n")
    vectors = load_vectors()
    test_blake3_raw(vectors)
    test_merkle_leaf_hash(vectors)
    test_merkle_parent_hash(vectors)
    test_merkle_root(vectors)
    test_merkle_proof(vectors)
    print("\n✓ All Python conformance tests passed!")


if __name__ == "__main__":
    main()
