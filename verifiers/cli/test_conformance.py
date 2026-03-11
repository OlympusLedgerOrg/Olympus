#!/usr/bin/env python3
# ruff: noqa: E402
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

from protocol.canonical import normalize_whitespace
from protocol.hashes import (
    HASH_SEPARATOR,
    LEDGER_PREFIX,
    NODE_PREFIX,
    blake3_hash,
    blake3_to_field_element,
)
from protocol.merkle import (
    MerkleTree,
    deserialize_merkle_proof,
    merkle_leaf_hash,
    verify_proof,
)
from protocol.poseidon_tree import PoseidonMerkleTree


VECTORS_PATH = Path(__file__).parent.parent / "test_vectors" / "vectors.json"
CANONICALIZER_VECTORS_PATH = (
    Path(__file__).parent.parent / "test_vectors" / "canonicalizer_vectors.tsv"
)
_SEP = HASH_SEPARATOR.encode("utf-8")


def load_vectors() -> dict:
    with open(VECTORS_PATH) as f:
        return json.load(f)


def load_canonicalizer_vectors() -> list[tuple[str, bytes, bytes, str]]:
    rows: list[tuple[str, bytes, bytes, str]] = []
    with open(CANONICALIZER_VECTORS_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            group_id, input_hex, canonical_hex, hash_hex = line.split("\t")
            rows.append(
                (group_id, bytes.fromhex(input_hex), bytes.fromhex(canonical_hex), hash_hex)
            )
    return rows


def test_blake3_raw(vectors: dict) -> None:
    for vec in vectors["blake3_raw"]:
        data = vec["input_utf8"].encode("utf-8")
        got = blake3_hash([data]).hex()
        assert got == vec["hash"], (
            f"blake3_raw failed for {repr(vec['input_utf8'])!r}: got {got}, want {vec['hash']}"
        )
    print(f"  ✓ blake3_raw: {len(vectors['blake3_raw'])} vectors")


def test_merkle_leaf_hash(vectors: dict) -> None:
    for vec in vectors["merkle_leaf_hash"]:
        data = vec["input_utf8"].encode("utf-8")
        got = merkle_leaf_hash(data).hex()
        assert got == vec["hash"], (
            f"merkle_leaf_hash failed for {repr(vec['input_utf8'])}: got {got}, want {vec['hash']}"
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
            f"merkle_root failed for {vec['leaves_utf8']}: got {got}, want {vec['root']}"
        )
    print(f"  ✓ merkle_root: {len(vectors['merkle_root'])} vectors")


def test_merkle_proof(vectors: dict) -> None:
    for vec in vectors["merkle_proof"]:
        # Use deserialize_merkle_proof so that versioning fields are handled
        # consistently; legacy vectors without proof_version/tree_version/epoch/
        # tree_size receive the current defaults.
        proof_data = {
            "leaf_hash": vec["leaf_hash"],
            "leaf_index": vec["leaf_index"],
            "siblings": [[s["hash"], s["position"]] for s in vec["siblings"]],
            "root_hash": vec["root_hash"],
        }
        proof = deserialize_merkle_proof(proof_data)
        got = verify_proof(proof)
        assert got == vec["expected_valid"], (
            f"merkle_proof verification failed: got {got}, want {vec['expected_valid']}"
        )
    print(f"  ✓ merkle_proof: {len(vectors['merkle_proof'])} vectors")


def test_canonicalizer_hash_vectors() -> None:
    rows = load_canonicalizer_vectors()
    assert len(rows) >= 500, "canonicalizer vector suite must include at least 500 pairs"
    for _, _, canonical_bytes, hash_hex in rows:
        got = blake3_hash([canonical_bytes]).hex()
        assert got == hash_hex, f"canonicalizer vector hash mismatch: got {got}, want {hash_hex}"
    print(f"  ✓ canonicalizer_hash: {len(rows)} vectors")


def test_ledger_entry_hash(vectors: dict) -> None:
    """Test that ledger entry hashes match across the Python reference implementation.

    Each vector stores the pre-canonicalized payload bytes (hex) and the expected
    entry hash. Formula: BLAKE3(OLY:LEDGER:V1 || canonical_json_bytes(payload)).
    """
    for vec in vectors["ledger_entry_hash"]:
        payload_bytes = bytes.fromhex(vec["canonical_payload_hex"])
        got = blake3_hash([LEDGER_PREFIX, payload_bytes]).hex()
        assert got == vec["entry_hash"], (
            f"ledger_entry_hash failed for {vec['description']!r}: "
            f"got {got}, want {vec['entry_hash']}"
        )
    print(f"  ✓ ledger_entry_hash: {len(vectors['ledger_entry_hash'])} vectors")


def _compute_dual_commitment(blake3_root_hex: str, poseidon_root_decimal: str) -> str:
    """Compute the dual-root commitment hash.

    Formula: BLAKE3(OLY:LEDGER:V1 | "|" | blake3_root_bytes | "|" | poseidon_root_bytes)
    where poseidon_root_bytes is the 32-byte big-endian encoding of the decimal integer.
    """
    sep = HASH_SEPARATOR.encode("utf-8")
    b3_bytes = bytes.fromhex(blake3_root_hex)
    pos_bytes = int(poseidon_root_decimal).to_bytes(32, byteorder="big")
    return blake3_hash([LEDGER_PREFIX, sep, b3_bytes, sep, pos_bytes]).hex()


def test_dual_root_commitment(vectors: dict) -> None:
    """Test dual-root commitment validation vectors.

    Each vector stores document parts plus the expected BLAKE3 root, Poseidon root,
    and the combined dual commitment.  The test verifies:

    1. The BLAKE3 Merkle root recomputed from document_parts_utf8 matches blake3_root
       (iff expected_blake3_consistent is true).
    2. The Poseidon Merkle root recomputed from document_parts_utf8 matches poseidon_root
       (iff expected_valid is true).
    3. The dual_commitment matches the formula:
       BLAKE3(OLY:LEDGER:V1 | "|" | blake3_root_bytes | "|" | poseidon_root_32be_bytes).
    4. If a blake3_proof is provided, it verifies correctly against the stored blake3_root.

    Leaf inputs for the BLAKE3 Merkle tree are canonical section bytes (whitespace-
    normalized UTF-8), passed directly to :class:`~protocol.merkle.MerkleTree` without
    pre-hashing.  This matches the behaviour of :func:`ComputeMerkleRoot` in the Go,
    Rust, and JavaScript verifiers.
    """
    for vec in vectors["dual_root_commitment"]:
        desc = vec["description"]
        parts = vec["document_parts_utf8"]

        # 1. Verify dual_commitment formula is always correct as stored
        got_dual = _compute_dual_commitment(vec["blake3_root"], vec["poseidon_root"])
        assert got_dual == vec["dual_commitment"], (
            f"dual_commitment formula mismatch for {desc!r}: got {got_dual}, want {vec['dual_commitment']}"
        )

        # 2. Recompute BLAKE3 root from document parts using canonical section bytes
        # (whitespace-normalized UTF-8) passed directly to MerkleTree – no pre-hashing.
        canonical_sections = [normalize_whitespace(p).encode("utf-8") for p in parts]
        tree = MerkleTree(canonical_sections)
        computed_blake3_root = tree.get_root().hex()

        blake3_matches = computed_blake3_root == vec["blake3_root"]
        assert blake3_matches == vec["expected_blake3_consistent"], (
            f"expected_blake3_consistent={vec['expected_blake3_consistent']} "
            f"but blake3 match={blake3_matches} for {desc!r}"
        )

        # 3. Recompute Poseidon root and verify full expected_valid
        pos_leaves = [int(blake3_to_field_element(s)) for s in canonical_sections]
        pos_tree = PoseidonMerkleTree(pos_leaves, depth=4)
        computed_poseidon_root = pos_tree.get_root()

        poseidon_matches = computed_poseidon_root == vec["poseidon_root"]
        is_valid = blake3_matches and poseidon_matches
        assert is_valid == vec["expected_valid"], (
            f"expected_valid={vec['expected_valid']} but full check={is_valid} for {desc!r}"
        )

        # 4. Verify blake3_proof when present
        if vec.get("blake3_proof") is not None:
            proof_data = {
                "leaf_hash": vec["blake3_proof"]["leaf_hash"],
                "leaf_index": vec["blake3_proof"]["leaf_index"],
                "siblings": [
                    [s["hash"], s["position"]] for s in vec["blake3_proof"]["siblings"]
                ],
                "root_hash": vec["blake3_proof"]["root_hash"],
            }
            proof = deserialize_merkle_proof(proof_data)
            assert verify_proof(proof), (
                f"blake3_proof verification failed for {desc!r}"
            )

    print(f"  ✓ dual_root_commitment: {len(vectors['dual_root_commitment'])} vectors")


def main() -> None:
    print("Running Python conformance tests against vectors.json\n")
    vectors = load_vectors()
    test_blake3_raw(vectors)
    test_merkle_leaf_hash(vectors)
    test_merkle_parent_hash(vectors)
    test_merkle_root(vectors)
    test_merkle_proof(vectors)
    test_canonicalizer_hash_vectors()
    test_ledger_entry_hash(vectors)
    test_dual_root_commitment(vectors)
    print("\n✓ All Python conformance tests passed!")


if __name__ == "__main__":
    main()
