"""Regression coverage for cross-implementation end-to-end test vectors."""

from __future__ import annotations

import json
from pathlib import Path

from protocol.canonicalizer import Canonicalizer
from protocol.hashes import hash_bytes
from protocol.ledger import Ledger, LedgerEntry
from protocol.merkle import MerkleProof, MerkleTree, merkle_leaf_hash, verify_proof


VECTOR_PATH = (
    Path(__file__).resolve().parent.parent / "test_vectors" / "proofs" / "end_to_end.json"
)


def _load_vector() -> dict:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def test_end_to_end_vector_matches_reference_outputs() -> None:
    vector = _load_vector()

    # Canonicalization
    raw_bytes = json.dumps(vector["input_record"], separators=(",", ":")).encode("utf-8")
    canonicalizer = Canonicalizer()
    canonical_bytes = canonicalizer.json_jcs(raw_bytes)
    assert canonical_bytes.hex() == vector["canonicalized_bytes_hex"]
    assert hash_bytes(canonical_bytes).hex() == vector["record_hash_hex"]

    # Merkle
    leaf_hash = merkle_leaf_hash(canonical_bytes)
    assert leaf_hash.hex() == vector["merkle"]["leaf_hash_hex"]
    tree = MerkleTree([canonical_bytes])
    assert tree.get_root().hex() == vector["merkle"]["root_hex"]
    proof = tree.generate_proof(0)
    assert proof.leaf_index == vector["proof"]["leaf_index"]
    assert proof.siblings == []

    # Proof verification against serialized vector
    serialized_proof = MerkleProof(
        leaf_hash=bytes.fromhex(vector["merkle"]["leaf_hash_hex"]),
        leaf_index=vector["proof"]["leaf_index"],
        siblings=[
            (bytes.fromhex(item["hash"]), item["position"]) for item in vector["proof"]["siblings"]
        ],
        root_hash=bytes.fromhex(vector["proof"]["root_hash_hex"]),
        tree_size=1,
    )
    assert verify_proof(serialized_proof) is vector["proof"]["expected_valid"]

    # Ledger chain verification
    ledger = Ledger()
    ledger.entries = [LedgerEntry.from_dict(entry) for entry in vector["ledger"]["entries"]]
    assert ledger.verify_chain()
    assert ledger.entries[-1].entry_hash == vector["ledger"]["head_entry_hash"]
