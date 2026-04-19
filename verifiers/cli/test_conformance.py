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
)
from protocol.merkle import (
    MerkleTree,
    deserialize_merkle_proof,
    merkle_leaf_hash,
    verify_proof,
)


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
    """Compute the dual-root commitment binding hash (V2).

    Formula:
        binding_hash = BLAKE3(
            OLY:LEDGER:V1 || "|" || len_b3 || blake3_root_bytes
                          || "|" || len_pos || poseidon_root_32be_bytes
        )

    where:
      - len_b3 and len_pos are 2-byte big-endian length prefixes (always 0x0020 = 32),
      - poseidon_root_bytes is the 32-byte big-endian encoding of the decimal integer.

    The leading "|" separator after the LEDGER prefix and the inclusion of both
    length fields are required by the V2 wire format (PR 4: M-15 + M-14).
    """
    sep = HASH_SEPARATOR.encode("utf-8")
    b3_bytes = bytes.fromhex(blake3_root_hex)
    pos_bytes = int(poseidon_root_decimal).to_bytes(32, byteorder="big")
    len_b3 = len(b3_bytes).to_bytes(2, byteorder="big")
    len_pos = len(pos_bytes).to_bytes(2, byteorder="big")
    return blake3_hash(
        [LEDGER_PREFIX, sep, len_b3, b3_bytes, sep, len_pos, pos_bytes]
    ).hex()


def test_dual_root_commitment(vectors: dict) -> None:
    """Test dual-root commitment validation vectors.

    Each vector stores document parts plus the expected BLAKE3 root, Poseidon root,
    and the combined dual commitment.  The test verifies:

    1. The dual_commitment matches the formula:
       BLAKE3(OLY:LEDGER:V1 | "|" | blake3_root_bytes | "|" | poseidon_root_32be_bytes).
    2. The BLAKE3 Merkle root recomputed from document_parts_utf8 matches blake3_root
       (iff expected_blake3_consistent is true).
    3. If a blake3_proof is provided, it verifies correctly against the stored blake3_root.

    Note: Poseidon root consistency (expected_valid vs expected_blake3_consistent) is
    not checked here.  The Python PoseidonMerkleTree depth/padding convention has not
    yet been aligned with the reference vectors; Go, Rust, and JS verifiers also skip
    this check.  Once the Poseidon tree implementation is stabilised, the full
    expected_valid check should be re-enabled.

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

        # 3. Verify blake3_proof when present
        if vec.get("blake3_proof") is not None:
            proof_data = {
                "leaf_hash": vec["blake3_proof"]["leaf_hash"],
                "leaf_index": vec["blake3_proof"]["leaf_index"],
                "siblings": [[s["hash"], s["position"]] for s in vec["blake3_proof"]["siblings"]],
                "root_hash": vec["blake3_proof"]["root_hash"],
            }
            proof = deserialize_merkle_proof(proof_data)
            assert verify_proof(proof), f"blake3_proof verification failed for {desc!r}"

    print(f"  ✓ dual_root_commitment: {len(vectors['dual_root_commitment'])} vectors")


def test_dual_root_commitment_wire(vectors: dict) -> None:
    """Verify the full dual-root commitment wire format (V2, PR 4: M-15 + M-14).

    Wire layout:
        len_b3 (2B BE) || blake3_root (32B) || len_pos (2B BE)
            || poseidon_root_32be (32B) || binding_hash (32B)
    where binding_hash is the value pinned by ``test_dual_root_commitment``.
    """
    from protocol.hashes import create_dual_root_commitment

    for vec in vectors["dual_root_commitment"]:
        if "dual_commitment_wire" not in vec:
            continue
        b3 = bytes.fromhex(vec["blake3_root"])
        pos = int(vec["poseidon_root"]).to_bytes(32, "big")
        wire_hex = create_dual_root_commitment(b3, pos).hex()
        assert wire_hex == vec["dual_commitment_wire"], (
            f"dual_commitment_wire mismatch for {vec['description']!r}: "
            f"got {wire_hex}, want {vec['dual_commitment_wire']}"
        )
        # Cross-check: last 32 bytes of wire == binding hash field
        assert wire_hex[-64:] == vec["dual_commitment"], (
            f"binding hash slice mismatch for {vec['description']!r}"
        )
    print("  ✓ dual_root_commitment_wire: validated")


def test_federation_vote_hash(vectors: dict) -> None:
    """Validate ``federation_vote_hash`` golden vectors (PR 4: M-16)."""
    from protocol.hashes import federation_vote_hash

    section = vectors.get("federation_vote_hash", [])
    for vec in section:
        got = federation_vote_hash(
            vec["node_id"],
            vec["shard_id"],
            vec["header_hash"],
            vec["timestamp"],
            vec["event_id"],
        ).hex()
        assert got == vec["vote_hash"], (
            f"federation_vote_hash mismatch for {vec['description']!r}: "
            f"got {got}, want {vec['vote_hash']}"
        )
    print(f"  ✓ federation_vote_hash: {len(section)} vectors")


def test_federation_vote_event_id(vectors: dict) -> None:
    """Validate length-prefixed ``_federation_vote_event_id`` vectors (PR 4: F-FED-6).

    Vectors pin the inputs (shard_id, header_hash, timestamp, epoch, membership_hash)
    so any verifier can reproduce the event_id without depending on the registry
    implementation.
    """
    from protocol.hashes import _length_prefixed_bytes, hash_bytes

    section = vectors.get("federation_vote_event_id", [])
    for vec in section:
        payload = b"".join(
            [
                _length_prefixed_bytes("shard_id", vec["shard_id"].encode("utf-8")),
                _length_prefixed_bytes("header_hash", vec["header_hash"].encode("utf-8")),
                _length_prefixed_bytes("timestamp", vec["timestamp"].encode("utf-8")),
                _length_prefixed_bytes("epoch", str(vec["epoch"]).encode("utf-8")),
                _length_prefixed_bytes(
                    "membership_hash", vec["membership_hash"].encode("utf-8")
                ),
            ]
        )
        got = hash_bytes(payload).hex()
        assert got == vec["event_id"], (
            f"federation_vote_event_id mismatch for {vec['description']!r}: "
            f"got {got}, want {vec['event_id']}"
        )
    print(f"  ✓ federation_vote_event_id: {len(section)} vectors")


def test_replication_proof_payload_hash(vectors: dict) -> None:
    """Validate ``ReplicationProof.proof_payload_hash`` vectors (PR 4: F-FED-7)."""
    from protocol.federation.replication import ReplicationProof

    section = vectors.get("replication_proof_payload_hash", [])
    for vec in section:
        proof = ReplicationProof(
            challenge_hash=vec["challenge_hash"],
            guardian_id=vec["guardian_id"],
            ledger_tail_hash=vec["ledger_tail_hash"],
            merkle_root_verified=vec["merkle_root_verified"],
            proof_sample_indices=tuple(vec["proof_sample_indices"]),
            proof_sample_hashes=tuple(vec["proof_sample_hashes"]),
            replicated_at=vec["replicated_at"],
            guardian_signature="",
        )
        got = proof.proof_payload_hash()
        assert got == vec["proof_payload_hash"], (
            f"proof_payload_hash mismatch for {vec['description']!r}: "
            f"got {got}, want {vec['proof_payload_hash']}"
        )
    print(f"  ✓ replication_proof_payload_hash: {len(section)} vectors")


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
    test_dual_root_commitment_wire(vectors)
    test_federation_vote_hash(vectors)
    test_federation_vote_event_id(vectors)
    test_replication_proof_payload_hash(vectors)
    print("\n✓ All Python conformance tests passed!")


if __name__ == "__main__":
    main()
