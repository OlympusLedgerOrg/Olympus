"""Property-based SMT update → prove → verify roundtrip test.

Uses Hypothesis to exercise the pure-Python Sparse Merkle Tree with random
key-value pairs and verifies that every inserted key can be proved (existence)
and that keys *not* inserted produce valid non-existence proofs.
"""

from __future__ import annotations

import os

import hypothesis.strategies as st
from hypothesis import given, settings

from protocol.ssmf import (
    ExistenceProof,
    NonExistenceProof,
    SparseMerkleTree,
    verify_nonexistence_proof,
    verify_proof,
    verify_unified_proof,
)


# 32-byte keys and values
_keys = st.binary(min_size=32, max_size=32)
_values = st.binary(min_size=32, max_size=32)

# Use smaller deadline in CI since Hypothesis may be slow
_DEADLINE_MS = int(os.environ.get("HYPOTHESIS_DEADLINE_MS", "2000"))


@given(
    entries=st.lists(
        st.tuples(_keys, _values),
        min_size=1,
        max_size=20,
    ),
)
@settings(max_examples=100, deadline=_DEADLINE_MS)
def test_smt_update_prove_verify_roundtrip(
    entries: list[tuple[bytes, bytes]],
) -> None:
    """For every key inserted, prove_existence must produce a valid proof
    that verify_proof accepts.
    """
    tree = SparseMerkleTree()
    for key, value in entries:
        tree.update(key, value, "docling@2.3.1", "v1")

    root = tree.get_root()

    # Build a map of the last value for each key (update semantics).
    final_values: dict[bytes, bytes] = {}
    for key, value in entries:
        final_values[key] = value

    for key, value in final_values.items():
        proof = tree.prove_existence(key)
        assert isinstance(proof, ExistenceProof)
        assert proof.root_hash == root
        assert proof.key == key
        assert proof.value_hash == value
        assert verify_proof(proof), f"verify_proof failed for key {key.hex()}"
        assert verify_unified_proof(proof)


@given(
    entries=st.lists(
        st.tuples(_keys, _values),
        min_size=1,
        max_size=10,
    ),
    absent_key=_keys,
)
@settings(max_examples=100, deadline=_DEADLINE_MS)
def test_smt_nonexistence_proof_roundtrip(
    entries: list[tuple[bytes, bytes]],
    absent_key: bytes,
) -> None:
    """A key that was never inserted must produce a valid non-existence proof."""
    tree = SparseMerkleTree()
    inserted_keys = set()
    for key, value in entries:
        tree.update(key, value, "docling@2.3.1", "v1")
        inserted_keys.add(key)

    if absent_key in inserted_keys:
        # Skip when Hypothesis generates the same key — that's an existence case.
        return

    root = tree.get_root()
    proof = tree.prove_nonexistence(absent_key)
    assert isinstance(proof, NonExistenceProof)
    assert proof.root_hash == root
    assert proof.key == absent_key
    assert verify_nonexistence_proof(proof), (
        f"verify_nonexistence_proof failed for key {absent_key.hex()}"
    )
    assert verify_unified_proof(proof)


@given(
    entries=st.lists(
        st.tuples(_keys, _values),
        min_size=1,
        max_size=10,
    ),
)
@settings(max_examples=50, deadline=_DEADLINE_MS)
def test_smt_unified_prove_dispatches_correctly(
    entries: list[tuple[bytes, bytes]],
) -> None:
    """The unified prove() method should dispatch to existence or nonexistence
    correctly and produce verifiable proofs.
    """
    tree = SparseMerkleTree()
    inserted_keys = set()
    for key, value in entries:
        tree.update(key, value, "docling@2.3.1", "v1")
        inserted_keys.add(key)

    # Existence via prove()
    for key, _value in entries:
        proof = tree.prove(key)
        assert isinstance(proof, ExistenceProof)
        assert verify_unified_proof(proof)

    # Non-existence via prove() with a key that was never inserted
    absent = b"\xff" * 32
    if absent not in inserted_keys:
        proof = tree.prove(absent)
        assert isinstance(proof, NonExistenceProof)
        assert verify_unified_proof(proof)


@given(
    entries=st.lists(
        st.tuples(_keys, _values),
        min_size=2,
        max_size=15,
    ),
)
@settings(max_examples=50, deadline=_DEADLINE_MS)
def test_smt_root_changes_after_update(
    entries: list[tuple[bytes, bytes]],
) -> None:
    """Inserting a new key must change the root hash (barring collisions,
    which are astronomically unlikely with BLAKE3).
    """
    tree = SparseMerkleTree()

    # Insert first entry, capture root
    tree.update(entries[0][0], entries[0][1], "docling@2.3.1", "v1")
    root_after_first = tree.get_root()

    # If a second *distinct* key is present, root must differ after insert.
    if entries[1][0] != entries[0][0]:
        tree.update(entries[1][0], entries[1][1], "docling@2.3.1", "v1")
        root_after_second = tree.get_root()
        assert root_after_first != root_after_second
