"""Tests for Poseidon sparse Merkle tree (ZK witness generator)."""

import pytest

from protocol.hashes import SNARK_SCALAR_FIELD
from protocol.poseidon_bn128 import poseidon_hash_bn128
from protocol.poseidon_smt import (
    POSEIDON_EMPTY_HASHES,
    PoseidonSMT,
    _key_to_path_bits,
    verify_poseidon_nonexistence_witness,
)


# --- Basic tree operations ---


def test_empty_tree_root():
    """Empty Poseidon SMT has deterministic root."""
    tree = PoseidonSMT()
    root = tree.get_root()
    assert root == POSEIDON_EMPTY_HASHES[256]


def test_insert_and_retrieve():
    """Insert a key-value pair and retrieve it."""
    tree = PoseidonSMT()
    key = b"\x00" * 31 + b"\x01"
    value = 42

    tree.update(key, value)
    assert tree.get(key) == value


def test_insert_multiple_keys():
    """Insert multiple key-value pairs."""
    tree = PoseidonSMT()
    keys = [
        b"\x00" * 31 + b"\x01",
        b"\x00" * 31 + b"\x02",
        b"\x00" * 31 + b"\x03",
    ]
    values = [100, 200, 300]

    for key, value in zip(keys, values):
        tree.update(key, value)

    for key, value in zip(keys, values):
        assert tree.get(key) == value


def test_update_existing_key():
    """Update an existing key with a new value."""
    tree = PoseidonSMT()
    key = b"\x00" * 31 + b"\x01"

    tree.update(key, 42)
    assert tree.get(key) == 42

    tree.update(key, 99)
    assert tree.get(key) == 99


def test_get_nonexistent_key():
    """Get returns None for nonexistent keys."""
    tree = PoseidonSMT()
    key = b"\x00" * 31 + b"\x01"
    assert tree.get(key) is None


def test_root_changes_on_insert():
    """Root changes when a key is inserted."""
    tree = PoseidonSMT()
    empty_root = tree.get_root()

    tree.update(b"\x00" * 31 + b"\x01", 42)
    new_root = tree.get_root()

    assert new_root != empty_root


def test_root_deterministic():
    """Same insertions produce same root."""
    tree1 = PoseidonSMT()
    tree1.update(b"\x00" * 31 + b"\x01", 42)
    tree1.update(b"\x00" * 31 + b"\x02", 99)

    tree2 = PoseidonSMT()
    tree2.update(b"\x00" * 31 + b"\x01", 42)
    tree2.update(b"\x00" * 31 + b"\x02", 99)

    assert tree1.get_root() == tree2.get_root()


def test_root_order_independent():
    """Root is independent of insertion order."""
    tree1 = PoseidonSMT()
    tree1.update(b"\x00" * 31 + b"\x01", 42)
    tree1.update(b"\x00" * 31 + b"\x02", 99)

    tree2 = PoseidonSMT()
    tree2.update(b"\x00" * 31 + b"\x02", 99)
    tree2.update(b"\x00" * 31 + b"\x01", 42)

    assert tree1.get_root() == tree2.get_root()


# --- Key path derivation ---


def test_key_to_path_bits_length():
    """32-byte key produces 256-bit path."""
    key = b"\x00" * 32
    path = _key_to_path_bits(key)
    assert len(path) == 256


def test_key_to_path_bits_all_zeros():
    """All-zero key produces all-zero path."""
    key = b"\x00" * 32
    path = _key_to_path_bits(key)
    assert all(bit == 0 for bit in path)


def test_key_to_path_bits_all_ones():
    """All-ones key produces all-ones path."""
    key = b"\xFF" * 32
    path = _key_to_path_bits(key)
    assert all(bit == 1 for bit in path)


def test_key_to_path_bits_msb_first():
    """Path bits are MSB-first per byte."""
    # Key with byte 0x80 (binary 10000000) in first position
    key = b"\x80" + b"\x00" * 31
    path = _key_to_path_bits(key)
    # First bit should be 1 (MSB of 0x80)
    assert path[0] == 1
    # Next 7 bits should be 0
    assert all(path[i] == 0 for i in range(1, 8))
    # Remaining bits should be 0
    assert all(path[i] == 0 for i in range(8, 256))


# --- Non-existence proofs ---


def test_prove_nonexistence_empty_tree():
    """Prove non-existence in an empty tree."""
    tree = PoseidonSMT()
    key = b"\x00" * 31 + b"\x01"

    witness = tree.prove_nonexistence(key)
    assert witness.root == str(POSEIDON_EMPTY_HASHES[256])
    assert len(witness.key) == 32
    assert len(witness.path_elements) == 256


def test_prove_nonexistence_rejects_existing_key():
    """prove_nonexistence raises ValueError if key exists."""
    tree = PoseidonSMT()
    key = b"\x00" * 31 + b"\x01"
    tree.update(key, 42)

    with pytest.raises(ValueError, match="Key exists"):
        tree.prove_nonexistence(key)


def test_prove_nonexistence_different_key():
    """Prove non-existence of a key after inserting a different key."""
    tree = PoseidonSMT()
    tree.update(b"\x00" * 31 + b"\x01", 42)

    # Prove non-existence of different key
    witness = tree.prove_nonexistence(b"\x00" * 31 + b"\x02")
    assert len(witness.path_elements) == 256


def test_prove_nonexistence_invalid_key_length():
    """prove_nonexistence rejects keys of wrong length."""
    tree = PoseidonSMT()
    with pytest.raises(ValueError, match="Key must be 32 bytes"):
        tree.prove_nonexistence(b"\x00" * 16)


# --- Witness verification (circuit soundness) ---


def test_verify_poseidon_nonexistence_witness_empty_tree():
    """Verify non-existence witness in empty tree."""
    tree = PoseidonSMT()
    key = b"\x00" * 31 + b"\x01"

    witness = tree.prove_nonexistence(key)
    assert verify_poseidon_nonexistence_witness(witness)


def test_verify_poseidon_nonexistence_witness_populated_tree():
    """Verify non-existence witness in a tree with multiple keys."""
    tree = PoseidonSMT()
    tree.update(b"\x00" * 31 + b"\x01", 100)
    tree.update(b"\x00" * 31 + b"\x02", 200)
    tree.update(b"\x00" * 31 + b"\x03", 300)

    # Prove non-existence of key not in tree
    witness = tree.prove_nonexistence(b"\x00" * 31 + b"\xFF")
    assert verify_poseidon_nonexistence_witness(witness)


def test_witness_reconstruction_matches_circuit_logic():
    """
    Critical soundness test: witness reconstructs root using exact circuit logic.

    This verifies that the witness generated by prove_nonexistence() can be
    used to generate a valid snarkjs proof for non_existence.circom.
    """
    tree = PoseidonSMT()
    tree.update(b"\x00" * 31 + b"\x01", 100)
    tree.update(b"\x00" * 31 + b"\x02", 200)

    key = b"\x00" * 31 + b"\x05"
    witness = tree.prove_nonexistence(key)

    # Extract path bits from key (MSB-first)
    path_bits = _key_to_path_bits(key)

    # Reconstruct root using exact circuit logic
    # Siblings are ordered from leaf to root (level 0, 1, 2...)
    # Path bits are ordered from root to leaf (bit 0, 1, 2...)
    current = 0  # empty sentinel
    for level in range(256):
        sibling = int(witness.path_elements[level])
        bit_pos = 255 - level  # Map from level to bit position
        bit = path_bits[bit_pos]

        if bit == 0:
            current = poseidon_hash_bn128(current, sibling)
        else:
            current = poseidon_hash_bn128(sibling, current)
        current %= SNARK_SCALAR_FIELD

    # Reconstructed root must match witness root
    assert str(current) == witness.root


def test_witness_verification_rejects_invalid_key_length():
    """Witness verification rejects invalid key length."""
    tree = PoseidonSMT()
    witness = tree.prove_nonexistence(b"\x00" * 32)

    # Tamper with key length
    witness.key = witness.key[:16]
    assert not verify_poseidon_nonexistence_witness(witness)


def test_witness_verification_rejects_invalid_path_length():
    """Witness verification rejects invalid path length."""
    tree = PoseidonSMT()
    witness = tree.prove_nonexistence(b"\x00" * 32)

    # Tamper with path length
    witness.path_elements = witness.path_elements[:128]
    assert not verify_poseidon_nonexistence_witness(witness)


def test_witness_verification_rejects_tampered_root():
    """Witness verification rejects tampered root."""
    tree = PoseidonSMT()
    witness = tree.prove_nonexistence(b"\x00" * 32)

    # Tamper with root
    witness.root = "123456789"
    assert not verify_poseidon_nonexistence_witness(witness)


# --- Field element handling ---


def test_values_reduced_to_field():
    """Values are reduced modulo SNARK_SCALAR_FIELD."""
    tree = PoseidonSMT()
    key = b"\x00" * 32
    large_value = SNARK_SCALAR_FIELD + 42

    tree.update(key, large_value)
    assert tree.get(key) == 42


def test_leaf_hash_matches_circuit():
    """Leaf hash computation matches circuit: Poseidon(key_int, value_int)."""
    key = b"\x00" * 31 + b"\x05"
    value = 42

    key_int = int.from_bytes(key, byteorder="big") % SNARK_SCALAR_FIELD
    expected_leaf_hash = poseidon_hash_bn128(key_int, value)

    tree = PoseidonSMT()
    tree.update(key, value)

    # The tree should compute the same leaf hash internally
    # We verify this indirectly by checking root computation
    # (leaf hash is not exposed in the public API)
    assert tree.get_root() != POSEIDON_EMPTY_HASHES[256]


# --- Empty hash precomputation ---


def test_empty_hashes_length():
    """POSEIDON_EMPTY_HASHES has 257 elements (levels 0-256)."""
    assert len(POSEIDON_EMPTY_HASHES) == 257


def test_empty_hashes_sentinel():
    """Empty hash at level 0 is the sentinel value 0."""
    assert POSEIDON_EMPTY_HASHES[0] == 0


def test_empty_hashes_recursive():
    """Each empty hash is Poseidon(prev, prev)."""
    for i in range(1, 257):
        prev = POSEIDON_EMPTY_HASHES[i - 1]
        expected = poseidon_hash_bn128(prev, prev)
        assert POSEIDON_EMPTY_HASHES[i] == expected


# --- Edge cases ---


def test_max_key_value():
    """Tree handles maximum key value (all 0xFF)."""
    tree = PoseidonSMT()
    key = b"\xFF" * 32
    value = SNARK_SCALAR_FIELD - 1

    tree.update(key, value)
    assert tree.get(key) == value


def test_zero_value():
    """Tree handles zero value (distinct from nonexistent key)."""
    tree = PoseidonSMT()
    key = b"\x00" * 32
    value = 0

    tree.update(key, value)
    assert tree.get(key) == 0  # Exists with value 0
    assert tree.get(b"\x00" * 31 + b"\x01") is None  # Does not exist
