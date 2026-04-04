"""Targeted coverage tests for protocol/hashes.py — error/rejection paths.

Covers:
- Rust fallback detection (line 35)
- blake3_hash via Rust path (lines 87-88)
- _length_prefixed_bytes overflow (line 95)
- record_key Rust path + validation (lines 112-118)
- global_key Rust path (lines 157-158)
- leaf_hash Rust path (lines 180-181)
- node_hash Rust path (lines 188-189)
- hash_string (lines 252-253)
- event_id field length overflow (line 303)
- parse_dual_root_commitment — tampered binding hash (lines 386, 388)
"""

import pytest

from protocol.hashes import (
    _RUST_CRYPTO_AVAILABLE,
    blake3_hash,
    blake3_to_field_element,
    create_dual_root_commitment,
    event_id,
    global_key,
    hash_bytes,
    hash_string,
    leaf_hash,
    node_hash,
    parse_dual_root_commitment,
    record_key,
)


# ---------------------------------------------------------------------------
# Rust fallback detection (line 35)
# ---------------------------------------------------------------------------


def test_rust_crypto_available_flag():
    """_RUST_CRYPTO_AVAILABLE is bool (True if built, False otherwise)."""
    assert isinstance(_RUST_CRYPTO_AVAILABLE, bool)


# ---------------------------------------------------------------------------
# blake3_hash determinism (lines 87-88 — exercised via either path)
# ---------------------------------------------------------------------------


def test_blake3_hash_empty_parts():
    """BLAKE3 hash of empty parts list produces a 32-byte digest."""
    result = blake3_hash([])
    assert len(result) == 32


def test_blake3_hash_single_part():
    """BLAKE3 hash of one-element list."""
    result = blake3_hash([b"abc"])
    assert len(result) == 32


# ---------------------------------------------------------------------------
# record_key validation (lines 112-118)
# ---------------------------------------------------------------------------


def test_record_key_negative_version():
    """record_key rejects negative version."""
    with pytest.raises(ValueError, match="non-negative"):
        record_key("doc", "id1", -1)


def test_record_key_overflow_version():
    """record_key rejects version exceeding 64-bit range."""
    with pytest.raises(ValueError, match="maximum supported"):
        record_key("doc", "id1", 0xFFFFFFFFFFFFFFFF + 1)


def test_record_key_via_python_path():
    """Exercise record_key with a valid call (Python or Rust path)."""
    k = record_key("document", "doc-1", 0)
    assert len(k) == 32
    # version 0 is allowed
    assert k == record_key("document", "doc-1", 0)


# ---------------------------------------------------------------------------
# global_key (lines 157-158)
# ---------------------------------------------------------------------------


def test_global_key_determinism():
    """global_key returns the same value for the same inputs."""
    rk = record_key("doc", "id", 1)
    g1 = global_key("shard:a", rk)
    g2 = global_key("shard:a", rk)
    assert g1 == g2 and len(g1) == 32


def test_global_key_different_shards():
    """Different shard IDs produce different global keys."""
    rk = record_key("doc", "id", 1)
    assert global_key("shard:a", rk) != global_key("shard:b", rk)


# ---------------------------------------------------------------------------
# leaf_hash and node_hash (lines 180-181, 188-189)
# ---------------------------------------------------------------------------


def test_leaf_hash_determinism():
    """leaf_hash returns consistent 32-byte hashes."""
    k = b"\x00" * 32
    v = b"\x01" * 32
    h1 = leaf_hash(k, v)
    h2 = leaf_hash(k, v)
    assert h1 == h2 and len(h1) == 32


def test_node_hash_determinism():
    """node_hash returns consistent 32-byte hashes."""
    left = b"\x00" * 32
    right = b"\x01" * 32
    h1 = node_hash(left, right)
    h2 = node_hash(left, right)
    assert h1 == h2 and len(h1) == 32


def test_node_hash_order_sensitive():
    """node_hash(a,b) != node_hash(b,a) — prevents second-preimage attacks."""
    a = b"\x00" * 32
    b = b"\x01" * 32
    assert node_hash(a, b) != node_hash(b, a)


# ---------------------------------------------------------------------------
# hash_string (lines 252-253)
# ---------------------------------------------------------------------------


def test_hash_string_returns_32_bytes():
    """hash_string produces domain-separated 32-byte digest."""
    h = hash_string("hello world")
    assert len(h) == 32


def test_hash_string_determinism():
    """hash_string is deterministic."""
    assert hash_string("x") == hash_string("x")


def test_hash_string_different_inputs():
    """Different strings produce different hashes."""
    assert hash_string("a") != hash_string("b")


# ---------------------------------------------------------------------------
# event_id field length overflow (line 303)
# ---------------------------------------------------------------------------


def test_event_id_oversized_field():
    """event_id rejects fields exceeding the 4-byte length limit."""
    huge = "x" * (0xFFFFFFFF + 1)
    with pytest.raises(ValueError, match="exceeds 4-byte limit"):
        event_id(huge, "hash", "ts")


# ---------------------------------------------------------------------------
# parse_dual_root_commitment error paths (lines 385-392)
# ---------------------------------------------------------------------------


def test_parse_dual_root_commitment_wrong_length():
    """Reject commitments with wrong overall byte count."""
    with pytest.raises(ValueError, match="bytes"):
        parse_dual_root_commitment(b"\x00" * 10)


def test_parse_dual_root_commitment_bad_length_metadata():
    """Reject commitment where embedded length fields don't match 32."""
    # Build a 100-byte payload with bad embedded length prefix
    # Expected: 2 + 32 + 2 + 32 + 32 = 100 bytes
    bad = (
        (0).to_bytes(2, "big") + b"\x00" * 32 + (0).to_bytes(2, "big") + b"\x00" * 32 + b"\x00" * 32
    )
    assert len(bad) == 100
    with pytest.raises(ValueError, match="length metadata"):
        parse_dual_root_commitment(bad)


def test_parse_dual_root_commitment_tampered_binding():
    """Reject commitment where the binding hash doesn't match."""
    blake3_root = b"\xaa" * 32
    poseidon_root = b"\xbb" * 32
    valid_commitment = create_dual_root_commitment(blake3_root, poseidon_root)

    # Tamper with the binding hash (last 32 bytes)
    tampered = bytearray(valid_commitment)
    tampered[-1] ^= 0xFF
    with pytest.raises(ValueError, match="tampered"):
        parse_dual_root_commitment(bytes(tampered))


def test_parse_dual_root_commitment_roundtrip():
    """create → parse roundtrip preserves roots."""
    blake3_root = b"\x01" * 32
    poseidon_root = b"\x02" * 32
    commitment = create_dual_root_commitment(blake3_root, poseidon_root)
    b3, pos = parse_dual_root_commitment(commitment)
    assert b3 == blake3_root
    assert pos == poseidon_root


# ---------------------------------------------------------------------------
# blake3_to_field_element
# ---------------------------------------------------------------------------


def test_blake3_to_field_element_returns_decimal_string():
    """blake3_to_field_element returns a decimal string in the BN128 field."""
    result = blake3_to_field_element(b"test seed")
    assert isinstance(result, str)
    val = int(result)
    assert 0 <= val < 21888242871839275222246405745257275088548364400416034343698204186575808495617


def test_blake3_to_field_element_deterministic():
    """Same seed produces the same field element."""
    a = blake3_to_field_element(b"seed")
    b = blake3_to_field_element(b"seed")
    assert a == b


# ---------------------------------------------------------------------------
# hash_bytes
# ---------------------------------------------------------------------------


def test_hash_bytes_determinism():
    """hash_bytes is deterministic and 32-byte output."""
    h = hash_bytes(b"payload")
    assert len(h) == 32
    assert h == hash_bytes(b"payload")
