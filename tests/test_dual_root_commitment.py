import pytest

from protocol.hashes import (
    HASH_SEPARATOR,
    blake3_hash,
    create_dual_root_commitment,
    hash_bytes,
    parse_dual_root_commitment,
)


def _sample_roots() -> tuple[bytes, bytes]:
    return hash_bytes(b"blake3 shard root"), hash_bytes(b"poseidon merkle root")


def test_dual_root_commitment_deterministic() -> None:
    blake3_root, poseidon_root = _sample_roots()
    first = create_dual_root_commitment(blake3_root, poseidon_root)
    second = create_dual_root_commitment(blake3_root, poseidon_root)
    assert first == second


def test_dual_root_commitment_round_trip() -> None:
    blake3_root, poseidon_root = _sample_roots()
    commitment = create_dual_root_commitment(blake3_root, poseidon_root)
    recovered_blake3, recovered_poseidon = parse_dual_root_commitment(commitment)
    assert recovered_blake3 == blake3_root
    assert recovered_poseidon == poseidon_root


def test_dual_root_commitment_rejects_empty_blake3_root() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        create_dual_root_commitment(b"", hash_bytes(b"poseidon"))


def test_dual_root_commitment_rejects_empty_poseidon_root() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        create_dual_root_commitment(hash_bytes(b"blake3"), b"")


def test_parse_dual_root_commitment_rejects_truncated_input() -> None:
    blake3_root, poseidon_root = _sample_roots()
    commitment = create_dual_root_commitment(blake3_root, poseidon_root)[:-1]
    with pytest.raises(ValueError, match="100 bytes"):
        parse_dual_root_commitment(commitment)


def test_parse_dual_root_commitment_rejects_tampered_binding_hash() -> None:
    blake3_root, poseidon_root = _sample_roots()
    commitment = bytearray(create_dual_root_commitment(blake3_root, poseidon_root))
    commitment[-1] ^= 0x01
    with pytest.raises(ValueError, match="tampered commitment"):
        parse_dual_root_commitment(bytes(commitment))


def test_parse_dual_root_commitment_rejects_tampered_blake3_root() -> None:
    blake3_root, poseidon_root = _sample_roots()
    commitment = bytearray(create_dual_root_commitment(blake3_root, poseidon_root))
    commitment[2] ^= 0xFF  # Flip a bit in the BLAKE3 root segment
    with pytest.raises(ValueError, match="tampered commitment"):
        parse_dual_root_commitment(bytes(commitment))


def test_parse_dual_root_commitment_rejects_tampered_poseidon_root() -> None:
    blake3_root, poseidon_root = _sample_roots()
    commitment = bytearray(create_dual_root_commitment(blake3_root, poseidon_root))
    poseidon_offset = 2 + len(blake3_root) + 2
    commitment[poseidon_offset] ^= 0x0F
    with pytest.raises(ValueError, match="tampered commitment"):
        parse_dual_root_commitment(bytes(commitment))


def test_dual_root_commitment_order_sensitive() -> None:
    blake3_root, poseidon_root = _sample_roots()
    forward = create_dual_root_commitment(blake3_root, poseidon_root)
    reversed_commitment = create_dual_root_commitment(poseidon_root, blake3_root)
    assert forward != reversed_commitment


def test_dual_root_commitment_binding_hash_domain_separated() -> None:
    blake3_root, poseidon_root = _sample_roots()
    commitment = create_dual_root_commitment(blake3_root, poseidon_root)
    binding_hash = commitment[-32:]
    plain_hash = blake3_hash([blake3_root, HASH_SEPARATOR.encode("utf-8"), poseidon_root])
    assert binding_hash != plain_hash


def test_dual_root_commitment_preserves_length_prefixes() -> None:
    blake3_root, poseidon_root = _sample_roots()
    commitment = create_dual_root_commitment(blake3_root, poseidon_root)
    assert len(commitment) == 100
    assert int.from_bytes(commitment[:2], "big") == 32
    second_length_offset = 2 + len(blake3_root)
    assert int.from_bytes(commitment[second_length_offset : second_length_offset + 2], "big") == 32


def test_parse_dual_root_commitment_error_message_for_tampering() -> None:
    blake3_root, poseidon_root = _sample_roots()
    commitment = bytearray(create_dual_root_commitment(blake3_root, poseidon_root))
    commitment[-1] ^= 0x01
    with pytest.raises(ValueError) as excinfo:
        parse_dual_root_commitment(bytes(commitment))
    assert str(excinfo.value) == "tampered commitment"
