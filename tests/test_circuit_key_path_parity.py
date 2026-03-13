"""Cross-layer consistency: circuit key-to-path derivation matches ssmf.py."""

import pytest


@pytest.mark.layer4
@pytest.mark.circuits
def test_key_to_path_bits_matches_circuit_derivation():
    """
    Verify that the bit ordering produced by protocol/ssmf.py::_key_to_path_bits
    matches the ordering that non_existence.circom derives from key bytes.

    The circuit uses circomlib Num2Bits(8) which outputs bits LSB-first (out[0]
    is the LSB), then takes out[7-i] for path position i within each byte.
    This is equivalent to MSB-first extraction.

    Independently verify by computing expected path bits from a known key using
    the Python implementation and checking they match the formula used in the circuit.
    """
    from protocol.ssmf import _key_to_path_bits

    test_key = bytes(range(32))  # 0x00 0x01 0x02 ... 0x1f
    python_bits = _key_to_path_bits(test_key)

    # Compute expected bits using the circuit's formula:
    # For byte b, bit position i in that byte maps to path position b*8+i
    # Circuit uses Num2Bits LSB-first: out[k] = (byte >> k) & 1
    # Circuit takes out[7-i] for path index i
    # So path[b*8+i] = (byte >> (7-i)) & 1 — identical to ssmf.py
    circuit_bits = []
    for byte_val in test_key:
        for i in range(8):
            circuit_bits.append((byte_val >> (7 - i)) & 1)

    assert python_bits == circuit_bits, (
        "Bit ordering mismatch between ssmf._key_to_path_bits and "
        "non_existence.circom path derivation. First divergence at bit "
        f"{next((i for i, (a, b) in enumerate(zip(python_bits, circuit_bits)) if a != b), -1)}"
    )
    assert len(python_bits) == 256
