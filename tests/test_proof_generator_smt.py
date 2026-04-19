"""Tests for ProofGenerator PoseidonSMT witness helpers."""

from __future__ import annotations

import inspect

import pytest

from proofs.proof_generator import ProofGenerator
from protocol.hashes import blake3_hash
from protocol.poseidon_smt import PoseidonSMT, key_to_smt_bytes


def test_witness_from_smt_roundtrip() -> None:
    """witness_from_smt produces a valid snarkjs input dict."""
    smt = PoseidonSMT()
    key1 = key_to_smt_bytes(blake3_hash([b"key1"]))
    key2 = key_to_smt_bytes(blake3_hash([b"key2"]))
    val1 = int.from_bytes(blake3_hash([b"val1"]), byteorder="big")
    val2 = int.from_bytes(blake3_hash([b"val2"]), byteorder="big")
    smt.update(key1, val1)
    smt.update(key2, val2)

    key_absent = key_to_smt_bytes(blake3_hash([b"not_here"]))
    witness = ProofGenerator.witness_from_smt(smt, key_absent)
    inp = witness.inputs

    assert inp["root"] == str(smt.get_root())
    assert inp["key"] == list(key_absent)
    assert len(inp["pathElements"]) == 256


def test_witness_from_smt_raises_for_present_key() -> None:
    smt = PoseidonSMT()
    key1 = key_to_smt_bytes(blake3_hash([b"key1"]))
    smt.update(key1, int.from_bytes(blake3_hash([b"val1"]), byteorder="big"))

    with pytest.raises(ValueError):
        ProofGenerator.witness_from_smt(smt, key1)


def test_no_placeholder_string_in_proof_generator() -> None:
    """Regression: the literal placeholder must be removed from the module."""
    import proofs.proof_generator as pg_mod

    src = inspect.getsource(pg_mod)
    assert "<poseidon_smt_root_as_field_element>" not in src, (
        "Placeholder string still present in proof_generator.py"
    )
