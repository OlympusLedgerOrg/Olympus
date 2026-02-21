from pathlib import Path

import pytest

from protocol.zkp import Groth16Prover, ZKProof


def test_zkproof_to_dict_round_trip():
    proof = ZKProof(proof={"a": 1}, public_signals=[1, 2, 3], circuit="example")
    assert proof.to_dict() == {"proof": {"a": 1}, "public_signals": [1, 2, 3], "circuit": "example"}


def test_groth16_prover_requires_snarkjs():
    prover = Groth16Prover(Path("/tmp"), snarkjs_bin="nonexistent-snarkjs")
    dummy_proof = ZKProof(proof={}, public_signals=[], circuit="document_existence")
    with pytest.raises(FileNotFoundError, match="snarkjs binary"):
        prover.verify(dummy_proof, verification_key_path=Path("/tmp/vkey.json"))
