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


def test_prove_existence_requires_snarkjs(tmp_path: Path):
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    witness = build_dir / "document_existence.wtns"
    zkey = build_dir / "document_existence_final.zkey"
    witness.write_text("", encoding="utf-8")
    zkey.write_text("", encoding="utf-8")

    prover = Groth16Prover(tmp_path, snarkjs_bin="nonexistent-snarkjs")
    with pytest.raises(FileNotFoundError, match="snarkjs binary"):
        prover.prove_existence(
            leaf="0",
            root="0",
            path_elements=[],
            path_indices=[],
            witness_path=witness,
            zkey_path=zkey,
            proof_path=build_dir / "proof.json",
            public_path=build_dir / "public.json",
        )
