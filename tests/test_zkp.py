import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from protocol.zkp import Groth16Prover, ZKProof


_GROTH16_PROOF = {"pi_a": [], "pi_b": [], "pi_c": []}


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


def test_prove_existence_missing_witness(tmp_path: Path):
    """prove_existence raises FileNotFoundError when witness file is absent."""
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    zkey = build_dir / "document_existence_final.zkey"
    zkey.write_text("", encoding="utf-8")

    prover = Groth16Prover(tmp_path)
    with patch("shutil.which", return_value="/usr/bin/snarkjs"):
        with pytest.raises(FileNotFoundError, match="Witness file not found"):
            prover.prove_existence(
                leaf="0",
                root="0",
                path_elements=[],
                path_indices=[],
                witness_path=build_dir / "missing.wtns",
                zkey_path=zkey,
            )


def test_prove_existence_missing_zkey(tmp_path: Path):
    """prove_existence raises FileNotFoundError when zkey file is absent."""
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    witness = build_dir / "document_existence.wtns"
    witness.write_text("", encoding="utf-8")

    prover = Groth16Prover(tmp_path)
    with patch("shutil.which", return_value="/usr/bin/snarkjs"):
        with pytest.raises(FileNotFoundError, match="ZKey file not found"):
            prover.prove_existence(
                leaf="0",
                root="0",
                path_elements=[],
                path_indices=[],
                witness_path=witness,
                zkey_path=build_dir / "missing.zkey",
            )


def test_prove_existence_success(tmp_path: Path):
    """prove_existence returns a ZKProof when snarkjs succeeds."""
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    witness = build_dir / "document_existence.wtns"
    zkey = build_dir / "document_existence_final.zkey"
    proof_file = build_dir / "proof.json"
    public_file = build_dir / "public.json"

    witness.write_text("", encoding="utf-8")
    zkey.write_text("", encoding="utf-8")
    proof_file.write_text(json.dumps(_GROTH16_PROOF), encoding="utf-8")
    public_file.write_text(json.dumps(["1", "0"]), encoding="utf-8")

    prover = Groth16Prover(tmp_path)
    mock_result = MagicMock(spec=subprocess.CompletedProcess)

    with patch("shutil.which", return_value="/usr/bin/snarkjs"):
        with patch("subprocess.run", return_value=mock_result):
            result = prover.prove_existence(
                leaf="0",
                root="0",
                path_elements=[],
                path_indices=[],
                witness_path=witness,
                zkey_path=zkey,
                proof_path=proof_file,
                public_path=public_file,
            )

    assert isinstance(result, ZKProof)
    assert result.circuit == "document_existence"
    assert result.public_signals == ["1", "0"]


def test_verify_missing_vkey(tmp_path: Path):
    """verify raises FileNotFoundError when verification key is absent."""
    prover = Groth16Prover(tmp_path)
    dummy_proof = ZKProof(proof={}, public_signals=[], circuit="document_existence")
    with patch("shutil.which", return_value="/usr/bin/snarkjs"):
        with pytest.raises(FileNotFoundError, match="Verification key not found"):
            prover.verify(dummy_proof)


def test_verify_success(tmp_path: Path):
    """verify returns True when snarkjs groth16 verify succeeds."""
    keys_dir = tmp_path / "keys" / "verification_keys"
    keys_dir.mkdir(parents=True)
    vkey = keys_dir / "document_existence_vkey.json"
    vkey.write_text(json.dumps({}), encoding="utf-8")

    prover = Groth16Prover(tmp_path)
    dummy_proof = ZKProof(
        proof=_GROTH16_PROOF,
        public_signals=["1"],
        circuit="document_existence",
    )
    mock_result = MagicMock(spec=subprocess.CompletedProcess)

    with patch("shutil.which", return_value="/usr/bin/snarkjs"):
        with patch("subprocess.run", return_value=mock_result):
            assert prover.verify(dummy_proof) is True


def test_verify_failure(tmp_path: Path):
    """verify returns False when snarkjs groth16 verify fails."""
    vkey = tmp_path / "vkey.json"
    vkey.write_text(json.dumps({}), encoding="utf-8")

    prover = Groth16Prover(tmp_path)
    dummy_proof = ZKProof(proof={}, public_signals=[], circuit="document_existence")

    with patch("shutil.which", return_value="/usr/bin/snarkjs"):
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "snarkjs")):
            assert prover.verify(dummy_proof, verification_key_path=vkey) is False
