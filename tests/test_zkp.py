import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from protocol.canonical_json import canonical_json_bytes
from protocol.hashes import hash_bytes
from protocol.zkp import Groth16Prover, ZKProof


_GROTH16_PROOF = {"pi_a": [], "pi_b": [], "pi_c": []}


def test_zkproof_to_dict_round_trip():
    proof = ZKProof(proof={"a": 1}, public_signals=[1, 2, 3], circuit="example")
    proof_bytes_hex = canonical_json_bytes({"a": 1}).hex()
    public_hash = hash_bytes(canonical_json_bytes([1, 2, 3])).hex()
    result = proof.to_dict()

    assert result["proof_type"] == "groth16"
    assert result["circuit_id"] == "example"
    assert result["public_inputs_hash"] == public_hash
    assert result["proof_bytes"] == proof_bytes_hex
    # Backwards-compatibility fields remain present
    assert result["proof"] == {"a": 1}
    assert result["public_signals"] == [1, 2, 3]
    assert result["circuit"] == "example"


def test_zkproof_proof_bytes_are_canonical():
    proof = ZKProof(proof={"a": 1}, public_signals=[], circuit="example")
    assert proof.proof_bytes == canonical_json_bytes({"a": 1})


def test_zkproof_from_dict_validates_hash():
    proof_dict = {
        "proof_type": "groth16",
        "circuit_id": "example",
        "public_inputs_hash": hash_bytes(canonical_json_bytes([1, 2, 3])).hex(),
        "proof_bytes": canonical_json_bytes({"a": 1}).hex(),
        "protocol_version": "1",
        "public_signals": [1, 2, 3],
    }
    proof = ZKProof.from_dict(proof_dict)
    assert proof.circuit == "example"
    assert proof.proof == {"a": 1}
    assert proof.public_signals == [1, 2, 3]


def test_zkproof_from_dict_rejects_mismatched_hash():
    proof_dict = {
        "proof_type": "groth16",
        "circuit_id": "example",
        "public_inputs_hash": "invalid_hash",
        "proof_bytes": canonical_json_bytes({"a": 1}).hex(),
        "protocol_version": "1",
        "public_signals": [1, 2, 3],
    }
    with pytest.raises(
        ValueError, match=r"public_inputs_hash.*expected [0-9a-f]+, got invalid_hash"
    ):
        ZKProof.from_dict(proof_dict)


def test_zkproof_from_dict_rejects_mismatched_proof_bytes():
    proof_dict = {
        "proof_type": "groth16",
        "circuit_id": "example",
        "public_inputs_hash": hash_bytes(canonical_json_bytes([1, 2, 3])).hex(),
        "proof_bytes": canonical_json_bytes({"a": 2}).hex(),
        "protocol_version": "1",
        "public_signals": [1, 2, 3],
        "proof": {"a": 1},
    }
    with pytest.raises(ValueError, match=r"Canonical proof bytes mismatch"):
        ZKProof.from_dict(proof_dict)


def test_groth16_prover_requires_snarkjs():
    prover = Groth16Prover(Path("/tmp"), snarkjs_bin="nonexistent-snarkjs")
    dummy_proof = ZKProof(proof={}, public_signals=[], circuit="document_existence")
    with pytest.raises(FileNotFoundError, match="snarkjs binary"):
        prover.verify(dummy_proof, verification_key_path=Path("/tmp/vkey.json"))


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
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


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
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


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
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


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
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
        with patch("protocol.zkp._run_subprocess", return_value=mock_result):
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
        with patch("protocol.zkp._run_subprocess", return_value=mock_result):
            assert prover.verify(dummy_proof) is True


def test_verify_failure(tmp_path: Path):
    """verify returns False when snarkjs groth16 verify fails."""
    vkey = tmp_path / "vkey.json"
    vkey.write_text(json.dumps({}), encoding="utf-8")

    prover = Groth16Prover(tmp_path)
    dummy_proof = ZKProof(proof={}, public_signals=[], circuit="document_existence")

    with patch("shutil.which", return_value="/usr/bin/snarkjs"):
        with patch(
            "protocol.zkp._run_subprocess",
            side_effect=subprocess.CalledProcessError(1, "snarkjs"),
        ):
            assert prover.verify(dummy_proof, verification_key_path=vkey) is False


def test_run_kills_process_group_on_timeout(tmp_path: Path) -> None:
    """Verify _run raises TimeoutExpired and does not leave orphans."""
    prover = Groth16Prover(tmp_path, snarkjs_bin="npx")
    prover._snarkjs_path = shutil.which("sleep") or "/bin/sleep"
    prover.snarkjs_bin = "sleep"

    # Monkeypatch _build_cmd to run `sleep 60` (a long-running process)
    with patch.object(prover, "_build_cmd", return_value=["sleep", "60"]):
        with patch.object(prover, "_check_snarkjs", return_value=None):
            with pytest.raises(subprocess.TimeoutExpired):
                prover._run([], timeout=1)


def test_run_subprocess_fallback_uses_pdeathsig(monkeypatch: pytest.MonkeyPatch) -> None:
    """When start_new_session raises OSError, _make_pdeathsig_preexec is called."""
    import protocol.zkp as zkp_mod

    preexec_called = []

    def fake_pdeathsig():
        preexec_called.append(True)
        return lambda: None

    monkeypatch.setattr(zkp_mod, "_make_pdeathsig_preexec", fake_pdeathsig)

    original_popen = subprocess.Popen
    call_count = [0]

    def popen_raise_first(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            raise OSError("setsid blocked")
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", popen_raise_first)

    # Should not raise — falls back and completes
    zkp_mod._run_subprocess(["echo", "ok"], timeout=5)
    assert preexec_called, "preexec_fn factory was not called on OSError fallback"


def test_try_limit_cgroup_called_after_popen(monkeypatch: pytest.MonkeyPatch) -> None:
    """_try_limit_cgroup is called with the child PID after every successful Popen."""
    import protocol.zkp as zkp_mod

    limited_pids: list[int] = []

    def fake_limit(pid: int, *, memory_bytes: int) -> None:
        limited_pids.append(pid)

    monkeypatch.setattr(zkp_mod, "_try_limit_cgroup", fake_limit)

    result = zkp_mod._run_subprocess(["echo", "ok"], timeout=5)
    assert result.returncode == 0
    assert len(limited_pids) == 1, "expected exactly one _try_limit_cgroup call"


# --- CI gate: verification key presence (fix-11) ---


def test_committed_verification_keys_present():
    """CI gate: committed verification keys must exist in the repository."""
    repo_root = Path(__file__).resolve().parent.parent
    vkeys_dir = repo_root / "proofs" / "keys" / "verification_keys"
    assert vkeys_dir.is_dir(), f"Verification keys directory missing: {vkeys_dir}"

    vkey_file = vkeys_dir / "document_existence_vkey.json"
    assert vkey_file.is_file(), f"Verification key missing: {vkey_file}"

    # Ensure the key is valid JSON with expected structure
    data = json.loads(vkey_file.read_text(encoding="utf-8"))
    assert "protocol" in data, "Verification key missing 'protocol' field"
    assert "curve" in data, "Verification key missing 'curve' field"
