"""
Tests for the dual-anchor redaction protocol (protocol/redaction_ledger.py).

Coverage:
- Poseidon root serialization round-trip and validation
- SMT key derivation for "redaction_root_poseidon" namespace
- RedactionProofWithLedger construction and verify_smt_anchor
- verify_all with and without a pluggable ZK verifier
- Tamper detection: modified ZK public input root, modified SMT value
"""

from unittest.mock import patch

import pytest

from protocol.hashes import SNARK_SCALAR_FIELD, record_key
from protocol.redaction import RedactionProtocol
from protocol.redaction_ledger import (
    POSEIDON_ROOT_RECORD_TYPE,
    RedactionProofWithLedger,
    ZKPublicInputs,
    poseidon_root_from_bytes,
    poseidon_root_record_key,
    poseidon_root_to_bytes,
    verify_zk_redaction,
)
from protocol.ssmf import ExistenceProof, SparseMerkleTree


# ---------------------------------------------------------------------------
# Poseidon root serialization helpers
# ---------------------------------------------------------------------------


def test_poseidon_root_to_bytes_round_trip():
    """Serialization and deserialization of a Poseidon root is identity."""
    root_int = 12345678901234567890
    root_str = str(root_int)
    serialized = poseidon_root_to_bytes(root_str)
    assert len(serialized) == 32
    recovered = poseidon_root_from_bytes(serialized)
    assert recovered == root_str


def test_poseidon_root_to_bytes_zero():
    """Zero is a valid field element."""
    serialized = poseidon_root_to_bytes("0")
    assert serialized == b"\x00" * 32
    assert poseidon_root_from_bytes(serialized) == "0"


def test_poseidon_root_to_bytes_max_valid():
    """Maximum valid field element (SNARK_SCALAR_FIELD - 1) round-trips."""
    max_val = SNARK_SCALAR_FIELD - 1
    root_str = str(max_val)
    serialized = poseidon_root_to_bytes(root_str)
    assert len(serialized) == 32
    assert poseidon_root_from_bytes(serialized) == root_str


def test_poseidon_root_to_bytes_rejects_non_integer():
    """Non-integer strings are rejected."""
    with pytest.raises(ValueError, match="decimal integer"):
        poseidon_root_to_bytes("not_an_int")


def test_poseidon_root_to_bytes_rejects_negative():
    """Negative integers are rejected."""
    with pytest.raises(ValueError, match="outside the BN128 scalar field"):
        poseidon_root_to_bytes("-1")


def test_poseidon_root_to_bytes_rejects_out_of_field():
    """Values >= SNARK_SCALAR_FIELD are rejected."""
    with pytest.raises(ValueError, match="outside the BN128 scalar field"):
        poseidon_root_to_bytes(str(SNARK_SCALAR_FIELD))


def test_poseidon_root_from_bytes_wrong_length():
    """from_bytes raises ValueError for non-32-byte input."""
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        poseidon_root_from_bytes(b"\x00" * 16)


def test_poseidon_root_from_bytes_rejects_out_of_field():
    """from_bytes rejects values >= SNARK_SCALAR_FIELD."""
    # Encode a value that is >= SNARK_SCALAR_FIELD
    big_val = SNARK_SCALAR_FIELD + 1
    raw = big_val.to_bytes(32, byteorder="big")
    with pytest.raises(ValueError, match="outside the BN128 scalar field"):
        poseidon_root_from_bytes(raw)


# ---------------------------------------------------------------------------
# SMT key derivation
# ---------------------------------------------------------------------------


def test_poseidon_root_record_key_is_deterministic():
    """Same inputs always produce the same 32-byte key."""
    k1 = poseidon_root_record_key("doc42", 1)
    k2 = poseidon_root_record_key("doc42", 1)
    assert k1 == k2
    assert len(k1) == 32


def test_poseidon_root_record_key_differs_from_document_key():
    """Poseidon root key must differ from the standard document key."""
    poseidon_key = poseidon_root_record_key("doc42", 1)
    document_key = record_key("document", "doc42", 1)
    assert poseidon_key != document_key


def test_poseidon_root_record_key_uses_correct_namespace():
    """Key is in the POSEIDON_ROOT_RECORD_TYPE namespace."""
    k = poseidon_root_record_key("docX", 3)
    expected = record_key(POSEIDON_ROOT_RECORD_TYPE, "docX", 3)
    assert k == expected


def test_poseidon_root_record_key_version_changes_key():
    """Different versions produce different keys (append-only semantics)."""
    k1 = poseidon_root_record_key("doc1", 1)
    k2 = poseidon_root_record_key("doc1", 2)
    assert k1 != k2


# ---------------------------------------------------------------------------
# Full integration: build SMT, insert Poseidon root, generate + verify proof
# ---------------------------------------------------------------------------


def make_fixture(poseidon_root_str: str = "99999999999", doc_id: str = "docA", version: int = 1):
    """Helper: build an SMT with one Poseidon root entry and return all pieces."""
    smt = SparseMerkleTree()
    key = poseidon_root_record_key(doc_id, version)
    value = poseidon_root_to_bytes(poseidon_root_str)
    smt.update(key, value)
    smt_proof = smt.prove_existence(key)
    public_inputs = ZKPublicInputs(
        original_root=poseidon_root_str,
        redacted_commitment="11111111111",
        revealed_count=2,
    )
    wrapped = RedactionProofWithLedger(
        smt_proof=smt_proof,
        zk_proof={"pi_a": [], "pi_b": [], "pi_c": []},
        zk_public_inputs=public_inputs,
    )
    return smt, wrapped


def test_verify_smt_anchor_succeeds():
    """verify_smt_anchor returns True for a valid proof."""
    smt, wrapped = make_fixture()
    assert wrapped.verify_smt_anchor(smt.get_root()) is True


def test_verify_smt_anchor_wrong_smt_root():
    """verify_smt_anchor returns False when the expected SMT root doesn't match."""
    smt, wrapped = make_fixture()
    wrong_root = bytes(32)  # all zeros != real root
    assert wrapped.verify_smt_anchor(wrong_root) is False


def test_verify_smt_anchor_wrong_smt_root_length():
    """verify_smt_anchor returns False for a root hash of wrong length."""
    smt, wrapped = make_fixture()
    assert wrapped.verify_smt_anchor(b"short") is False


def test_verify_smt_anchor_fails_if_zk_root_modified():
    """
    If zk_public_inputs.original_root is changed after proof creation,
    verify_smt_anchor must detect the mismatch.
    """
    smt, wrapped = make_fixture(poseidon_root_str="99999999999")
    smt_root = smt.get_root()

    # Mutate the ZK public input root to something different
    wrapped.zk_public_inputs = ZKPublicInputs(
        original_root="12345",  # tampered
        redacted_commitment=wrapped.zk_public_inputs.redacted_commitment,
        revealed_count=wrapped.zk_public_inputs.revealed_count,
    )
    assert wrapped.verify_smt_anchor(smt_root) is False


def test_verify_smt_anchor_fails_if_smt_value_tampered():
    """Tampering with the SMT proof value_hash is detected."""
    smt, wrapped = make_fixture()
    smt_root = smt.get_root()

    # Replace value_hash in the proof with a different value
    tampered_proof = ExistenceProof(
        key=wrapped.smt_proof.key,
        value_hash=poseidon_root_to_bytes("12345"),  # different from original_root
        siblings=wrapped.smt_proof.siblings,
        root_hash=wrapped.smt_proof.root_hash,
    )
    wrapped.smt_proof = tampered_proof
    assert wrapped.verify_smt_anchor(smt_root) is False


def test_verify_all_without_zk_verifier():
    """verify_all without an override uses the default Groth16 verifier."""
    smt, wrapped = make_fixture()

    with patch("protocol.redaction_ledger.verify_zk_redaction", return_value=True) as mock_verify:
        assert wrapped.verify_all(smt.get_root()) is True
        mock_verify.assert_called_once_with(wrapped.zk_proof, wrapped.zk_public_inputs)

    assert wrapped.verify_all(bytes(32)) is False


def test_verify_all_with_accepting_zk_verifier():
    """verify_all invokes the ZK verifier when provided and returns its result."""
    smt, wrapped = make_fixture()
    smt_root = smt.get_root()

    def accept_all(proof, inputs):
        return True

    assert wrapped.verify_all(smt_root, zk_verifier=accept_all) is True


def test_verify_all_with_rejecting_zk_verifier():
    """verify_all returns False when the ZK verifier rejects."""
    smt, wrapped = make_fixture()
    smt_root = smt.get_root()

    def reject_all(proof, inputs):
        return False

    assert wrapped.verify_all(smt_root, zk_verifier=reject_all) is False


def test_verify_all_zk_verifier_receives_correct_args():
    """The ZK verifier receives the proof blob and public inputs unchanged."""
    smt, wrapped = make_fixture()
    smt_root = smt.get_root()

    captured = {}

    def capture(proof, inputs):
        captured["proof"] = proof
        captured["inputs"] = inputs
        return True

    wrapped.verify_all(smt_root, zk_verifier=capture)

    assert captured["proof"] is wrapped.zk_proof
    assert captured["inputs"] is wrapped.zk_public_inputs


def test_verify_zk_redaction_maps_public_inputs_and_calls_prover():
    """verify_zk_redaction forwards a redaction_validity proof to Groth16Prover."""
    proof_blob = {"pi_a": ["1", "2"], "pi_b": [["3", "4"], ["5", "6"]], "pi_c": ["7", "8"]}
    public_inputs = ZKPublicInputs(
        original_root="123",
        redacted_commitment="456",
        revealed_count=2,
    )

    with patch("protocol.redaction_ledger.Groth16Prover.verify", return_value=True) as mock_verify:
        assert verify_zk_redaction(proof_blob, public_inputs) is True

    zk_proof_arg = mock_verify.call_args.args[0]
    vkey_arg = mock_verify.call_args.kwargs["verification_key_path"]

    assert zk_proof_arg.proof is proof_blob
    assert zk_proof_arg.circuit == "redaction_validity"
    assert zk_proof_arg.public_signals == ["123", "456", "2"]
    assert vkey_arg.name == "redaction_validity_vkey.json"


def test_verify_zk_redaction_rejects_invalid_public_inputs():
    """Non-numeric public inputs are rejected before snarkjs invocation."""
    bad_inputs = ZKPublicInputs(
        original_root="not-a-number",
        redacted_commitment="456",
        revealed_count=1,
    )
    assert verify_zk_redaction({"pi_a": [], "pi_b": [], "pi_c": []}, bad_inputs) is False


# ---------------------------------------------------------------------------
# RedactionProtocol integration helpers
# ---------------------------------------------------------------------------


def test_commit_document_dual_inserts_poseidon_root():
    """commit_document_dual inserts the Poseidon root into the SMT."""
    parts = ["section one", "section two", "section three"]
    poseidon_root = "7654321"
    smt = SparseMerkleTree()

    tree, blake3_root = RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id="docB",
        version=1,
    )

    # The BLAKE3 commitment is still returned as a hex string
    assert isinstance(blake3_root, str)
    assert len(blake3_root) == 64  # 32 bytes hex-encoded

    # The Poseidon root must be in the SMT
    key = poseidon_root_record_key("docB", 1)
    stored_value = smt.get(key)
    assert stored_value is not None
    assert poseidon_root_from_bytes(stored_value) == poseidon_root


def test_create_redaction_proof_with_ledger_round_trip():
    """
    Full flow: commit → generate proof with ledger → verify SMT anchor.
    """
    parts = ["alpha", "beta", "gamma"]
    poseidon_root = "99887766554433"
    smt = SparseMerkleTree()

    tree, _ = RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id="docC",
        version=1,
    )

    wrapped = RedactionProtocol.create_redaction_proof_with_ledger(
        tree=tree,
        revealed_indices=[0, 2],
        poseidon_root=poseidon_root,
        smt=smt,
        document_id="docC",
        version=1,
        zk_proof={"dummy": True},
        redacted_commitment="55555",
        revealed_count=2,
    )

    assert isinstance(wrapped, RedactionProofWithLedger)
    assert wrapped.zk_public_inputs.original_root == poseidon_root
    assert wrapped.zk_public_inputs.revealed_count == 2
    assert wrapped.verify_smt_anchor(smt.get_root()) is True


def test_append_only_versioning_via_dual_anchor():
    """Different versions produce independent SMT entries."""
    parts = ["x", "y"]
    smt = SparseMerkleTree()

    RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root="111",
        smt=smt,
        document_id="docD",
        version=1,
    )
    RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root="222",
        smt=smt,
        document_id="docD",
        version=2,
    )

    key_v1 = poseidon_root_record_key("docD", 1)
    key_v2 = poseidon_root_record_key("docD", 2)

    assert smt.get(key_v1) == poseidon_root_to_bytes("111")
    assert smt.get(key_v2) == poseidon_root_to_bytes("222")
    assert key_v1 != key_v2
