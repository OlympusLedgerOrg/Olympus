"""
Tests for the dual-anchor redaction protocol (protocol/redaction_ledger.py).

Coverage:
- Poseidon root serialization round-trip and validation
- SMT key derivation for "redaction_root_poseidon" namespace
- RedactionProofWithLedger construction and verify_smt_anchor
- verify_all with and without a pluggable ZK verifier
- Tamper detection: modified ZK public input root, modified SMT value
- Tamper detection: dual-root commitment integrity
"""

from unittest.mock import patch

import pytest

from protocol.canonical import CANONICAL_VERSION, canonicalize_document, document_to_bytes
from protocol.canonicalizer import canonicalization_provenance
from protocol.hashes import SNARK_SCALAR_FIELD, blake3_to_field_element, hash_bytes, record_key
from protocol.ledger import Ledger
from protocol.poseidon_tree import PoseidonMerkleTree
from protocol.redaction import RedactionProof, RedactionProtocol
from protocol.redaction_ledger import (
    POSEIDON_ROOT_RECORD_TYPE,
    RedactionProofWithLedger,
    VerificationResult,
    ZKPublicInputs,
    poseidon_root_from_bytes,
    poseidon_root_record_key,
    poseidon_root_to_bytes,
    verify_zk_redaction,
)
from protocol.ssmf import ExistenceProof, SparseMerkleTree


def _poseidon_root_for_parts(parts: list[str]) -> str:
    canonical = RedactionProtocol.canonical_section_bytes_list(parts)
    leaves = [int(blake3_to_field_element(part)) for part in canonical]
    return PoseidonMerkleTree(leaves, depth=4).get_root()


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

    with patch(
        "protocol.redaction_ledger.verify_zk_redaction", return_value=VerificationResult.VALID
    ) as mock_verify:
        assert wrapped.verify_all(smt.get_root()) is VerificationResult.VALID
        mock_verify.assert_called_once_with(wrapped.zk_proof, wrapped.zk_public_inputs)

    assert wrapped.verify_all(bytes(32)) is VerificationResult.INVALID


def test_verify_all_with_accepting_zk_verifier():
    """verify_all invokes the ZK verifier when provided and returns its result."""
    smt, wrapped = make_fixture()
    smt_root = smt.get_root()

    def accept_all(proof, inputs):
        return VerificationResult.VALID

    assert wrapped.verify_all(smt_root, zk_verifier=accept_all) is VerificationResult.VALID


def test_verify_all_with_rejecting_zk_verifier():
    """verify_all returns INVALID when the ZK verifier rejects."""
    smt, wrapped = make_fixture()
    smt_root = smt.get_root()

    def reject_all(proof, inputs):
        return VerificationResult.INVALID

    assert wrapped.verify_all(smt_root, zk_verifier=reject_all) is VerificationResult.INVALID


def test_verify_all_zk_verifier_receives_correct_args():
    """The ZK verifier receives the proof blob and public inputs unchanged."""
    smt, wrapped = make_fixture()
    smt_root = smt.get_root()

    captured = {}

    def capture(proof, inputs):
        captured["proof"] = proof
        captured["inputs"] = inputs
        return VerificationResult.VALID

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
        assert verify_zk_redaction(proof_blob, public_inputs) is VerificationResult.VALID

    kwargs = mock_verify.call_args[1]
    zk_proof_arg = kwargs["proof"]
    vkey_arg = kwargs["verification_key_path"]

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
    assert (
        verify_zk_redaction({"pi_a": [], "pi_b": [], "pi_c": []}, bad_inputs)
        is VerificationResult.UNABLE_TO_VERIFY
    )


def test_verify_zk_redaction_reports_missing_verification_key():
    """Missing verification key surfaces as UNABLE_TO_VERIFY."""
    proof_blob = {"pi_a": ["1", "2"], "pi_b": [["3", "4"], ["5", "6"]], "pi_c": ["7", "8"]}
    public_inputs = ZKPublicInputs(
        original_root="123",
        redacted_commitment="456",
        revealed_count=2,
    )

    with patch("protocol.redaction_ledger.Groth16Prover.verify", side_effect=FileNotFoundError):
        result = verify_zk_redaction(proof_blob, public_inputs)

    assert result is VerificationResult.UNABLE_TO_VERIFY


# ---------------------------------------------------------------------------
# RedactionProtocol integration helpers
# ---------------------------------------------------------------------------


def test_commit_document_dual_inserts_poseidon_root():
    """commit_document_dual inserts the Poseidon root into the SMT."""
    parts = ["section one", "section two", "section three"]
    poseidon_root = _poseidon_root_for_parts(parts)
    smt = SparseMerkleTree()

    tree, commitment = RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id="docB",
        version=1,
    )

    # The BLAKE3 commitment is still returned as a hex string
    assert isinstance(commitment.blake3_root, str)
    assert len(commitment.blake3_root) == 64  # 32 bytes hex-encoded
    assert commitment.poseidon_root == poseidon_root

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
    poseidon_root = _poseidon_root_for_parts(parts)
    smt = SparseMerkleTree()

    tree, commitment = RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id="docC",
        version=1,
    )

    wrapped = RedactionProtocol.create_redaction_proof_with_ledger(
        document_parts=parts,
        revealed_indices=[0, 2],
        poseidon_root=poseidon_root,
        smt=smt,
        document_id="docC",
        version=1,
        zk_proof={"dummy": True},
    )

    assert isinstance(wrapped, RedactionProofWithLedger)
    assert wrapped.zk_public_inputs.original_root == commitment.poseidon_root
    assert wrapped.zk_public_inputs.revealed_count == 2
    assert wrapped.zk_public_inputs.redacted_commitment.isdigit()
    assert wrapped.verify_smt_anchor(smt.get_root()) is True


def test_commit_to_zk_proof_round_trip_binding_poseidon_root():
    """
    Round-trip: commit → build ZK inputs → verify against committed Poseidon root.
    """
    parts = ["delta", "epsilon", "zeta", "eta"]
    poseidon_root = _poseidon_root_for_parts(parts)
    smt = SparseMerkleTree()

    _, commitment = RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id="docZ",
        version=1,
    )

    revealed_indices = [1, 3]
    wrapped = RedactionProtocol.create_redaction_proof_with_ledger(
        document_parts=parts,
        revealed_indices=revealed_indices,
        poseidon_root=commitment.poseidon_root,
        smt=smt,
        document_id="docZ",
        version=1,
        zk_proof={"pi_a": [], "pi_b": [], "pi_c": []},
    )

    _, poseidon_leaves = RedactionProtocol.build_poseidon_tree(parts)
    revealed_set = set(revealed_indices)
    nullified = [
        poseidon_leaves[i] if i in revealed_set else 0 for i in range(len(poseidon_leaves))
    ]
    expected_redacted = PoseidonMerkleTree(nullified, depth=4).get_root()

    assert wrapped.zk_public_inputs.original_root == commitment.poseidon_root
    assert wrapped.zk_public_inputs.redacted_commitment == expected_redacted

    def zk_verifier(proof, inputs):
        assert proof == wrapped.zk_proof
        assert inputs.original_root == commitment.poseidon_root
        return VerificationResult.VALID

    assert wrapped.verify_all(smt.get_root(), zk_verifier=zk_verifier) is VerificationResult.VALID


def test_full_dual_proof_workflow_with_selective_disclosure():
    """
    End-to-end: ingest → canonicalize → commit dual roots → prove → verify.
    """
    raw_document = {
        "document_id": "doc-e2e-1",
        "parts": [" Public section ", "Classified section", "Public appendix  "],
    }
    canonical_document = canonicalize_document(raw_document)
    canonical_bytes = document_to_bytes(canonical_document)
    parts = canonical_document["parts"]

    poseidon_root = _poseidon_root_for_parts(parts)
    smt = SparseMerkleTree()
    tree, commitment = RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id=canonical_document["document_id"],
        version=1,
    )

    revealed_indices = [0, 2]
    wrapped = RedactionProtocol.create_redaction_proof_with_ledger(
        document_parts=parts,
        revealed_indices=revealed_indices,
        poseidon_root=commitment.poseidon_root,
        smt=smt,
        document_id=canonical_document["document_id"],
        version=1,
        zk_proof={"pi_a": [], "pi_b": [], "pi_c": []},
    )
    correctness_proof = RedactionProtocol.create_redaction_correctness_proof(
        document_parts=parts,
        revealed_indices=revealed_indices,
    )

    assert RedactionProtocol.verify_redaction_correctness_proof(correctness_proof) is True
    assert wrapped.zk_public_inputs.original_root == correctness_proof.original_poseidon_root
    assert wrapped.zk_public_inputs.redacted_commitment == correctness_proof.redacted_poseidon_root

    selective_disclosure_proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)
    revealed_content = [parts[idx] for idx in revealed_indices]
    assert (
        RedactionProtocol.verify_redaction_proof(selective_disclosure_proof, revealed_content)
        is True
    )

    smt_root = smt.get_root()
    assert wrapped.verify_smt_anchor(smt_root) is True
    assert wrapped.verify_all(smt_root, zk_verifier=lambda _p, _i: VerificationResult.VALID) is (
        VerificationResult.VALID
    )

    ledger = Ledger()
    entry = ledger.append(
        record_hash=hash_bytes(canonical_bytes).hex(),
        shard_id="shard-e2e",
        shard_root=smt_root.hex(),
        canonicalization=canonicalization_provenance("application/json", CANONICAL_VERSION),
        poseidon_root=commitment.poseidon_root,
    )
    assert entry.poseidon_root == wrapped.zk_public_inputs.original_root
    assert ledger.verify_chain() is True


def test_append_only_versioning_via_dual_anchor():
    """Different versions produce independent SMT entries."""
    parts = ["x", "y"]
    poseidon_root = _poseidon_root_for_parts(parts)
    smt = SparseMerkleTree()

    RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id="docD",
        version=1,
    )
    RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id="docD",
        version=2,
    )

    key_v1 = poseidon_root_record_key("docD", 1)
    key_v2 = poseidon_root_record_key("docD", 2)

    assert smt.get(key_v1) == poseidon_root_to_bytes(poseidon_root)
    assert smt.get(key_v2) == poseidon_root_to_bytes(poseidon_root)
    assert key_v1 != key_v2


def test_commit_document_dual_rejects_poseidon_root_mismatch():
    """
    Adversary cannot mix-and-match Poseidon and BLAKE3 commitments.

    The Poseidon root derived from a different document must be rejected
    when generating a proof, rather than silently anchored alongside the
    BLAKE3 commitment.
    """
    mismatched_poseidon_root = _poseidon_root_for_parts(["alpha", "beta", "delta"])

    smt = SparseMerkleTree()

    _tree, _commitment = RedactionProtocol.commit_document_dual(
        document_parts=["alpha", "beta", "gamma"],
        poseidon_root=mismatched_poseidon_root,
        smt=smt,
        document_id="docE",
        version=1,
    )

    with pytest.raises(ValueError, match="does not match canonical document sections"):
        RedactionProtocol.create_redaction_proof_with_ledger(
            document_parts=["alpha", "beta", "gamma"],
            revealed_indices=[0],
            poseidon_root=mismatched_poseidon_root,
            smt=smt,
            document_id="docE",
            version=1,
            zk_proof={},
        )


# ---------------------------------------------------------------------------
# Dual-root commitment integrity: tamper-detection tests
# ---------------------------------------------------------------------------


def test_commit_document_dual_blake3_root_matches_returned_tree():
    """
    Structural invariant: commitment.blake3_root must equal tree.get_root().hex().

    An adversary who replaces commitment.blake3_root with a value from a
    different document is immediately detectable because the returned tree's
    root still reflects the authentic document.
    """
    parts = ["authentic section one", "authentic section two"]
    poseidon_root = _poseidon_root_for_parts(parts)
    smt = SparseMerkleTree()

    tree, commitment = RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id="docTamper1",
        version=1,
    )

    assert commitment.blake3_root == tree.get_root().hex()


def test_commit_document_dual_poseidon_root_matches_smt_value():
    """
    Structural invariant: commitment.poseidon_root must equal the value stored
    in the SMT under the document's key.

    An adversary who replaces commitment.poseidon_root with a forged value
    is detectable because the SMT still stores the authentic Poseidon root.
    """
    parts = ["authentic section one", "authentic section two"]
    poseidon_root = _poseidon_root_for_parts(parts)
    smt = SparseMerkleTree()

    _, commitment = RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id="docTamper2",
        version=1,
    )

    key = poseidon_root_record_key("docTamper2", 1)
    stored_bytes = smt.get(key)
    assert stored_bytes is not None
    assert poseidon_root_from_bytes(stored_bytes) == commitment.poseidon_root


def test_tampered_blake3_root_detected_in_redaction_proof_verification():
    """
    Cross-document blake3_root substitution is detected during proof verification.

    If an adversary replaces the original_root in a RedactionProof with the
    blake3_root from a different document, the Merkle inclusion proofs (which
    were generated from the authentic tree) contain root_hash values that differ
    from the tampered root, causing verify_redaction_proof to return False.
    """
    parts_authentic = ["sensitive section A", "public section B"]
    parts_other = ["completely different content", "unrelated second part"]

    tree_authentic, root_authentic = RedactionProtocol.commit_document(parts_authentic)
    _, root_other = RedactionProtocol.commit_document(parts_other)

    # Sanity: the two documents produce different roots.
    assert root_authentic != root_other

    # Build a legitimate proof for the authentic document.
    proof = RedactionProtocol.create_redaction_proof(tree_authentic, [0])

    # Tamper: substitute the other document's blake3 root as the claimed root.
    tampered_proof = RedactionProof(
        original_root=root_other,
        revealed_indices=proof.revealed_indices,
        revealed_hashes=proof.revealed_hashes,
        merkle_proofs=proof.merkle_proofs,
    )

    # The Merkle inclusion proofs embed root_authentic as root_hash, but
    # tampered_proof.original_root == root_other → mismatch → fails.
    assert RedactionProtocol.verify_redaction_proof(tampered_proof, [parts_authentic[0]]) is False


def test_cross_document_poseidon_root_substitution_fails_smt_anchor():
    """
    Substituting a Poseidon root from a different document into the ZK public
    inputs is detected by verify_smt_anchor.

    The SMT stores the authentic document's Poseidon root.  If the ZK public
    inputs claim a different root (from another document), the value_hash in
    the SMT proof won't match the expected serialization of the tampered root.
    """
    parts_authentic = ["real section one", "real section two"]
    parts_other = ["adversarial section one", "adversarial section two"]

    poseidon_root_authentic = _poseidon_root_for_parts(parts_authentic)
    poseidon_root_other = _poseidon_root_for_parts(parts_other)

    # Sanity: the two documents yield different Poseidon roots.
    assert poseidon_root_authentic != poseidon_root_other

    smt = SparseMerkleTree()
    RedactionProtocol.commit_document_dual(
        document_parts=parts_authentic,
        poseidon_root=poseidon_root_authentic,
        smt=smt,
        document_id="docTamper3",
        version=1,
    )
    smt_root = smt.get_root()

    # Build an SMT existence proof for the authentic document's key.
    key = poseidon_root_record_key("docTamper3", 1)
    smt_proof = smt.prove_existence(key)

    # Adversary wraps the authentic SMT proof but substitutes the other
    # document's Poseidon root as the ZK public input.
    tampered_wrapped = RedactionProofWithLedger(
        smt_proof=smt_proof,
        zk_proof={},
        zk_public_inputs=ZKPublicInputs(
            original_root=poseidon_root_other,  # tampered: different document
            redacted_commitment="0",
            revealed_count=0,
        ),
    )

    # The SMT proof's value_hash encodes poseidon_root_authentic, but
    # verify_smt_anchor expects poseidon_root_to_bytes(poseidon_root_other) → fails.
    assert tampered_wrapped.verify_smt_anchor(smt_root) is False


def test_stale_smt_proof_invalidated_after_new_entry_appended():
    """
    Append-only integrity: an SMT existence proof captured at version N is
    invalidated once version N+1 is committed, because appending a new entry
    changes the SMT root hash.

    This prevents an adversary from replaying an old proof against a newer
    ledger state.
    """
    parts = ["versioned section one"]
    poseidon_root = _poseidon_root_for_parts(parts)
    smt = SparseMerkleTree()

    # Commit version 1 and capture the existence proof immediately.
    RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id="docTamper4",
        version=1,
    )
    key_v1 = poseidon_root_record_key("docTamper4", 1)
    smt_proof_v1 = smt.prove_existence(key_v1)
    smt_root_after_v1 = smt.get_root()

    # The v1 proof verifies correctly against the v1 SMT root.
    wrapped_v1 = RedactionProofWithLedger(
        smt_proof=smt_proof_v1,
        zk_proof={},
        zk_public_inputs=ZKPublicInputs(
            original_root=poseidon_root,
            redacted_commitment="0",
            revealed_count=0,
        ),
    )
    assert wrapped_v1.verify_smt_anchor(smt_root_after_v1) is True

    # Commit version 2, which mutates the SMT root.
    RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id="docTamper4",
        version=2,
    )
    smt_root_after_v2 = smt.get_root()

    # The two SMT roots must be different (version 2 added a new leaf).
    assert smt_root_after_v1 != smt_root_after_v2

    # The stale v1 proof must NOT verify against the newer SMT root.
    assert wrapped_v1.verify_smt_anchor(smt_root_after_v2) is False


def test_commit_document_dual_is_deterministic():
    """
    The DualHashCommitment is fully deterministic: identical inputs always
    produce the same blake3_root and poseidon_root regardless of the SMT
    instance used.
    """
    parts = ["alpha", "beta", "gamma"]
    poseidon_root = _poseidon_root_for_parts(parts)

    smt1 = SparseMerkleTree()
    _, commitment1 = RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt1,
        document_id="docTamper5",
        version=1,
    )

    smt2 = SparseMerkleTree()
    _, commitment2 = RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt2,
        document_id="docTamper5",
        version=1,
    )

    assert commitment1.blake3_root == commitment2.blake3_root
    assert commitment1.poseidon_root == commitment2.poseidon_root


def test_commit_document_dual_distinct_for_different_documents():
    """
    Two distinct documents must produce different blake3_root AND poseidon_root
    values.  This ensures that commitments cannot be confused across documents.
    """
    parts_a = ["unique content A part one", "unique content A part two"]
    parts_b = ["unique content B part one", "unique content B part two"]

    poseidon_root_a = _poseidon_root_for_parts(parts_a)
    poseidon_root_b = _poseidon_root_for_parts(parts_b)

    smt = SparseMerkleTree()
    _, commitment_a = RedactionProtocol.commit_document_dual(
        document_parts=parts_a,
        poseidon_root=poseidon_root_a,
        smt=smt,
        document_id="docTamper6",
        version=1,
    )
    _, commitment_b = RedactionProtocol.commit_document_dual(
        document_parts=parts_b,
        poseidon_root=poseidon_root_b,
        smt=smt,
        document_id="docTamper6",
        version=2,
    )

    assert commitment_a.blake3_root != commitment_b.blake3_root
    assert commitment_a.poseidon_root != commitment_b.poseidon_root


def test_forged_commit_document_dual_cannot_satisfy_both_verification_paths():
    """
    An adversary who forges a DualHashCommitment by mixing roots from two
    different documents cannot satisfy both verification paths simultaneously.

    - Using document A's blake3_root with document B's poseidon_root:
      The BLAKE3 Merkle proofs for document A carry root_hash == blake3_root_A,
      which won't match if the adversary claims blake3_root_B instead.  And the
      SMT anchor check will fail because the SMT stores poseidon_root_A under
      document A's key, not poseidon_root_B.

    This test exercises the first path (BLAKE3 Merkle proof mismatch).
    The SMT anchor path is covered by
    test_cross_document_poseidon_root_substitution_fails_smt_anchor.
    """
    parts_a = ["original government report section 1", "original government report section 2"]
    parts_b = ["replacement document section 1", "replacement document section 2"]

    tree_a, blake3_root_a = RedactionProtocol.commit_document(parts_a)
    _, blake3_root_b = RedactionProtocol.commit_document(parts_b)

    assert blake3_root_a != blake3_root_b

    # Build a proof for doc A; the Merkle proofs encode blake3_root_a as root_hash.
    proof_a = RedactionProtocol.create_redaction_proof(tree_a, [0])

    # Forged commitment: replace the claimed root with doc B's blake3 root.
    forged_proof = RedactionProof(
        original_root=blake3_root_b,
        revealed_indices=proof_a.revealed_indices,
        revealed_hashes=proof_a.revealed_hashes,
        merkle_proofs=proof_a.merkle_proofs,
    )

    # Verification must fail: merkle_proofs[0].root_hash.hex() == blake3_root_a
    # but forged_proof.original_root == blake3_root_b.
    assert RedactionProtocol.verify_redaction_proof(forged_proof, [parts_a[0]]) is False
