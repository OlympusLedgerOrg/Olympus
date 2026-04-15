"""
Tests for RT-M4: expected_root parameter in proof verification functions.

verify_proof(), verify_nonexistence_proof(), and verify_unified_proof() now
accept an optional expected_root parameter for root authentication. When
provided, the proof's root_hash is checked against expected_root before
path reconstruction.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from protocol.hashes import hash_bytes, record_key
from protocol.ssmf import (
    SparseMerkleTree,
    verify_nonexistence_proof,
    verify_proof,
    verify_unified_proof,
)


@pytest.fixture
def populated_tree():
    """Create a tree with a single entry and return tree, key, value_hash."""
    tree = SparseMerkleTree()
    key = record_key("document", "doc1", 1)
    value_hash = hash_bytes(b"test value")
    tree.update(key, value_hash)
    return tree, key, value_hash


class TestVerifyProofExpectedRoot:
    """Test expected_root parameter on verify_proof (existence)."""

    def test_correct_expected_root_passes(self, populated_tree):
        """Proof passes when expected_root matches the tree root."""
        tree, key, _value_hash = populated_tree
        proof = tree.prove_existence(key)
        assert verify_proof(proof, expected_root=tree.get_root()) is True

    def test_wrong_expected_root_fails(self, populated_tree):
        """Proof fails immediately when expected_root doesn't match."""
        tree, key, _value_hash = populated_tree
        proof = tree.prove_existence(key)
        wrong_root = b"\x00" * 32
        assert verify_proof(proof, expected_root=wrong_root) is False

    def test_none_expected_root_backward_compat(self, populated_tree):
        """None expected_root preserves original behavior."""
        tree, key, _value_hash = populated_tree
        proof = tree.prove_existence(key)
        assert verify_proof(proof, expected_root=None) is True
        # Also test without kwarg
        assert verify_proof(proof) is True


class TestVerifyNonexistenceProofExpectedRoot:
    """Test expected_root parameter on verify_nonexistence_proof."""

    def test_correct_expected_root_passes(self, populated_tree):
        """Non-existence proof passes with correct expected_root."""
        tree, _key, _value_hash = populated_tree
        missing_key = record_key("document", "missing-doc", 1)
        proof = tree.prove_nonexistence(missing_key)
        assert verify_nonexistence_proof(proof, expected_root=tree.get_root()) is True

    def test_wrong_expected_root_fails(self, populated_tree):
        """Non-existence proof fails with wrong expected_root."""
        tree, _key, _value_hash = populated_tree
        missing_key = record_key("document", "missing-doc", 1)
        proof = tree.prove_nonexistence(missing_key)
        wrong_root = b"\xff" * 32
        assert verify_nonexistence_proof(proof, expected_root=wrong_root) is False

    def test_none_expected_root_backward_compat(self, populated_tree):
        """None expected_root preserves original behavior."""
        tree, _key, _value_hash = populated_tree
        missing_key = record_key("document", "missing-doc", 1)
        proof = tree.prove_nonexistence(missing_key)
        assert verify_nonexistence_proof(proof, expected_root=None) is True
        assert verify_nonexistence_proof(proof) is True


class TestVerifyUnifiedProofExpectedRoot:
    """Test expected_root parameter on verify_unified_proof."""

    def test_passes_expected_root_to_existence(self, populated_tree):
        """verify_unified_proof passes expected_root to verify_proof."""
        tree, key, _value_hash = populated_tree
        proof = tree.prove_existence(key)
        root = tree.get_root()
        assert verify_unified_proof(proof, expected_root=root) is True
        assert verify_unified_proof(proof, expected_root=b"\x00" * 32) is False

    def test_passes_expected_root_to_nonexistence(self, populated_tree):
        """verify_unified_proof passes expected_root to verify_nonexistence_proof."""
        tree, _key, _value_hash = populated_tree
        missing_key = record_key("document", "missing-doc", 1)
        proof = tree.prove_nonexistence(missing_key)
        root = tree.get_root()
        assert verify_unified_proof(proof, expected_root=root) is True
        assert verify_unified_proof(proof, expected_root=b"\xff" * 32) is False

    def test_none_expected_root_backward_compat(self, populated_tree):
        """verify_unified_proof with None expected_root is backward compatible."""
        tree, key, _value_hash = populated_tree
        proof = tree.prove_existence(key)
        assert verify_unified_proof(proof, expected_root=None) is True
        assert verify_unified_proof(proof) is True


class TestVerifyCliSmtCommand:
    """Test that verify_cli.py smt subcommand uses expected_root from headers."""

    def test_smt_subcommand_with_matching_root(self, populated_tree, tmp_path):
        """verify_cli.py smt command extracts root from signed_shard_header."""
        tree, key, value_hash = populated_tree
        proof = tree.prove_existence(key)
        root_hex = tree.get_root().hex()

        bundle = {
            "signed_shard_header": {"shard_root": root_hex},
            "proof": proof.to_dict(),
        }

        proof_file = tmp_path / "bundle.json"
        proof_file.write_text(json.dumps(bundle))
        result = subprocess.run(
            [sys.executable, "tools/verify_cli.py", "smt", str(proof_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "VALID" in result.stdout

    def test_smt_subcommand_with_wrong_root(self, populated_tree, tmp_path):
        """verify_cli.py smt command fails when header root doesn't match proof."""
        tree, key, value_hash = populated_tree
        proof = tree.prove_existence(key)

        bundle = {
            "signed_shard_header": {"shard_root": "aa" * 32},
            "proof": proof.to_dict(),
        }

        proof_file = tmp_path / "bundle.json"
        proof_file.write_text(json.dumps(bundle))
        result = subprocess.run(
            [sys.executable, "tools/verify_cli.py", "smt", str(proof_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "INVALID" in result.stderr

    def test_smt_subcommand_with_explicit_expected_root(self, populated_tree, tmp_path):
        """verify_cli.py smt --expected-root overrides bundle header."""
        tree, key, value_hash = populated_tree
        proof = tree.prove_existence(key)
        root_hex = tree.get_root().hex()

        proof_data = proof.to_dict()

        proof_file = tmp_path / "proof.json"
        proof_file.write_text(json.dumps(proof_data))
        result = subprocess.run(
            [
                sys.executable,
                "tools/verify_cli.py",
                "smt",
                str(proof_file),
                "--expected-root",
                root_hex,
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "VALID" in result.stdout


class TestVerifierCliSmtProofCommand:
    """Test that verifiers/cli/verify.py smt-proof subcommand works."""

    def test_smt_proof_command_exists(self):
        """The smt-proof subcommand is registered in the verifier CLI."""
        result = subprocess.run(
            [sys.executable, "verifiers/cli/verify.py", "smt-proof", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "expected-root" in result.stdout
