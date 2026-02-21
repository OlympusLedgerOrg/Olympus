"""
CLI tests for verify_cli.py

These tests validate the command-line interface for proof verification.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from protocol.hashes import hash_bytes
from protocol.ledger import Ledger
from protocol.merkle import MerkleTree
from protocol.redaction import RedactionProtocol


# Path to the CLI script
CLI_PATH = Path(__file__).parent.parent / "tools" / "verify_cli.py"


@pytest.fixture
def merkle_proof_data(tmp_path):
    """Create a valid Merkle proof for testing."""
    # Create a simple Merkle tree
    leaves = [
        hash_bytes(b"document1"),
        hash_bytes(b"document2"),
        hash_bytes(b"document3"),
    ]

    tree = MerkleTree(leaves)
    proof = tree.generate_proof(1)  # Proof for second leaf

    # Convert proof to JSON format expected by CLI
    proof_data = {
        "leaf_hash": proof.leaf_hash.hex(),
        "leaf_index": proof.leaf_index,
        "siblings": [[h.hex(), is_right] for h, is_right in proof.siblings],
        "root_hash": proof.root_hash.hex(),
    }

    proof_file = tmp_path / "merkle_proof.json"
    with open(proof_file, "w") as f:
        json.dump(proof_data, f)

    return proof_file


@pytest.fixture
def invalid_merkle_proof_data(tmp_path):
    """Create an invalid Merkle proof for testing."""
    # Create a proof with tampered data
    proof_data = {
        "leaf_hash": "0" * 64,  # Invalid hash
        "leaf_index": 0,
        "siblings": [["1" * 64, False]],
        "root_hash": "2" * 64,
    }

    proof_file = tmp_path / "invalid_merkle_proof.json"
    with open(proof_file, "w") as f:
        json.dump(proof_data, f)

    return proof_file


@pytest.fixture
def ledger_data(tmp_path):
    """Create a valid ledger for testing."""
    ledger = Ledger()

    # Add several entries
    ledger.append(doc_id="doc1", record_hash="hash1", shard_id="shard1", shard_root="root1")

    ledger.append(doc_id="doc2", record_hash="hash2", shard_id="shard1", shard_root="root2")

    ledger.append(doc_id="doc3", record_hash="hash3", shard_id="shard1", shard_root="root3")

    # Export to JSON format
    ledger_data = {"entries": [entry.to_dict() for entry in ledger.entries]}

    ledger_file = tmp_path / "ledger.json"
    with open(ledger_file, "w") as f:
        json.dump(ledger_data, f)

    return ledger_file


@pytest.fixture
def tampered_ledger_data(tmp_path):
    """Create a tampered ledger for testing."""
    ledger = Ledger()

    ledger.append(doc_id="doc1", record_hash="hash1", shard_id="shard1", shard_root="root1")

    ledger.append(doc_id="doc2", record_hash="hash2", shard_id="shard1", shard_root="root2")

    # Tamper with the second entry
    ledger.entries[1].record_hash = "tampered_hash"

    ledger_data = {"entries": [entry.to_dict() for entry in ledger.entries]}

    ledger_file = tmp_path / "tampered_ledger.json"
    with open(ledger_file, "w") as f:
        json.dump(ledger_data, f)

    return ledger_file


@pytest.fixture
def redaction_proof_data(tmp_path):
    """Create a valid redaction proof for testing."""
    # Create document parts
    document_parts = ["Public information", "Sensitive data", "More public info"]

    # Create commitment
    tree, root_hash = RedactionProtocol.commit_document(document_parts)

    # Create proof revealing only parts 0 and 2
    revealed_indices = [0, 2]
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    # Convert to JSON format
    proof_data = {
        "original_root": proof.original_root,
        "revealed_indices": proof.revealed_indices,
        "revealed_hashes": proof.revealed_hashes,
        "merkle_proofs": [
            {
                "leaf_hash": mp.leaf_hash.hex(),
                "leaf_index": mp.leaf_index,
                "siblings": [[h.hex(), is_right] for h, is_right in mp.siblings],
                "root_hash": mp.root_hash.hex(),
            }
            for mp in proof.merkle_proofs
        ],
    }

    proof_file = tmp_path / "redaction_proof.json"
    with open(proof_file, "w") as f:
        json.dump(proof_data, f)

    # Create content file
    content_data = {"revealed_content": [document_parts[i] for i in revealed_indices]}

    content_file = tmp_path / "revealed_content.json"
    with open(content_file, "w") as f:
        json.dump(content_data, f)

    return proof_file, content_file


def test_cli_verify_merkle_proof_valid(merkle_proof_data):
    """Test verification of valid Merkle proof."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "merkle", str(merkle_proof_data)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "VALID" in result.stdout or "✓" in result.stdout


def test_cli_verify_merkle_proof_invalid(invalid_merkle_proof_data):
    """Test verification of invalid Merkle proof."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "merkle", str(invalid_merkle_proof_data)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "INVALID" in result.stderr or "✗" in result.stderr


def test_cli_verify_ledger_valid(ledger_data):
    """Test verification of valid ledger chain."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "ledger", str(ledger_data)], capture_output=True, text=True
    )

    assert result.returncode == 0
    assert "VALID" in result.stdout or "✓" in result.stdout
    assert "3 entries" in result.stdout  # Should report number of entries


def test_cli_verify_ledger_tampered(tampered_ledger_data):
    """Test verification of tampered ledger chain."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "ledger", str(tampered_ledger_data)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "INVALID" in result.stderr or "✗" in result.stderr


def test_cli_verify_redaction_proof_valid(redaction_proof_data):
    """Test verification of valid redaction proof."""
    proof_file, content_file = redaction_proof_data

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "redaction", str(proof_file), str(content_file)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "VALID" in result.stdout or "✓" in result.stdout
    assert "2 parts revealed" in result.stdout or "revealed" in result.stdout


def test_cli_no_command():
    """Test that CLI shows help when no command is provided."""
    result = subprocess.run([sys.executable, str(CLI_PATH)], capture_output=True, text=True)

    assert result.returncode == 1
    assert "usage:" in result.stderr.lower() or "help" in result.stdout.lower()


def test_cli_merkle_missing_file():
    """Test error handling for missing Merkle proof file."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "merkle", "nonexistent.json"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "Error" in result.stderr


def test_cli_ledger_missing_file():
    """Test error handling for missing ledger file."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "ledger", "nonexistent.json"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "Error" in result.stderr


def test_cli_redaction_missing_proof_file(tmp_path):
    """Test error handling for missing redaction proof file."""
    content_file = tmp_path / "content.json"
    with open(content_file, "w") as f:
        json.dump({"revealed_content": []}, f)

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "redaction", "nonexistent.json", str(content_file)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "Error" in result.stderr


def test_cli_redaction_missing_content_file(tmp_path):
    """Test error handling for missing content file."""
    proof_file = tmp_path / "proof.json"
    with open(proof_file, "w") as f:
        json.dump(
            {
                "original_root": "test",
                "revealed_indices": [],
                "revealed_hashes": [],
                "merkle_proofs": [],
            },
            f,
        )

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "redaction", str(proof_file), "nonexistent.json"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "Error" in result.stderr


def test_cli_ledger_single_entry(tmp_path):
    """Test verification of ledger with single entry."""
    ledger = Ledger()
    ledger.append(doc_id="doc1", record_hash="hash1", shard_id="shard1", shard_root="root1")

    ledger_data = {"entries": [entry.to_dict() for entry in ledger.entries]}

    ledger_file = tmp_path / "single_entry.json"
    with open(ledger_file, "w") as f:
        json.dump(ledger_data, f)

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "ledger", str(ledger_file)], capture_output=True, text=True
    )

    assert result.returncode == 0
    assert "VALID" in result.stdout or "✓" in result.stdout
    assert "1 entry" in result.stdout or "1 entries" in result.stdout


def test_cli_ledger_empty(tmp_path):
    """Test verification of empty ledger."""
    ledger_data = {"entries": []}

    ledger_file = tmp_path / "empty_ledger.json"
    with open(ledger_file, "w") as f:
        json.dump(ledger_data, f)

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "ledger", str(ledger_file)], capture_output=True, text=True
    )

    assert result.returncode == 0
    assert "VALID" in result.stdout or "✓" in result.stdout
