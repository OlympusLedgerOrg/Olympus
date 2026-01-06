"""
CLI tests for canonicalize_cli.py

These tests validate the command-line interface for document canonicalization.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

# Path to the CLI script
CLI_PATH = Path(__file__).parent.parent / "tools" / "canonicalize_cli.py"


@pytest.fixture
def sample_document(tmp_path):
    """Create a sample document for testing."""
    doc = {
        "title": "Test  Document",
        "version": 1,
        "metadata": {
            "author": "John   Doe"
        }
    }

    doc_path = tmp_path / "sample.json"
    with open(doc_path, 'w') as f:
        json.dump(doc, f)

    return doc_path


@pytest.fixture
def invalid_json(tmp_path):
    """Create an invalid JSON file for testing."""
    invalid_path = tmp_path / "invalid.json"
    with open(invalid_path, 'w') as f:
        f.write("{ this is not valid JSON }")

    return invalid_path


def test_cli_basic_canonicalization(sample_document):
    """Test basic document canonicalization via CLI."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(sample_document)],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    # Output should be valid JSON
    output = json.loads(result.stdout)

    # Should have normalized whitespace
    assert output["title"] == "Test Document"
    assert output["metadata"]["author"] == "John Doe"

    # Keys should be sorted
    assert list(output.keys()) == ["metadata", "title", "version"]


def test_cli_hash_flag(sample_document):
    """Test --hash flag outputs document hash."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(sample_document), "--hash"],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    # Output should be a hex hash
    output = result.stdout.strip()
    assert len(output) == 64  # SHA-256 hex is 64 characters
    # Should be valid hex
    int(output, 16)


def test_cli_output_flag(sample_document, tmp_path):
    """Test --output flag writes to file."""
    output_path = tmp_path / "output.json"

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(sample_document), "--output", str(output_path)],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0
    assert output_path.exists()

    # Verify output file contains canonical document
    with open(output_path) as f:
        output = json.load(f)

    assert output["title"] == "Test Document"


def test_cli_format_json(sample_document):
    """Test --format json outputs formatted JSON."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(sample_document), "--format", "json"],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    # Should be valid JSON
    output = json.loads(result.stdout)
    assert "title" in output


def test_cli_format_bytes(sample_document):
    """Test --format bytes outputs canonical bytes."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(sample_document), "--format", "bytes"],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    # Should be compact JSON (no newlines or spaces)
    output = result.stdout.strip()
    assert output.startswith('{"metadata"')
    assert "  " not in output  # No double spaces


def test_cli_format_hex(sample_document):
    """Test --format hex outputs hex-encoded bytes."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(sample_document), "--format", "hex"],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    # Should be valid hex
    output = result.stdout.strip()
    bytes.fromhex(output)  # Should not raise


def test_cli_hash_with_output_file(sample_document, tmp_path):
    """Test --hash with --output writes hash to file."""
    output_path = tmp_path / "hash.txt"

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(sample_document), "--hash", "--output", str(output_path)],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0
    assert output_path.exists()

    # Verify output file contains hash
    with open(output_path) as f:
        output = f.read().strip()

    assert len(output) == 64  # SHA-256 hex


def test_cli_file_not_found():
    """Test error handling for non-existent file."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "nonexistent.json"],
        capture_output=True,
        text=True
    )

    assert result.returncode == 1
    assert "Error: File not found" in result.stderr or "not found" in result.stderr.lower()


def test_cli_invalid_json(invalid_json):
    """Test error handling for invalid JSON."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(invalid_json)],
        capture_output=True,
        text=True
    )

    assert result.returncode == 1
    assert "Error: Invalid JSON" in result.stderr or "invalid" in result.stderr.lower()


def test_cli_deterministic_output(sample_document):
    """Test that CLI produces deterministic output."""
    result1 = subprocess.run(
        [sys.executable, str(CLI_PATH), str(sample_document)],
        capture_output=True,
        text=True
    )

    result2 = subprocess.run(
        [sys.executable, str(CLI_PATH), str(sample_document)],
        capture_output=True,
        text=True
    )

    assert result1.stdout == result2.stdout


def test_cli_deterministic_hash(sample_document):
    """Test that CLI produces deterministic hash."""
    result1 = subprocess.run(
        [sys.executable, str(CLI_PATH), str(sample_document), "--hash"],
        capture_output=True,
        text=True
    )

    result2 = subprocess.run(
        [sys.executable, str(CLI_PATH), str(sample_document), "--hash"],
        capture_output=True,
        text=True
    )

    assert result1.stdout == result2.stdout


def test_cli_complex_document(tmp_path):
    """Test CLI with a complex real-world document."""
    doc = {
        "title": "Complex   Document",
        "metadata": {
            "z_author": "Jane",
            "a_created": "2024-01-01"
        },
        "sections": [
            {"heading": "Section  1", "content": "Text   here"},
            {"heading": "Section  2", "content": "More   text"}
        ]
    }

    doc_path = tmp_path / "complex.json"
    with open(doc_path, 'w') as f:
        json.dump(doc, f)

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(doc_path)],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0

    output = json.loads(result.stdout)

    # Check whitespace normalization
    assert output["title"] == "Complex Document"
    assert output["sections"][0]["heading"] == "Section 1"

    # Check key sorting
    assert list(output["metadata"].keys()) == ["a_created", "z_author"]


def test_cli_empty_document(tmp_path):
    """Test CLI with empty document."""
    doc_path = tmp_path / "empty.json"
    with open(doc_path, 'w') as f:
        json.dump({}, f)

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(doc_path)],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "{}"
