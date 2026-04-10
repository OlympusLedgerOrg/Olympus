"""Tests for the cryptographic utilities."""

from __future__ import annotations

import tempfile
from pathlib import Path

from ingest_parser.crypto import (
    compute_blake3,
    compute_blake3_file,
    compute_sha256,
    compute_sha256_file,
    verify_hash,
)


class TestBlake3:
    """Tests for BLAKE3 hashing."""

    def test_compute_blake3(self) -> None:
        """Test BLAKE3 hash computation."""
        data = b"Hello, world!"
        hash_value = compute_blake3(data)

        assert hash_value.startswith("blake3_")
        assert len(hash_value) == 7 + 64  # "blake3_" + 64 hex chars

    def test_compute_blake3_deterministic(self) -> None:
        """Test that BLAKE3 is deterministic."""
        data = b"Test data for hashing"

        hash1 = compute_blake3(data)
        hash2 = compute_blake3(data)

        assert hash1 == hash2

    def test_compute_blake3_different_inputs(self) -> None:
        """Test that different inputs produce different hashes."""
        hash1 = compute_blake3(b"input1")
        hash2 = compute_blake3(b"input2")

        assert hash1 != hash2

    def test_compute_blake3_file(self) -> None:
        """Test BLAKE3 hash of a file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"File content for hashing")
            temp_path = Path(f.name)

        try:
            hash_value = compute_blake3_file(temp_path)
            assert hash_value.startswith("blake3_")
            assert len(hash_value) == 7 + 64
        finally:
            temp_path.unlink()

    def test_compute_blake3_file_matches_bytes(self) -> None:
        """Test that file hash matches direct bytes hash."""
        content = b"Test content"

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            file_hash = compute_blake3_file(temp_path)
            bytes_hash = compute_blake3(content)
            assert file_hash == bytes_hash
        finally:
            temp_path.unlink()


class TestSha256:
    """Tests for SHA256 hashing."""

    def test_compute_sha256(self) -> None:
        """Test SHA256 hash computation."""
        data = b"Hello, world!"
        hash_value = compute_sha256(data)

        assert hash_value.startswith("sha256_")
        assert len(hash_value) == 7 + 64  # "sha256_" + 64 hex chars

    def test_compute_sha256_deterministic(self) -> None:
        """Test that SHA256 is deterministic."""
        data = b"Test data for hashing"

        hash1 = compute_sha256(data)
        hash2 = compute_sha256(data)

        assert hash1 == hash2

    def test_compute_sha256_file(self) -> None:
        """Test SHA256 hash of a file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"File content for SHA256")
            temp_path = Path(f.name)

        try:
            hash_value = compute_sha256_file(temp_path)
            assert hash_value.startswith("sha256_")
        finally:
            temp_path.unlink()


class TestVerifyHash:
    """Tests for hash verification."""

    def test_verify_matching_hashes(self) -> None:
        """Test verification of matching hashes."""
        hash_value = "blake3_" + "a" * 64
        assert verify_hash(hash_value, hash_value) is True

    def test_verify_different_hashes(self) -> None:
        """Test verification of different hashes."""
        hash1 = "blake3_" + "a" * 64
        hash2 = "blake3_" + "b" * 64
        assert verify_hash(hash1, hash2) is False

    def test_verify_constant_time(self) -> None:
        """Test that verification uses constant-time comparison."""
        # This is hard to test directly, but we can at least verify it works
        expected = compute_blake3(b"test")
        actual = compute_blake3(b"test")
        assert verify_hash(expected, actual) is True
