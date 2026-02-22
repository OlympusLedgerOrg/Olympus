"""
Tests for binary blob handling in Olympus.

This module tests the handling of binary data (blobs) across the system,
ensuring proper encoding, hashing, and storage of arbitrary binary content.

Binary blob handling is critical for:
- Document content that may be binary (PDFs, images, etc.)
- Cryptographic values (hashes, keys, signatures)
- Database BYTEA column compatibility
"""

from protocol.hashes import hash_bytes


def test_blob_hash_determinism() -> None:
    """Test that hashing the same blob produces the same result."""
    blob = b"\x00\x01\x02\x03\xff\xfe\xfd"
    hash1 = hash_bytes(blob)
    hash2 = hash_bytes(blob)
    assert hash1 == hash2


def test_blob_hash_length() -> None:
    """Test that blob hashes are 32 bytes (BLAKE3 output)."""
    blob = b"arbitrary binary content"
    result = hash_bytes(blob)
    assert len(result) == 32


def test_empty_blob_hash() -> None:
    """Test that empty blobs can be hashed."""
    blob = b""
    result = hash_bytes(blob)
    assert len(result) == 32


def test_large_blob_hash() -> None:
    """Test that large blobs can be hashed efficiently."""
    blob = b"\x00" * 1_000_000  # 1MB of zeros
    result = hash_bytes(blob)
    assert len(result) == 32


def test_blob_hex_encoding() -> None:
    """Test that blob hashes can be hex-encoded for storage."""
    blob = b"test data"
    result = hash_bytes(blob)
    hex_encoded = result.hex()
    assert len(hex_encoded) == 64  # 32 bytes = 64 hex characters
    # Verify round-trip
    assert bytes.fromhex(hex_encoded) == result


def test_different_blobs_different_hashes() -> None:
    """Test that different blobs produce different hashes."""
    blob1 = b"first blob"
    blob2 = b"second blob"
    hash1 = hash_bytes(blob1)
    hash2 = hash_bytes(blob2)
    assert hash1 != hash2


def test_blob_with_null_bytes() -> None:
    """Test that blobs containing null bytes are handled correctly."""
    blob = b"data\x00with\x00nulls"
    result = hash_bytes(blob)
    assert len(result) == 32


def test_blob_with_high_bytes() -> None:
    """Test that blobs with high-value bytes (>127) are handled correctly."""
    blob = bytes(range(256))  # All possible byte values
    result = hash_bytes(blob)
    assert len(result) == 32
