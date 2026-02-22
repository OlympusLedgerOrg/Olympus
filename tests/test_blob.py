"""
Tests for blob storage layer.

These tests validate the BlobStore implementation using mocked S3 client.
For integration tests with real MinIO, use docker-compose and set
S3_ENDPOINT_URL, AWS_ACCESS_KEY_ID, and AWS_SECRET_ACCESS_KEY.
"""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from protocol.hashes import hash_bytes
from storage.blob import BlobStore


@pytest.fixture
def mock_s3():
    """Create a mock S3 client."""
    with patch("storage.blob.boto3.client") as mock_client:
        mock_s3 = MagicMock()
        mock_client.return_value = mock_s3
        yield mock_s3


@pytest.fixture
def blob_store(mock_s3):
    """Create a BlobStore instance with mocked S3."""
    return BlobStore()


def make_404_error():
    """Create a mock 404 ClientError for testing."""
    error_response = {"Error": {"Code": "404", "Message": "Not Found"}}
    return ClientError(error_response, "HeadObject")


def make_no_such_key_error():
    """Create a mock NoSuchKey ClientError for testing."""
    error_response = {"Error": {"Code": "NoSuchKey", "Message": "The specified key does not exist."}}
    return ClientError(error_response, "GetObject")


def test_blob_store_init_default_bucket():
    """Test BlobStore initializes with default bucket."""
    with patch("storage.blob.boto3.client"):
        store = BlobStore()
        assert store.bucket == "olympus-artifacts"


def test_blob_store_init_custom_bucket(monkeypatch):
    """Test BlobStore initializes with custom bucket from env."""
    monkeypatch.setenv("S3_BUCKET_NAME", "custom-bucket")
    with patch("storage.blob.boto3.client"):
        store = BlobStore()
        assert store.bucket == "custom-bucket"


def test_put_artifact_new_object(blob_store, mock_s3):
    """Test uploading a new artifact."""
    test_data = b"test content"
    raw_hash = hash_bytes(test_data).hex()
    mime_type = "text/plain"

    # Simulate object not existing
    mock_s3.head_object.side_effect = make_404_error()

    result = blob_store.put_artifact(raw_hash, test_data, mime_type)

    assert result == raw_hash
    mock_s3.put_object.assert_called_once_with(
        Bucket="olympus-artifacts",
        Key=raw_hash,
        Body=test_data,
        ContentType=mime_type,
    )


def test_put_artifact_existing_object(blob_store, mock_s3):
    """Test uploading an artifact that already exists (idempotent)."""
    test_data = b"test content"
    raw_hash = hash_bytes(test_data).hex()
    mime_type = "text/plain"

    # Simulate object already existing
    mock_s3.head_object.return_value = {}

    result = blob_store.put_artifact(raw_hash, test_data, mime_type)

    assert result == raw_hash
    # Should NOT call put_object since object exists
    mock_s3.put_object.assert_not_called()


def test_put_artifact_invalid_hash_length(blob_store):
    """Test that invalid hash length raises ValueError."""
    with pytest.raises(ValueError, match="must be 64 characters"):
        blob_store.put_artifact("tooshort", b"data", "text/plain")


def test_put_artifact_invalid_hex(blob_store):
    """Test that invalid hex string raises ValueError."""
    invalid_hex = "g" * 64  # 'g' is not a valid hex character
    with pytest.raises(ValueError, match="valid hex string"):
        blob_store.put_artifact(invalid_hex, b"data", "text/plain")


def test_get_artifact_existing(blob_store, mock_s3):
    """Test retrieving an existing artifact."""
    test_data = b"test content"
    raw_hash = hash_bytes(test_data).hex()

    # Mock successful get
    mock_body = MagicMock()
    mock_body.read.return_value = test_data
    mock_s3.get_object.return_value = {"Body": mock_body}

    result = blob_store.get_artifact(raw_hash)

    assert result == test_data
    mock_s3.get_object.assert_called_once_with(
        Bucket="olympus-artifacts",
        Key=raw_hash,
    )


def test_get_artifact_not_found(blob_store, mock_s3):
    """Test retrieving a non-existent artifact returns None."""
    raw_hash = hash_bytes(b"nonexistent").hex()

    mock_s3.get_object.side_effect = make_no_such_key_error()

    result = blob_store.get_artifact(raw_hash)

    assert result is None


def test_get_artifact_invalid_hash_length(blob_store):
    """Test that invalid hash length raises ValueError."""
    with pytest.raises(ValueError, match="must be 64 characters"):
        blob_store.get_artifact("tooshort")


def test_get_artifact_invalid_hex(blob_store):
    """Test that invalid hex string raises ValueError."""
    invalid_hex = "z" * 64  # 'z' is not a valid hex character
    with pytest.raises(ValueError, match="valid hex string"):
        blob_store.get_artifact(invalid_hex)


def test_exists_true(blob_store, mock_s3):
    """Test exists returns True for existing object."""
    raw_hash = hash_bytes(b"test").hex()

    mock_s3.head_object.return_value = {}

    result = blob_store.exists(raw_hash)

    assert result is True


def test_exists_false(blob_store, mock_s3):
    """Test exists returns False for non-existent object."""
    raw_hash = hash_bytes(b"nonexistent").hex()

    mock_s3.head_object.side_effect = make_404_error()

    result = blob_store.exists(raw_hash)

    assert result is False


def test_exists_invalid_hash_length(blob_store):
    """Test that invalid hash length raises ValueError."""
    with pytest.raises(ValueError, match="must be 64 characters"):
        blob_store.exists("tooshort")


def test_exists_invalid_hex(blob_store):
    """Test that invalid hex string raises ValueError."""
    invalid_hex = "x" * 64  # 'x' is not a valid hex character
    with pytest.raises(ValueError, match="valid hex string"):
        blob_store.exists(invalid_hex)


def test_cas_semantics():
    """Test that CAS semantics are enforced (key == hash)."""
    test_data = b"content addressable"
    raw_hash = hash_bytes(test_data).hex()

    # Verify the hash is 64 characters (32 bytes hex-encoded)
    assert len(raw_hash) == 64

    # Verify we can decode it back
    hash_bytes_decoded = bytes.fromhex(raw_hash)
    assert len(hash_bytes_decoded) == 32
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
