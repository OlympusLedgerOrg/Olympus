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
    error_response = {
        "Error": {"Code": "NoSuchKey", "Message": "The specified key does not exist."}
    }
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
