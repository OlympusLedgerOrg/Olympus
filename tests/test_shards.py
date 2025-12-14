"""
Tests for shard header protocol
"""

import pytest
from datetime import datetime
import nacl.signing
from protocol.shards import (
    create_shard_header,
    sign_header,
    verify_header,
    get_signing_key_from_seed,
    get_verify_key_from_signing_key
)
from protocol.hashes import hash_bytes


def test_create_shard_header():
    """Test creating a shard header."""
    root_hash = hash_bytes(b"test root")
    timestamp = datetime.utcnow().isoformat() + 'Z'
    
    header = create_shard_header(
        shard_id="shard1",
        root_hash=root_hash,
        timestamp=timestamp
    )
    
    assert header["shard_id"] == "shard1"
    assert header["root_hash"] == root_hash.hex()
    assert header["timestamp"] == timestamp
    assert header["previous_header_hash"] == ""
    assert "header_hash" in header
    assert len(bytes.fromhex(header["header_hash"])) == 32


def test_create_shard_header_with_previous():
    """Test creating a shard header with previous hash."""
    root_hash = hash_bytes(b"test root")
    timestamp = datetime.utcnow().isoformat() + 'Z'
    previous_hash = hash_bytes(b"previous").hex()
    
    header = create_shard_header(
        shard_id="shard1",
        root_hash=root_hash,
        timestamp=timestamp,
        previous_header_hash=previous_hash
    )
    
    assert header["previous_header_hash"] == previous_hash


def test_sign_and_verify_header():
    """Test signing and verifying a shard header."""
    # Generate key pair
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    
    # Create header
    root_hash = hash_bytes(b"test root")
    timestamp = datetime.utcnow().isoformat() + 'Z'
    header = create_shard_header(
        shard_id="shard1",
        root_hash=root_hash,
        timestamp=timestamp
    )
    
    # Sign header
    signature = sign_header(header, signing_key)
    assert len(bytes.fromhex(signature)) == 64  # Ed25519 signature is 64 bytes
    
    # Verify header
    assert verify_header(header, signature, verify_key) is True


def test_verify_header_with_bad_signature():
    """Test that verification fails with wrong signature."""
    # Generate two different key pairs
    signing_key1 = nacl.signing.SigningKey.generate()
    signing_key2 = nacl.signing.SigningKey.generate()
    verify_key1 = signing_key1.verify_key
    
    # Create and sign header with key1
    root_hash = hash_bytes(b"test root")
    timestamp = datetime.utcnow().isoformat() + 'Z'
    header = create_shard_header(
        shard_id="shard1",
        root_hash=root_hash,
        timestamp=timestamp
    )
    
    # Sign with key2 (wrong key)
    signature = sign_header(header, signing_key2)
    
    # Verify with key1 should fail
    assert verify_header(header, signature, verify_key1) is False


def test_verify_header_with_tampered_hash():
    """Test that verification fails with tampered header hash."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    
    root_hash = hash_bytes(b"test root")
    timestamp = datetime.utcnow().isoformat() + 'Z'
    header = create_shard_header(
        shard_id="shard1",
        root_hash=root_hash,
        timestamp=timestamp
    )
    
    signature = sign_header(header, signing_key)
    
    # Tamper with header hash
    header["header_hash"] = hash_bytes(b"tampered").hex()
    
    # Verification should fail
    assert verify_header(header, signature, verify_key) is False


def test_deterministic_signing_key_from_seed():
    """Test that signing key generation from seed is deterministic."""
    seed = hash_bytes(b"test seed")
    
    key1 = get_signing_key_from_seed(seed)
    key2 = get_signing_key_from_seed(seed)
    
    # Keys should be identical
    assert bytes(key1) == bytes(key2)


def test_signing_key_from_seed_invalid_length():
    """Test that invalid seed length is rejected."""
    with pytest.raises(ValueError, match="must be 32 bytes"):
        get_signing_key_from_seed(b"short")


def test_get_verify_key_from_signing_key():
    """Test extracting verify key from signing key."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = get_verify_key_from_signing_key(signing_key)
    
    # Should be able to verify signatures
    root_hash = hash_bytes(b"test root")
    timestamp = datetime.utcnow().isoformat() + 'Z'
    header = create_shard_header(
        shard_id="shard1",
        root_hash=root_hash,
        timestamp=timestamp
    )
    
    signature = sign_header(header, signing_key)
    assert verify_header(header, signature, verify_key) is True


def test_header_hash_changes_with_content():
    """Test that header hash changes when content changes."""
    root_hash = hash_bytes(b"test root")
    timestamp = datetime.utcnow().isoformat() + 'Z'
    
    header1 = create_shard_header(
        shard_id="shard1",
        root_hash=root_hash,
        timestamp=timestamp
    )
    
    header2 = create_shard_header(
        shard_id="shard2",  # Different shard ID
        root_hash=root_hash,
        timestamp=timestamp
    )
    
    assert header1["header_hash"] != header2["header_hash"]


def test_header_hash_deterministic():
    """Test that header hash is deterministic."""
    root_hash = hash_bytes(b"test root")
    timestamp = "2024-01-01T00:00:00Z"  # Fixed timestamp
    
    header1 = create_shard_header(
        shard_id="shard1",
        root_hash=root_hash,
        timestamp=timestamp
    )
    
    header2 = create_shard_header(
        shard_id="shard1",
        root_hash=root_hash,
        timestamp=timestamp
    )
    
    assert header1["header_hash"] == header2["header_hash"]


def test_invalid_root_hash_length():
    """Test that invalid root hash length is rejected."""
    timestamp = datetime.utcnow().isoformat() + 'Z'
    
    with pytest.raises(ValueError, match="must be 32 bytes"):
        create_shard_header(
            shard_id="shard1",
            root_hash=b"short",
            timestamp=timestamp
        )
