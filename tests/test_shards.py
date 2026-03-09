"""
Tests for shard header protocol
"""

import nacl.signing
import pytest

from protocol.hashes import hash_bytes
from protocol.shards import (
    create_key_revocation_record,
    create_shard_header,
    create_superseding_signature,
    derive_scoped_signing_key,
    get_signing_key_from_seed,
    get_verify_key_from_signing_key,
    rotation_record_to_event,
    sign_header,
    verify_header,
    verify_header_with_rotation,
    verify_key_revocation_record,
    verify_superseding_signature,
)
from protocol.timestamps import current_timestamp


def test_create_shard_header():
    """Test creating a shard header."""
    root_hash = hash_bytes(b"test root")
    timestamp = current_timestamp()

    header = create_shard_header(shard_id="shard1", root_hash=root_hash, timestamp=timestamp)

    assert header["shard_id"] == "shard1"
    assert header["root_hash"] == root_hash.hex()
    assert header["timestamp"] == timestamp
    assert header["previous_header_hash"] == ""
    assert "header_hash" in header
    assert len(bytes.fromhex(header["header_hash"])) == 32


def test_create_shard_header_with_previous():
    """Test creating a shard header with previous hash."""
    root_hash = hash_bytes(b"test root")
    timestamp = current_timestamp()
    previous_hash = hash_bytes(b"previous").hex()

    header = create_shard_header(
        shard_id="shard1",
        root_hash=root_hash,
        timestamp=timestamp,
        previous_header_hash=previous_hash,
    )

    assert header["previous_header_hash"] == previous_hash


def test_sign_and_verify_header():
    """Test signing and verifying a shard header."""
    # Generate key pair
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    # Create header
    root_hash = hash_bytes(b"test root")
    timestamp = current_timestamp()
    header = create_shard_header(shard_id="shard1", root_hash=root_hash, timestamp=timestamp)

    # Sign header
    signature = sign_header(header, signing_key)
    assert len(bytes.fromhex(signature)) == 64  # Ed25519 signature is 64 bytes

    # Verify header
    assert verify_header(header, signature, verify_key) is True


def test_sign_and_verify_header_with_timestamp_token_payload():
    """Verify signatures still validate when timestamp token payload is attached."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    root_hash = hash_bytes(b"test root")
    timestamp = current_timestamp()
    token_payload = {
        "hash_hex": root_hash.hex(),
        "tsa_url": "https://tsa.example",
        "tst_hex": "00",
        "timestamp": timestamp,
    }
    header = create_shard_header(
        shard_id="shard1",
        root_hash=root_hash,
        timestamp=timestamp,
        timestamp_token=token_payload,
    )

    signature = sign_header(header, signing_key)

    assert verify_header(header, signature, verify_key) is True


def test_verify_header_with_bad_signature():
    """Test that verification fails with wrong signature."""
    # Generate two different key pairs
    signing_key1 = nacl.signing.SigningKey.generate()
    signing_key2 = nacl.signing.SigningKey.generate()
    verify_key1 = signing_key1.verify_key

    # Create and sign header with key1
    root_hash = hash_bytes(b"test root")
    timestamp = current_timestamp()
    header = create_shard_header(shard_id="shard1", root_hash=root_hash, timestamp=timestamp)

    # Sign with key2 (wrong key)
    signature = sign_header(header, signing_key2)

    # Verify with key1 should fail
    assert verify_header(header, signature, verify_key1) is False


def test_verify_header_rejects_non_hex_signature():
    """Test that verification fails with non-hex signature input."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    root_hash = hash_bytes(b"test root")
    timestamp = current_timestamp()
    header = create_shard_header(shard_id="shard1", root_hash=root_hash, timestamp=timestamp)

    assert verify_header(header, "not-hex", verify_key) is False


def test_verify_header_with_tampered_hash():
    """Test that verification fails with tampered header hash."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    root_hash = hash_bytes(b"test root")
    timestamp = current_timestamp()
    header = create_shard_header(shard_id="shard1", root_hash=root_hash, timestamp=timestamp)

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


def test_derive_scoped_signing_key_is_deterministic_per_scope():
    """Scoped derivation should be stable for the same shard/node scope."""
    master_seed = hash_bytes(b"root secret")

    key1 = derive_scoped_signing_key(master_seed, "shard-a", "node-1")
    key2 = derive_scoped_signing_key(master_seed, "shard-a", "node-1")

    assert bytes(key1) == bytes(key2)


def test_derive_scoped_signing_key_changes_across_scopes():
    """Changing shard or node scope must change the derived key."""
    master_seed = hash_bytes(b"root secret")

    key_a = derive_scoped_signing_key(master_seed, "shard-a", "node-1")
    key_b = derive_scoped_signing_key(master_seed, "shard-b", "node-1")
    key_c = derive_scoped_signing_key(master_seed, "shard-a", "node-2")

    assert bytes(key_a) != bytes(key_b)
    assert bytes(key_a) != bytes(key_c)


def test_derive_scoped_signing_key_rejects_empty_explicit_node_id():
    master_seed = hash_bytes(b"root secret")

    with pytest.raises(ValueError, match="node_id must be non-empty"):
        derive_scoped_signing_key(master_seed, "shard-a", "")


def test_get_verify_key_from_signing_key():
    """Test extracting verify key from signing key."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = get_verify_key_from_signing_key(signing_key)

    # Should be able to verify signatures
    root_hash = hash_bytes(b"test root")
    timestamp = current_timestamp()
    header = create_shard_header(shard_id="shard1", root_hash=root_hash, timestamp=timestamp)

    signature = sign_header(header, signing_key)
    assert verify_header(header, signature, verify_key) is True


def test_header_hash_changes_with_content():
    """Test that header hash changes when content changes."""
    root_hash = hash_bytes(b"test root")
    timestamp = current_timestamp()

    header1 = create_shard_header(shard_id="shard1", root_hash=root_hash, timestamp=timestamp)

    header2 = create_shard_header(
        shard_id="shard2",  # Different shard ID
        root_hash=root_hash,
        timestamp=timestamp,
    )

    assert header1["header_hash"] != header2["header_hash"]


def test_header_hash_deterministic():
    """Test that header hash is deterministic."""
    root_hash = hash_bytes(b"test root")
    timestamp = "2024-01-01T00:00:00Z"  # Fixed timestamp

    header1 = create_shard_header(shard_id="shard1", root_hash=root_hash, timestamp=timestamp)

    header2 = create_shard_header(shard_id="shard1", root_hash=root_hash, timestamp=timestamp)

    assert header1["header_hash"] == header2["header_hash"]


def test_invalid_root_hash_length():
    """Test that invalid root hash length is rejected."""
    timestamp = current_timestamp()

    with pytest.raises(ValueError, match="must be 32 bytes"):
        create_shard_header(shard_id="shard1", root_hash=b"short", timestamp=timestamp)


def test_verify_key_revocation_record():
    """A replacement key must sign revocation metadata for the compromised key."""
    old_signing_key = nacl.signing.SigningKey.generate()
    new_signing_key = nacl.signing.SigningKey.generate()

    record = create_key_revocation_record(
        old_verify_key=old_signing_key.verify_key,
        new_signing_key=new_signing_key,
        compromise_timestamp="2026-03-01T00:00:00Z",
        last_good_sequence=7,
    )

    assert verify_key_revocation_record(record) is True


def test_verify_header_with_rotation_rejects_post_compromise_old_key():
    """Old-key signatures after compromise must be rejected without supersession."""
    old_signing_key = nacl.signing.SigningKey.generate()
    new_signing_key = nacl.signing.SigningKey.generate()
    header = create_shard_header(
        shard_id="shard1",
        root_hash=hash_bytes(b"test root"),
        timestamp="2026-03-01T00:00:00Z",
    )
    signature = sign_header(header, old_signing_key)
    revocation = create_key_revocation_record(
        old_verify_key=old_signing_key.verify_key,
        new_signing_key=new_signing_key,
        compromise_timestamp="2026-02-28T23:59:59Z",
        last_good_sequence=2,
    )

    assert (
        verify_header_with_rotation(
            header,
            signature,
            old_signing_key.verify_key,
            header_sequence=3,
            revocation_record=revocation,
        )
        is False
    )


def test_verify_header_with_rotation_accepts_superseding_signature():
    """Historical headers can be re-attested by the replacement key."""
    old_signing_key = nacl.signing.SigningKey.generate()
    new_signing_key = nacl.signing.SigningKey.generate()
    header = create_shard_header(
        shard_id="shard1",
        root_hash=hash_bytes(b"test root"),
        timestamp="2026-03-01T00:00:00Z",
    )
    signature = sign_header(header, old_signing_key)
    revocation = create_key_revocation_record(
        old_verify_key=old_signing_key.verify_key,
        new_signing_key=new_signing_key,
        compromise_timestamp="2026-02-28T23:59:59Z",
        last_good_sequence=2,
    )
    superseding = create_superseding_signature(
        header_hash=header["header_hash"],
        old_verify_key=old_signing_key.verify_key,
        new_signing_key=new_signing_key,
        supersedes_from=revocation["compromise_timestamp"],
    )

    assert verify_superseding_signature(
        superseding,
        header_hash=header["header_hash"],
        revocation_record=revocation,
    )
    assert (
        verify_header_with_rotation(
            header,
            signature,
            old_signing_key.verify_key,
            header_sequence=3,
            revocation_record=revocation,
            superseding_signature=superseding,
        )
        is True
    )


def test_verify_header_with_rotation_accepts_new_key_direct_signature():
    """Post-compromise headers signed directly by the replacement key stay valid."""
    old_signing_key = nacl.signing.SigningKey.generate()
    new_signing_key = nacl.signing.SigningKey.generate()
    header = create_shard_header(
        shard_id="shard1",
        root_hash=hash_bytes(b"test root"),
        timestamp="2026-03-01T00:00:00Z",
    )
    signature = sign_header(header, new_signing_key)
    revocation = create_key_revocation_record(
        old_verify_key=old_signing_key.verify_key,
        new_signing_key=new_signing_key,
        compromise_timestamp="2026-02-28T23:59:59Z",
        last_good_sequence=2,
    )

    assert (
        verify_header_with_rotation(
            header,
            signature,
            new_signing_key.verify_key,
            header_sequence=3,
            revocation_record=revocation,
        )
        is True
    )


def test_rotation_record_to_event_creates_canonical_event():
    """Rotation artifacts must be commit-ready for the append-only ledger."""
    old_signing_key = nacl.signing.SigningKey.generate()
    new_signing_key = nacl.signing.SigningKey.generate()
    record = create_key_revocation_record(
        old_verify_key=old_signing_key.verify_key,
        new_signing_key=new_signing_key,
        compromise_timestamp="2026-03-01T00:00:00Z",
        last_good_sequence=7,
    )

    event = rotation_record_to_event(record)

    assert event.payload["event_type"] == "key_revocation"
    assert event.hash_hex
