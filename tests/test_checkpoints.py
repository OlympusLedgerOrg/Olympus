"""
Tests for signed checkpoint protocol

This module tests the checkpoint system designed to prevent split-view
attacks in transparency logs.
"""

import nacl.signing
import pytest

from protocol.checkpoints import (
    CheckpointRegistry,
    SignedCheckpoint,
    create_checkpoint,
    detect_checkpoint_fork,
    verify_checkpoint,
    verify_checkpoint_chain,
)


@pytest.fixture
def signing_key():
    """Generate a test Ed25519 signing key."""
    return nacl.signing.SigningKey.generate()


@pytest.fixture
def another_signing_key():
    """Generate another test Ed25519 signing key."""
    return nacl.signing.SigningKey.generate()


def test_create_checkpoint_basic(signing_key):
    """Test basic checkpoint creation."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    assert checkpoint.sequence == 0
    assert checkpoint.ledger_head_hash == "abc123"
    assert checkpoint.ledger_height == 1
    assert checkpoint.previous_checkpoint_hash == ""
    assert checkpoint.shard_roots == {}
    assert checkpoint.checkpoint_hash
    assert checkpoint.signature
    assert checkpoint.public_key


def test_create_checkpoint_with_shards(signing_key):
    """Test checkpoint creation with shard roots."""
    shard_roots = {
        "shard1": "root1",
        "shard2": "root2",
    }
    checkpoint = create_checkpoint(
        sequence=1,
        ledger_head_hash="def456",
        ledger_height=10,
        previous_checkpoint_hash="previous123",
        shard_roots=shard_roots,
        signing_key=signing_key,
    )

    assert checkpoint.sequence == 1
    assert checkpoint.shard_roots == shard_roots
    assert checkpoint.previous_checkpoint_hash == "previous123"


def test_create_checkpoint_negative_sequence(signing_key):
    """Test that negative sequence numbers are rejected."""
    with pytest.raises(ValueError, match="sequence must be non-negative"):
        create_checkpoint(
            sequence=-1,
            ledger_head_hash="abc",
            ledger_height=1,
            signing_key=signing_key,
        )


def test_create_checkpoint_negative_height(signing_key):
    """Test that negative ledger heights are rejected."""
    with pytest.raises(ValueError, match="Ledger height must be non-negative"):
        create_checkpoint(
            sequence=0,
            ledger_head_hash="abc",
            ledger_height=-1,
            signing_key=signing_key,
        )


def test_verify_checkpoint_valid(signing_key):
    """Test verification of a valid checkpoint."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    # Verify with embedded public key
    assert verify_checkpoint(checkpoint)

    # Verify with explicit verify key
    verify_key = signing_key.verify_key
    assert verify_checkpoint(checkpoint, verify_key)


def test_verify_checkpoint_invalid_hash(signing_key):
    """Test that checkpoints with invalid hashes are rejected."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    # Tamper with checkpoint hash
    checkpoint.checkpoint_hash = "tampered_hash"

    assert not verify_checkpoint(checkpoint)


def test_verify_checkpoint_invalid_signature(signing_key, another_signing_key):
    """Test that checkpoints with invalid signatures are rejected."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    # Try to verify with wrong key
    wrong_verify_key = another_signing_key.verify_key
    assert not verify_checkpoint(checkpoint, wrong_verify_key)


def test_verify_checkpoint_tampered_content(signing_key):
    """Test that tampering with checkpoint content invalidates it."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    # Tamper with ledger height
    checkpoint.ledger_height = 999

    assert not verify_checkpoint(checkpoint)


def test_verify_checkpoint_chain_empty():
    """Test that empty checkpoint chains are valid."""
    assert verify_checkpoint_chain([])


def test_verify_checkpoint_chain_single(signing_key):
    """Test verification of a single checkpoint."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    assert verify_checkpoint_chain([checkpoint])


def test_verify_checkpoint_chain_valid(signing_key):
    """Test verification of a valid checkpoint chain."""
    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    checkpoint2 = create_checkpoint(
        sequence=1,
        ledger_head_hash="def456",
        ledger_height=2,
        previous_checkpoint_hash=checkpoint1.checkpoint_hash,
        signing_key=signing_key,
    )

    checkpoint3 = create_checkpoint(
        sequence=2,
        ledger_head_hash="ghi789",
        ledger_height=3,
        previous_checkpoint_hash=checkpoint2.checkpoint_hash,
        signing_key=signing_key,
    )

    assert verify_checkpoint_chain([checkpoint1, checkpoint2, checkpoint3])


def test_verify_checkpoint_chain_invalid_genesis(signing_key):
    """Test that non-empty previous_checkpoint_hash in genesis is rejected."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        previous_checkpoint_hash="should_be_empty",
        signing_key=signing_key,
    )

    assert not verify_checkpoint_chain([checkpoint])


def test_verify_checkpoint_chain_broken_linkage(signing_key):
    """Test that broken checkpoint linkage is detected."""
    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    checkpoint2 = create_checkpoint(
        sequence=1,
        ledger_head_hash="def456",
        ledger_height=2,
        previous_checkpoint_hash="wrong_hash",  # Should reference checkpoint1
        signing_key=signing_key,
    )

    assert not verify_checkpoint_chain([checkpoint1, checkpoint2])


def test_verify_checkpoint_chain_non_monotonic_sequence(signing_key):
    """Test that non-monotonic sequence numbers are rejected."""
    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    checkpoint2 = create_checkpoint(
        sequence=0,  # Same sequence as checkpoint1
        ledger_head_hash="def456",
        ledger_height=2,
        previous_checkpoint_hash=checkpoint1.checkpoint_hash,
        signing_key=signing_key,
    )

    assert not verify_checkpoint_chain([checkpoint1, checkpoint2])


def test_verify_checkpoint_chain_decreasing_height(signing_key):
    """Test that decreasing ledger heights are rejected."""
    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=10,
        signing_key=signing_key,
    )

    checkpoint2 = create_checkpoint(
        sequence=1,
        ledger_head_hash="def456",
        ledger_height=5,  # Lower than checkpoint1
        previous_checkpoint_hash=checkpoint1.checkpoint_hash,
        signing_key=signing_key,
    )

    assert not verify_checkpoint_chain([checkpoint1, checkpoint2])


def test_detect_checkpoint_fork_same_sequence(signing_key):
    """Test fork detection for checkpoints with same sequence."""
    checkpoint1 = create_checkpoint(
        sequence=1,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    checkpoint2 = create_checkpoint(
        sequence=1,  # Same sequence
        ledger_head_hash="def456",  # Different content
        ledger_height=1,
        signing_key=signing_key,
    )

    assert detect_checkpoint_fork(checkpoint1, checkpoint2)


def test_detect_checkpoint_fork_same_parent(signing_key):
    """Test fork detection for checkpoints with same parent."""
    parent = create_checkpoint(
        sequence=0,
        ledger_head_hash="parent",
        ledger_height=1,
        signing_key=signing_key,
    )

    checkpoint1 = create_checkpoint(
        sequence=1,
        ledger_head_hash="abc123",
        ledger_height=2,
        previous_checkpoint_hash=parent.checkpoint_hash,
        signing_key=signing_key,
    )

    checkpoint2 = create_checkpoint(
        sequence=2,  # Different sequence
        ledger_head_hash="def456",  # Different content
        ledger_height=2,
        previous_checkpoint_hash=parent.checkpoint_hash,  # Same parent
        signing_key=signing_key,
    )

    assert detect_checkpoint_fork(checkpoint1, checkpoint2)


def test_detect_checkpoint_fork_no_fork(signing_key):
    """Test that legitimate checkpoints don't trigger fork detection."""
    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    checkpoint2 = create_checkpoint(
        sequence=1,
        ledger_head_hash="def456",
        ledger_height=2,
        previous_checkpoint_hash=checkpoint1.checkpoint_hash,
        signing_key=signing_key,
    )

    assert not detect_checkpoint_fork(checkpoint1, checkpoint2)


def test_checkpoint_registry_add_checkpoint(signing_key):
    """Test adding checkpoints to registry."""
    registry = CheckpointRegistry()

    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    assert registry.add_checkpoint(checkpoint1)
    assert len(registry.checkpoints) == 1

    checkpoint2 = create_checkpoint(
        sequence=1,
        ledger_head_hash="def456",
        ledger_height=2,
        previous_checkpoint_hash=checkpoint1.checkpoint_hash,
        signing_key=signing_key,
    )

    assert registry.add_checkpoint(checkpoint2)
    assert len(registry.checkpoints) == 2


def test_checkpoint_registry_reject_invalid(signing_key):
    """Test that registry rejects invalid checkpoints."""
    registry = CheckpointRegistry()

    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    # Tamper with checkpoint
    checkpoint.checkpoint_hash = "invalid"

    assert not registry.add_checkpoint(checkpoint)
    assert len(registry.checkpoints) == 0


def test_checkpoint_registry_detect_fork(signing_key):
    """Test that registry detects and rejects forks."""
    registry = CheckpointRegistry()

    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    registry.add_checkpoint(checkpoint1)

    # Try to add a conflicting checkpoint with same sequence
    checkpoint2 = create_checkpoint(
        sequence=0,  # Same sequence
        ledger_head_hash="def456",  # Different content
        ledger_height=1,
        signing_key=signing_key,
    )

    with pytest.raises(ValueError, match="Fork detected"):
        registry.add_checkpoint(checkpoint2)


def test_checkpoint_registry_verify(signing_key):
    """Test registry verification."""
    registry = CheckpointRegistry()

    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )
    registry.add_checkpoint(checkpoint1)

    checkpoint2 = create_checkpoint(
        sequence=1,
        ledger_head_hash="def456",
        ledger_height=2,
        previous_checkpoint_hash=checkpoint1.checkpoint_hash,
        signing_key=signing_key,
    )
    registry.add_checkpoint(checkpoint2)

    assert registry.verify_registry()


def test_checkpoint_registry_get_checkpoint(signing_key):
    """Test retrieving checkpoints by sequence."""
    registry = CheckpointRegistry()

    checkpoint = create_checkpoint(
        sequence=5,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )
    registry.add_checkpoint(checkpoint)

    retrieved = registry.get_checkpoint(5)
    assert retrieved is not None
    assert retrieved.sequence == 5

    assert registry.get_checkpoint(999) is None


def test_checkpoint_registry_get_latest(signing_key):
    """Test retrieving the latest checkpoint."""
    registry = CheckpointRegistry()

    assert registry.get_latest_checkpoint() is None

    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )
    registry.add_checkpoint(checkpoint1)

    latest = registry.get_latest_checkpoint()
    assert latest is not None
    assert latest.sequence == 0

    checkpoint2 = create_checkpoint(
        sequence=1,
        ledger_head_hash="def456",
        ledger_height=2,
        previous_checkpoint_hash=checkpoint1.checkpoint_hash,
        signing_key=signing_key,
    )
    registry.add_checkpoint(checkpoint2)

    latest = registry.get_latest_checkpoint()
    assert latest is not None
    assert latest.sequence == 1


def test_checkpoint_serialization(signing_key):
    """Test checkpoint serialization to/from dictionary."""
    checkpoint = create_checkpoint(
        sequence=1,
        ledger_head_hash="abc123",
        ledger_height=10,
        previous_checkpoint_hash="prev123",
        shard_roots={"shard1": "root1"},
        signing_key=signing_key,
    )

    # Convert to dict
    checkpoint_dict = checkpoint.to_dict()

    # Convert back
    restored = SignedCheckpoint.from_dict(checkpoint_dict)

    assert restored.sequence == checkpoint.sequence
    assert restored.ledger_head_hash == checkpoint.ledger_head_hash
    assert restored.ledger_height == checkpoint.ledger_height
    assert restored.previous_checkpoint_hash == checkpoint.previous_checkpoint_hash
    assert restored.shard_roots == checkpoint.shard_roots
    assert restored.checkpoint_hash == checkpoint.checkpoint_hash
    assert restored.signature == checkpoint.signature
    assert restored.public_key == checkpoint.public_key


def test_checkpoint_determinism(signing_key):
    """Test that checkpoint creation is deterministic given same inputs."""
    # Create two checkpoints with same parameters at different times
    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    checkpoint2 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        signing_key=signing_key,
    )

    # Timestamps will differ, so hashes will differ
    assert checkpoint1.timestamp != checkpoint2.timestamp
    assert checkpoint1.checkpoint_hash != checkpoint2.checkpoint_hash

    # But signatures should both be valid
    assert verify_checkpoint(checkpoint1)
    assert verify_checkpoint(checkpoint2)
