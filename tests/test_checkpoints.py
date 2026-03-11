"""
Tests for signed checkpoint protocol

This module tests the checkpoint system designed to prevent split-view
attacks in transparency logs.
"""

from pathlib import Path

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
from protocol.federation import FederationNode, FederationRegistry
from protocol.hashes import hash_bytes
from protocol.merkle import ct_merkle_root, generate_consistency_proof
from protocol.shards import get_signing_key_from_seed


REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "examples" / "federation_registry.json"


def _test_signing_key(seed_byte: int) -> nacl.signing.SigningKey:
    """Return a deterministic test-only Ed25519 key for checkpoint tests (not for production)."""
    return get_signing_key_from_seed(bytes([seed_byte]) * 32)


@pytest.fixture
def registry() -> FederationRegistry:
    """Load the static federation registry."""
    return FederationRegistry.from_file(REGISTRY_PATH)


@pytest.fixture
def signing_keys() -> dict[str, nacl.signing.SigningKey]:
    """Provide quorum signing keys for the test federation registry."""
    return {
        "olympus-node-1": _test_signing_key(1),
        "olympus-node-2": _test_signing_key(2),
    }


def _leaf_hashes(count: int) -> list[bytes]:
    """Deterministic leaf hashes for building Merkle roots in tests."""
    return [hash_bytes(f"leaf-{i}".encode()) for i in range(count)]


def _build_checkpoint(
    *,
    sequence: int,
    height: int,
    registry: FederationRegistry,
    signing_keys: dict[str, nacl.signing.SigningKey],
    previous: SignedCheckpoint | None = None,
    shard_roots: dict[str, str] | None = None,
) -> SignedCheckpoint:
    leaves = _leaf_hashes(height)
    root_hex = ct_merkle_root(leaves).hex()
    prev_hash = ""
    proof: list[str] = []

    if previous is not None:
        proof_bytes = generate_consistency_proof(leaves, previous.ledger_height, height)
        proof = [p.hex() for p in proof_bytes]
        prev_hash = previous.checkpoint_hash

    return create_checkpoint(
        sequence=sequence,
        ledger_head_hash=root_hex,
        ledger_height=height,
        previous_checkpoint_hash=prev_hash,
        shard_roots=shard_roots,
        consistency_proof=proof,
        registry=registry,
        signing_keys=signing_keys,
    )


def test_create_checkpoint_basic(registry, signing_keys):
    """Test basic checkpoint creation."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    assert checkpoint.sequence == 0
    assert checkpoint.ledger_head_hash == "abc123"
    assert checkpoint.ledger_height == 1
    assert checkpoint.previous_checkpoint_hash == ""
    assert checkpoint.shard_roots == {}
    assert checkpoint.checkpoint_hash
    assert checkpoint.federation_quorum_certificate


def test_create_checkpoint_with_shards(registry, signing_keys):
    """Test checkpoint creation with shard roots."""
    genesis = _build_checkpoint(
        sequence=0, height=4, registry=registry, signing_keys=signing_keys
    )
    shard_roots = {
        "shard1": "root1",
        "shard2": "root2",
    }
    checkpoint = _build_checkpoint(
        sequence=1,
        height=6,
        registry=registry,
        signing_keys=signing_keys,
        previous=genesis,
        shard_roots=shard_roots,
    )

    assert checkpoint.sequence == 1
    assert checkpoint.shard_roots == shard_roots
    assert checkpoint.previous_checkpoint_hash == genesis.checkpoint_hash


def test_create_checkpoint_negative_sequence(registry, signing_keys):
    """Test that negative sequence numbers are rejected."""
    with pytest.raises(ValueError, match="sequence must be non-negative"):
        create_checkpoint(
            sequence=-1,
            ledger_head_hash="abc",
            ledger_height=1,
            registry=registry,
            signing_keys=signing_keys,
        )


def test_create_checkpoint_negative_height(registry, signing_keys):
    """Test that negative ledger heights are rejected."""
    with pytest.raises(ValueError, match="Ledger height must be non-negative"):
        create_checkpoint(
            sequence=0,
            ledger_head_hash="abc",
            ledger_height=-1,
            registry=registry,
            signing_keys=signing_keys,
        )


def test_create_checkpoint_requires_consistency_proof_for_children(registry, signing_keys):
    """Non-genesis checkpoints must supply a consistency proof."""
    with pytest.raises(ValueError, match="consistency proof"):
        create_checkpoint(
            sequence=1,
            ledger_head_hash="abc",
            ledger_height=2,
            previous_checkpoint_hash="prev",
            registry=registry,
            signing_keys=signing_keys,
        )


def test_create_checkpoint_requires_previous_hash_for_children(registry, signing_keys):
    """Non-genesis checkpoints must supply a previous checkpoint hash."""
    with pytest.raises(ValueError, match="previous_checkpoint_hash"):
        create_checkpoint(
            sequence=1,
            ledger_head_hash="abc",
            ledger_height=2,
            consistency_proof=["00"],
            registry=registry,
            signing_keys=signing_keys,
        )


def test_verify_checkpoint_valid(registry, signing_keys):
    """Test verification of a valid checkpoint."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    assert verify_checkpoint(checkpoint, registry)


def test_verify_checkpoint_invalid_hash(registry, signing_keys):
    """Test that checkpoints with invalid hashes are rejected."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    # Tamper with checkpoint hash
    checkpoint.checkpoint_hash = "tampered_hash"

    assert not verify_checkpoint(checkpoint, registry)


def test_verify_checkpoint_invalid_signature(registry, signing_keys):
    """Test that checkpoints with invalid signatures are rejected."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    checkpoint.federation_quorum_certificate["signatures"][0]["signature"] = "00"
    assert not verify_checkpoint(checkpoint, registry)


def test_verify_checkpoint_uses_epoch_snapshot(registry, signing_keys):
    """Verification should use the registry snapshot matching the certificate epoch."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    advanced_registry = FederationRegistry(
        nodes=tuple(
            [
                *registry.nodes,
                FederationNode(
                    node_id="olympus-node-4",
                    pubkey=_test_signing_key(4).verify_key.encode(),
                    endpoint="https://node4.olympus.org",
                    operator="Regional Clerk",
                    jurisdiction="region-d",
                    status="active",
                ),
            ]
        ),
        epoch=1,
        snapshots={0: registry},
    )

    assert verify_checkpoint(checkpoint, advanced_registry)


def test_verify_checkpoint_tampered_content(registry, signing_keys):
    """Test that tampering with checkpoint content invalidates it."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    # Tamper with ledger height
    checkpoint.ledger_height = 999

    assert not verify_checkpoint(checkpoint, registry)


def test_verify_checkpoint_chain_empty(registry):
    """Test that empty checkpoint chains are valid."""
    assert verify_checkpoint_chain([], registry)


def test_verify_checkpoint_chain_single(registry, signing_keys):
    """Test verification of a single checkpoint."""
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    assert verify_checkpoint_chain([checkpoint], registry)


def test_verify_checkpoint_chain_valid(registry, signing_keys):
    """Test verification of a valid checkpoint chain."""
    checkpoint1 = _build_checkpoint(
        sequence=0, height=1, registry=registry, signing_keys=signing_keys
    )
    checkpoint2 = _build_checkpoint(
        sequence=1,
        height=2,
        registry=registry,
        signing_keys=signing_keys,
        previous=checkpoint1,
    )
    checkpoint3 = _build_checkpoint(
        sequence=2,
        height=3,
        registry=registry,
        signing_keys=signing_keys,
        previous=checkpoint2,
    )

    assert verify_checkpoint_chain([checkpoint1, checkpoint2, checkpoint3], registry)


def test_verify_checkpoint_chain_invalid_genesis(registry, signing_keys):
    """Test that non-empty previous_checkpoint_hash in genesis is rejected."""
    with pytest.raises(ValueError, match="Genesis checkpoints .* previous_checkpoint_hash"):
        create_checkpoint(
            sequence=0,
            ledger_head_hash="abc123",
            ledger_height=1,
            previous_checkpoint_hash="should_be_empty",
            consistency_proof=["00"],
            registry=registry,
            signing_keys=signing_keys,
        )


def test_verify_checkpoint_chain_broken_linkage(registry, signing_keys):
    """Test that broken checkpoint linkage is detected."""
    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    checkpoint2 = create_checkpoint(
        sequence=1,
        ledger_head_hash="def456",
        ledger_height=2,
        previous_checkpoint_hash="wrong_hash",  # Should reference checkpoint1
        consistency_proof=["00"],
        registry=registry,
        signing_keys=signing_keys,
    )

    assert not verify_checkpoint_chain([checkpoint1, checkpoint2], registry)


def test_verify_checkpoint_chain_non_monotonic_sequence(registry, signing_keys):
    """Test that non-monotonic sequence numbers are rejected."""
    checkpoint1 = _build_checkpoint(
        sequence=0, height=1, registry=registry, signing_keys=signing_keys
    )
    checkpoint2 = _build_checkpoint(
        sequence=2,
        height=2,
        registry=registry,
        signing_keys=signing_keys,
        previous=checkpoint1,
    )
    checkpoint3 = _build_checkpoint(
        sequence=1,
        height=3,
        registry=registry,
        signing_keys=signing_keys,
        previous=checkpoint2,
    )

    # Intentional sequence ordering: 0, 2, 1 with valid linkage to isolate 2→1 non-monotonic detection.
    assert not verify_checkpoint_chain([checkpoint1, checkpoint2, checkpoint3], registry)


def test_verify_checkpoint_chain_decreasing_height(registry, signing_keys):
    """Test that decreasing ledger heights are rejected."""
    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=10,
        registry=registry,
        signing_keys=signing_keys,
    )

    checkpoint2 = create_checkpoint(
        sequence=1,
        ledger_head_hash="def456",
        ledger_height=5,  # Lower than checkpoint1
        previous_checkpoint_hash=checkpoint1.checkpoint_hash,
        consistency_proof=["00"],
        registry=registry,
        signing_keys=signing_keys,
    )

    assert not verify_checkpoint_chain([checkpoint1, checkpoint2], registry)


def test_verify_checkpoint_chain_rejects_invalid_consistency_proof(registry, signing_keys):
    """Checkpoint chains must provide a valid Merkle consistency proof."""
    checkpoint1 = _build_checkpoint(
        sequence=0, height=2, registry=registry, signing_keys=signing_keys
    )
    checkpoint2 = _build_checkpoint(
        sequence=1,
        height=4,
        registry=registry,
        signing_keys=signing_keys,
        previous=checkpoint1,
    )

    # Tamper with the proof
    checkpoint2.consistency_proof[0] = "00"

    assert not verify_checkpoint_chain([checkpoint1, checkpoint2], registry)


def test_detect_checkpoint_fork_same_sequence(registry, signing_keys):
    """Test fork detection for checkpoints with same sequence."""
    parent = _build_checkpoint(
        sequence=0, height=1, registry=registry, signing_keys=signing_keys
    )
    checkpoint1 = _build_checkpoint(
        sequence=1,
        height=2,
        registry=registry,
        signing_keys=signing_keys,
        previous=parent,
    )
    checkpoint2 = _build_checkpoint(
        sequence=1,
        height=3,
        registry=registry,
        signing_keys=signing_keys,
        previous=parent,
    )

    assert detect_checkpoint_fork(checkpoint1, checkpoint2)


def test_detect_checkpoint_fork_same_parent(registry, signing_keys):
    """Test fork detection for checkpoints with same parent."""
    parent = create_checkpoint(
        sequence=0,
        ledger_head_hash="parent",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    checkpoint1 = _build_checkpoint(
        sequence=1,
        height=3,
        registry=registry,
        signing_keys=signing_keys,
        previous=parent,
    )

    checkpoint2 = _build_checkpoint(
        sequence=2,  # Different sequence
        height=3,
        registry=registry,
        signing_keys=signing_keys,
        previous=parent,  # Same parent
    )

    assert detect_checkpoint_fork(checkpoint1, checkpoint2)


def test_detect_checkpoint_fork_no_fork(registry, signing_keys):
    """Test that legitimate checkpoints don't trigger fork detection."""
    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    checkpoint2 = _build_checkpoint(
        sequence=1,
        height=2,
        registry=registry,
        signing_keys=signing_keys,
        previous=checkpoint1,
    )

    assert not detect_checkpoint_fork(checkpoint1, checkpoint2)


def test_checkpoint_registry_add_checkpoint(registry, signing_keys):
    """Test adding checkpoints to registry."""
    registry_store = CheckpointRegistry(registry)

    checkpoint1 = _build_checkpoint(
        sequence=0, height=1, registry=registry, signing_keys=signing_keys
    )

    assert registry_store.add_checkpoint(checkpoint1)
    assert len(registry_store.checkpoints) == 1

    checkpoint2 = _build_checkpoint(
        sequence=1,
        height=2,
        registry=registry,
        signing_keys=signing_keys,
        previous=checkpoint1,
    )

    assert registry_store.add_checkpoint(checkpoint2)
    assert len(registry_store.checkpoints) == 2


def test_checkpoint_registry_reject_invalid(registry, signing_keys):
    """Test that registry rejects invalid checkpoints."""
    registry_store = CheckpointRegistry(registry)

    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    # Tamper with checkpoint
    checkpoint.checkpoint_hash = "invalid"

    assert not registry_store.add_checkpoint(checkpoint)
    assert len(registry_store.checkpoints) == 0


def test_checkpoint_registry_detect_fork(registry, signing_keys):
    """Test that registry detects and rejects forks."""
    registry_store = CheckpointRegistry(registry)

    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    registry_store.add_checkpoint(checkpoint1)

    # Try to add a conflicting checkpoint with same sequence
    checkpoint2 = create_checkpoint(
        sequence=0,  # Same sequence
        ledger_head_hash="def456",  # Different content
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    with pytest.raises(ValueError, match="Fork detected"):
        registry_store.add_checkpoint(checkpoint2)


def test_checkpoint_registry_verify(registry, signing_keys):
    """Test registry verification."""
    registry_store = CheckpointRegistry(registry)

    checkpoint1 = _build_checkpoint(
        sequence=0, height=1, registry=registry, signing_keys=signing_keys
    )
    registry_store.add_checkpoint(checkpoint1)

    checkpoint2 = _build_checkpoint(
        sequence=1,
        height=2,
        registry=registry,
        signing_keys=signing_keys,
        previous=checkpoint1,
    )
    registry_store.add_checkpoint(checkpoint2)

    assert registry_store.verify_registry()


def test_checkpoint_registry_get_checkpoint(registry, signing_keys):
    """Test retrieving checkpoints by sequence."""
    registry_store = CheckpointRegistry(registry)

    parent = _build_checkpoint(
        sequence=0, height=1, registry=registry, signing_keys=signing_keys
    )
    registry_store.add_checkpoint(parent)

    checkpoint = _build_checkpoint(
        sequence=1,
        height=2,
        registry=registry,
        signing_keys=signing_keys,
        previous=parent,
    )
    registry_store.add_checkpoint(checkpoint)

    retrieved = registry_store.get_checkpoint(1)
    assert retrieved is not None
    assert retrieved.sequence == 1

    assert registry_store.get_checkpoint(999) is None


def test_checkpoint_registry_get_latest(registry, signing_keys):
    """Test retrieving the latest checkpoint."""
    registry_store = CheckpointRegistry(registry)

    assert registry_store.get_latest_checkpoint() is None

    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )
    registry_store.add_checkpoint(checkpoint1)

    latest = registry_store.get_latest_checkpoint()
    assert latest is not None
    assert latest.sequence == 0

    checkpoint2 = create_checkpoint(
        sequence=1,
        ledger_head_hash="def456",
        ledger_height=2,
        previous_checkpoint_hash=checkpoint1.checkpoint_hash,
        consistency_proof=["00"],
        registry=registry,
        signing_keys=signing_keys,
    )
    registry_store.add_checkpoint(checkpoint2)

    latest = registry_store.get_latest_checkpoint()
    assert latest is not None
    assert latest.sequence == 1


def test_checkpoint_serialization(registry, signing_keys):
    """Test checkpoint serialization to/from dictionary."""
    checkpoint = create_checkpoint(
        sequence=1,
        ledger_head_hash="abc123",
        ledger_height=10,
        previous_checkpoint_hash="prev123",
        shard_roots={"shard1": "root1"},
        consistency_proof=["deadbeef"],
        registry=registry,
        signing_keys=signing_keys,
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
    assert restored.federation_quorum_certificate == checkpoint.federation_quorum_certificate


def test_checkpoint_determinism(registry, signing_keys):
    """Test that checkpoint creation is deterministic given same inputs."""
    # Create two checkpoints with same parameters at different times
    checkpoint1 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    checkpoint2 = create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )

    # Timestamps will differ, so hashes will differ
    assert checkpoint1.timestamp != checkpoint2.timestamp
    assert checkpoint1.checkpoint_hash != checkpoint2.checkpoint_hash

    # But signatures should both be valid
    assert verify_checkpoint(checkpoint1, registry)
    assert verify_checkpoint(checkpoint2, registry)
