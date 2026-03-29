"""Extended tests for protocol.checkpoints – verify_checkpoint_quorum_certificate paths."""

from pathlib import Path

import nacl.signing
import pytest

from protocol.checkpoints import (
    SignedCheckpoint,
    create_checkpoint,
    sign_federated_checkpoint,
    verify_checkpoint_quorum_certificate,
    verify_federated_checkpoint_signatures,
)
from protocol.federation import FederationNode, FederationRegistry, NodeSignature
from protocol.shards import get_signing_key_from_seed


REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "examples" / "federation_registry.json"


def _test_signing_key(seed_byte: int) -> nacl.signing.SigningKey:
    """Return a deterministic test-only Ed25519 key."""
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


def _build_valid_checkpoint(
    registry: FederationRegistry,
    signing_keys: dict[str, nacl.signing.SigningKey],
) -> SignedCheckpoint:
    """Build a valid signed checkpoint with quorum certificate."""
    return create_checkpoint(
        sequence=0,
        ledger_head_hash="abc123",
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )


# ---------------------------------------------------------------------------
# Duplicate node signatures (line 195-196: node_id in seen_nodes → continue)
# ---------------------------------------------------------------------------


def test_duplicate_node_signatures_are_skipped(registry, signing_keys):
    """Duplicate node signatures should be skipped in verify_federated_checkpoint_signatures."""
    checkpoint = _build_valid_checkpoint(registry, signing_keys)
    # Build NodeSignature objects from the certificate signatures
    cert = checkpoint.federation_quorum_certificate
    sigs = [
        NodeSignature(node_id=s["node_id"], signature=s["signature"])
        for s in cert["signatures"]
    ]
    # Add a duplicate of the first signature
    duplicated_sigs = sigs + [sigs[0]]

    valid = verify_federated_checkpoint_signatures(
        checkpoint_hash=checkpoint.checkpoint_hash,
        sequence=checkpoint.sequence,
        ledger_height=checkpoint.ledger_height,
        timestamp=checkpoint.timestamp,
        signatures=duplicated_sigs,
        registry=registry,
    )
    # Duplicate should be filtered out; valid count should equal original
    assert len(valid) == len(sigs)


# ---------------------------------------------------------------------------
# Node not in registry (line 198-200: registry.get_node raises ValueError)
# ---------------------------------------------------------------------------


def test_node_not_in_registry(registry, signing_keys):
    """Signature from a node not in the registry is filtered out."""
    checkpoint = _build_valid_checkpoint(registry, signing_keys)
    unknown_sig = NodeSignature(node_id="unknown-node-999", signature="aa" * 64)

    valid = verify_federated_checkpoint_signatures(
        checkpoint_hash=checkpoint.checkpoint_hash,
        sequence=checkpoint.sequence,
        ledger_height=checkpoint.ledger_height,
        timestamp=checkpoint.timestamp,
        signatures=[unknown_sig],
        registry=registry,
    )
    assert len(valid) == 0


# ---------------------------------------------------------------------------
# Inactive node (line 201-202: not node.active → continue)
# ---------------------------------------------------------------------------


def test_inactive_node_signature_rejected(signing_keys):
    """Signature from an inactive node should not count toward valid signatures."""
    inactive_node = FederationNode(
        node_id="olympus-node-1",
        pubkey=_test_signing_key(1).verify_key.encode(),
        endpoint="https://node1.olympus.org",
        operator="State Archives",
        jurisdiction="state-a",
        status="inactive",
    )
    active_node = FederationNode(
        node_id="olympus-node-2",
        pubkey=_test_signing_key(2).verify_key.encode(),
        endpoint="https://node2.olympus.org",
        operator="County Clerk",
        jurisdiction="county-b",
        status="active",
    )
    reg = FederationRegistry(
        nodes=(inactive_node, active_node),
        epoch=0,
    )

    # Sign with the inactive node's key
    inactive_sig = sign_federated_checkpoint(
        checkpoint_hash="test_hash",
        sequence=0,
        ledger_height=1,
        timestamp="2026-01-01T00:00:00Z",
        node_id="olympus-node-1",
        signing_key=signing_keys["olympus-node-1"],
        registry=reg,
    )

    valid = verify_federated_checkpoint_signatures(
        checkpoint_hash="test_hash",
        sequence=0,
        ledger_height=1,
        timestamp="2026-01-01T00:00:00Z",
        signatures=[inactive_sig],
        registry=reg,
    )
    # Inactive node's signature should be filtered out
    assert len(valid) == 0


# ---------------------------------------------------------------------------
# Malformed hex signature (line 214-217: bytes.fromhex → ValueError)
# ---------------------------------------------------------------------------


def test_malformed_hex_signature(registry, signing_keys):
    """Malformed hex in signature field should be filtered out."""
    checkpoint = _build_valid_checkpoint(registry, signing_keys)
    bad_sig = NodeSignature(node_id="olympus-node-1", signature="zzzz_not_valid_hex")

    valid = verify_federated_checkpoint_signatures(
        checkpoint_hash=checkpoint.checkpoint_hash,
        sequence=checkpoint.sequence,
        ledger_height=checkpoint.ledger_height,
        timestamp=checkpoint.timestamp,
        signatures=[bad_sig],
        registry=registry,
    )
    assert len(valid) == 0


# ---------------------------------------------------------------------------
# BadSignatureError (line 222-224: nacl BadSignatureError → continue)
# ---------------------------------------------------------------------------


def test_bad_signature_error(registry, signing_keys):
    """A valid-hex but wrong signature should not verify (BadSignatureError)."""
    checkpoint = _build_valid_checkpoint(registry, signing_keys)
    bad_sig = NodeSignature(node_id="olympus-node-1", signature="00" * 64)

    valid = verify_federated_checkpoint_signatures(
        checkpoint_hash=checkpoint.checkpoint_hash,
        sequence=checkpoint.sequence,
        ledger_height=checkpoint.ledger_height,
        timestamp=checkpoint.timestamp,
        signatures=[bad_sig],
        registry=registry,
    )
    assert len(valid) == 0


# ---------------------------------------------------------------------------
# Missing required fields in certificate
# ---------------------------------------------------------------------------


def test_missing_required_fields(registry, signing_keys):
    """Certificate missing required fields should fail verification."""
    checkpoint = _build_valid_checkpoint(registry, signing_keys)
    # Remove a required field
    del checkpoint.federation_quorum_certificate["checkpoint_hash"]
    assert not verify_checkpoint_quorum_certificate(checkpoint=checkpoint, registry=registry)


# ---------------------------------------------------------------------------
# Certificate checkpoint_hash mismatch
# ---------------------------------------------------------------------------


def test_certificate_checkpoint_hash_mismatch(registry, signing_keys):
    """Certificate checkpoint_hash not matching the checkpoint's hash fails."""
    checkpoint = _build_valid_checkpoint(registry, signing_keys)
    checkpoint.federation_quorum_certificate["checkpoint_hash"] = "wrong_hash"
    assert not verify_checkpoint_quorum_certificate(checkpoint=checkpoint, registry=registry)


# ---------------------------------------------------------------------------
# Certificate sequence mismatch
# ---------------------------------------------------------------------------


def test_certificate_sequence_mismatch(registry, signing_keys):
    """Certificate sequence not matching the checkpoint's sequence fails."""
    checkpoint = _build_valid_checkpoint(registry, signing_keys)
    checkpoint.federation_quorum_certificate["sequence"] = 999
    assert not verify_checkpoint_quorum_certificate(checkpoint=checkpoint, registry=registry)


# ---------------------------------------------------------------------------
# Certificate scheme mismatch
# ---------------------------------------------------------------------------


def test_certificate_scheme_mismatch(registry, signing_keys):
    """Certificate scheme not 'ed25519' should fail."""
    checkpoint = _build_valid_checkpoint(registry, signing_keys)
    checkpoint.federation_quorum_certificate["scheme"] = "rsa"
    assert not verify_checkpoint_quorum_certificate(checkpoint=checkpoint, registry=registry)


# ---------------------------------------------------------------------------
# Signer bitmap length mismatch
# ---------------------------------------------------------------------------


def test_signer_bitmap_wrong_length(registry, signing_keys):
    """signer_bitmap length not matching active node count should fail."""
    checkpoint = _build_valid_checkpoint(registry, signing_keys)
    checkpoint.federation_quorum_certificate["signer_bitmap"] = "1"
    assert not verify_checkpoint_quorum_certificate(checkpoint=checkpoint, registry=registry)


# ---------------------------------------------------------------------------
# Invalid signer_bitmap characters
# ---------------------------------------------------------------------------


def test_signer_bitmap_invalid_chars(registry, signing_keys):
    """signer_bitmap with non-0/1 characters should fail."""
    checkpoint = _build_valid_checkpoint(registry, signing_keys)
    bitmap = checkpoint.federation_quorum_certificate["signer_bitmap"]
    checkpoint.federation_quorum_certificate["signer_bitmap"] = "x" * len(bitmap)
    assert not verify_checkpoint_quorum_certificate(checkpoint=checkpoint, registry=registry)


# ---------------------------------------------------------------------------
# signatures not a list
# ---------------------------------------------------------------------------


def test_signatures_not_a_list(registry, signing_keys):
    """Non-list signatures field should fail."""
    checkpoint = _build_valid_checkpoint(registry, signing_keys)
    checkpoint.federation_quorum_certificate["signatures"] = "not_a_list"
    assert not verify_checkpoint_quorum_certificate(checkpoint=checkpoint, registry=registry)


# ---------------------------------------------------------------------------
# signer_bitmap not a string
# ---------------------------------------------------------------------------


def test_signer_bitmap_not_a_string(registry, signing_keys):
    """Non-string signer_bitmap should fail."""
    checkpoint = _build_valid_checkpoint(registry, signing_keys)
    checkpoint.federation_quorum_certificate["signer_bitmap"] = 123
    assert not verify_checkpoint_quorum_certificate(checkpoint=checkpoint, registry=registry)
