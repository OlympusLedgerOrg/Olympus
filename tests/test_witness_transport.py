"""Tests for witness transport and DNS publication helpers."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from protocol.checkpoints import SignedCheckpoint, create_checkpoint
from protocol.dns_publisher import checkpoint_record_set, checkpoint_txt_record, verify_txt_record
from protocol.federation import FederationRegistry
from protocol.hashes import hash_bytes
from protocol.shards import get_signing_key_from_seed
from protocol.witness_transport import WitnessAnnouncement, verify_announcement


REGISTRY_PATH = Path(__file__).resolve().parent.parent / "examples" / "federation_registry.json"


@pytest.fixture
def registry() -> FederationRegistry:
    """Load the static federation registry."""
    return FederationRegistry.from_file(REGISTRY_PATH)


@pytest.fixture
def signing_keys():
    """Deterministic test signing keys for the registry."""
    return {
        "olympus-node-1": get_signing_key_from_seed(b"\x01" * 32),
        "olympus-node-2": get_signing_key_from_seed(b"\x02" * 32),
    }


def _checkpoint(registry: FederationRegistry, signing_keys: dict[str, object]) -> SignedCheckpoint:
    """Build a minimal genesis checkpoint for testing."""
    root_hash = hash_bytes(b"witness-root").hex()
    return create_checkpoint(
        sequence=0,
        ledger_head_hash=root_hash,
        ledger_height=1,
        registry=registry,
        signing_keys=signing_keys,
    )


def test_witness_announcement_round_trip(registry, signing_keys):
    """Announcements validate their packet hash and checkpoint."""
    checkpoint = _checkpoint(registry, signing_keys)
    announcement = WitnessAnnouncement.create(
        origin="node-a",
        checkpoint=checkpoint,
        observed_at="2024-01-01T00:00:00Z",
        registry=registry,
    )

    assert verify_announcement(announcement, registry=registry)


def test_witness_announcement_rejects_tampering(registry, signing_keys):
    """Tampering with the checkpoint invalidates the packet hash verification."""
    checkpoint = _checkpoint(registry, signing_keys)
    announcement = WitnessAnnouncement.create(
        origin="node-b",
        checkpoint=checkpoint,
        observed_at="2024-01-01T00:00:00Z",
    )
    tampered = replace(
        announcement,
        checkpoint=replace(checkpoint, ledger_height=99),
    )

    assert not verify_announcement(tampered)


def test_dns_txt_record_is_deterministic(registry, signing_keys):
    """DNS TXT helper produces deterministic records that verify against checkpoints."""
    checkpoint = _checkpoint(registry, signing_keys)
    record = checkpoint_txt_record(checkpoint)
    assert verify_txt_record(record, checkpoint)

    payload = checkpoint_record_set(domain="example.gov", checkpoint=checkpoint)
    assert payload["txt"] == record
    assert payload["name"].startswith("oly-chk-0.example.gov")
