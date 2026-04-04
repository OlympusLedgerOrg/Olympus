"""Gap-filling tests for federation key rotation.

Covers edge cases for FederationRegistry.rotate_node_key:
  - Unknown node_id rejection
  - Same-pubkey rotation rejection
"""

from __future__ import annotations

from pathlib import Path

import pytest

from protocol.federation import FederationRegistry
from protocol.shards import get_signing_key_from_seed


REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "examples" / "federation_registry.json"


def _test_signing_key(seed_byte: int):
    return get_signing_key_from_seed(bytes([seed_byte]) * 32)


def _three_node_registry() -> FederationRegistry:
    return FederationRegistry.from_file(REGISTRY_PATH)


# =============================================================================
# FederationRegistry.rotate_node_key edge cases
# =============================================================================


def test_rotate_node_key_raises_on_unknown_node_id() -> None:
    """rotate_node_key must raise ValueError when the node_id does not exist in the registry."""
    registry = _three_node_registry()

    with pytest.raises(ValueError, match="Unknown federation node"):
        registry.rotate_node_key(
            node_id="olympus-node-999",  # does not exist
            new_pubkey=_test_signing_key(9).verify_key.encode(),
            rotated_at="2026-03-15T00:00:00Z",
        )


def test_rotate_node_key_raises_on_same_pubkey() -> None:
    """rotate_node_key must reject a rotation to the same public key."""
    registry = _three_node_registry()
    same_key = _test_signing_key(1).verify_key.encode()

    with pytest.raises(ValueError, match="must differ from current pubkey"):
        registry.rotate_node_key(
            node_id="olympus-node-1",
            new_pubkey=same_key,
            rotated_at="2026-03-15T00:00:00Z",
        )
