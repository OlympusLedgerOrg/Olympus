"""Tests for federation identity and quorum prototype helpers."""

from __future__ import annotations

from pathlib import Path

from protocol.federation import (
    FederationNode,
    FederationRegistry,
    build_federation_header_record,
    has_federation_quorum,
    sign_federated_header,
    verify_federated_header_signatures,
)
from protocol.shards import create_shard_header, get_signing_key_from_seed


REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "examples" / "federation_registry.json"


def test_federation_registry_loads_static_nodes() -> None:
    """Static federation registry should expose node identity metadata."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)

    assert len(registry.nodes) == 3
    assert registry.quorum_threshold() == 2
    assert registry.nodes[0] == FederationNode(
        node_id="olympus-node-1",
        pubkey=bytes.fromhex("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"),
        endpoint="https://node1.olympus.org",
        operator="City Records Office",
        jurisdiction="city-a",
        status="active",
    )


def test_federated_shard_header_reaches_quorum_with_two_of_three_signatures() -> None:
    """Two valid signatures out of three active nodes satisfy the >=2/3 prototype quorum."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("11" * 32),
        timestamp="2026-03-08T17:09:10Z",
    )

    signatures = [
        sign_federated_header(header, "olympus-node-1", get_signing_key_from_seed(bytes([1]) * 32)),
        sign_federated_header(header, "olympus-node-2", get_signing_key_from_seed(bytes([2]) * 32)),
    ]

    valid_signatures = verify_federated_header_signatures(header, signatures, registry)

    assert len(valid_signatures) == 2
    assert has_federation_quorum(header, signatures, registry) is True

    federation_record = build_federation_header_record(header, valid_signatures)
    assert federation_record["state_root"] == header["root_hash"]
    assert len(federation_record["node_signatures"]) == 2


def test_federated_quorum_rejects_invalid_or_duplicate_signatures() -> None:
    """Duplicate node ids and invalid signatures should not count toward quorum."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("22" * 32),
        timestamp="2026-03-08T17:09:10Z",
    )
    other_header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("33" * 32),
        timestamp="2026-03-08T17:09:11Z",
    )

    duplicate_signature = sign_federated_header(
        header,
        "olympus-node-1",
        get_signing_key_from_seed(bytes([1]) * 32),
    )
    wrong_header_signature = sign_federated_header(
        other_header,
        "olympus-node-2",
        get_signing_key_from_seed(bytes([2]) * 32),
    )

    signatures = [duplicate_signature, duplicate_signature, wrong_header_signature]

    valid_signatures = verify_federated_header_signatures(header, signatures, registry)
    assert len(valid_signatures) == 1
    assert has_federation_quorum(header, signatures, registry) is False
