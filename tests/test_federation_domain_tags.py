"""Tests for federation domain tags, event IDs, and registry bindings."""

from __future__ import annotations

from protocol.hashes import (
    EVENT_PREFIX,
    FEDERATION_PREFIX,
    HASH_SEPARATOR,
    blake3_hash,
    event_id,
    federation_vote_hash,
)
from protocol.shards import create_shard_header, get_signing_key_from_seed


def test_event_id_is_deterministic_and_includes_domain_prefix() -> None:
    """Event IDs should be deterministic and include domain separation."""
    shard_id = "records/test"
    header_hash = "a" * 64
    timestamp = "2026-03-09T00:00:00Z"

    event_id_1 = event_id(shard_id, header_hash, timestamp)
    event_id_2 = event_id(shard_id, header_hash, timestamp)

    # Event IDs should be deterministic
    assert event_id_1 == event_id_2

    # Event IDs should be hex-encoded (64 hex chars = 32 bytes)
    assert len(event_id_1) == 64
    assert all(c in "0123456789abcdef" for c in event_id_1)

    # Different inputs should produce different event IDs
    different_shard_id = event_id("records/different", header_hash, timestamp)
    different_header = event_id(shard_id, "b" * 64, timestamp)
    different_timestamp = event_id(shard_id, header_hash, "2026-03-10T00:00:00Z")

    assert event_id_1 != different_shard_id
    assert event_id_1 != different_header
    assert event_id_1 != different_timestamp


def test_event_id_binds_to_shard_header_and_timestamp() -> None:
    """Event IDs should bind signatures to specific shard header events."""
    # Create two headers with different content
    header1 = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("11" * 32),
        timestamp="2026-03-09T00:00:00Z",
    )
    header2 = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("22" * 32),
        timestamp="2026-03-09T00:00:00Z",
    )

    event_id_1 = event_id(header1["shard_id"], header1["header_hash"], header1["timestamp"])
    event_id_2 = event_id(header2["shard_id"], header2["header_hash"], header2["timestamp"])

    # Different headers should have different event IDs
    assert event_id_1 != event_id_2


def test_event_id_prevents_field_injection() -> None:
    """Length-prefixing prevents '|' injection collisions across event_id fields."""
    timestamp = "2026-03-09T00:00:00Z"

    def legacy_event_id(shard_id: str, header_hash: str) -> str:
        event_data = HASH_SEPARATOR.join([shard_id, header_hash, timestamp])
        return blake3_hash([EVENT_PREFIX, b"|", event_data.encode("utf-8")]).hex()

    colliding_legacy = legacy_event_id("X|Y", "Z")
    assert colliding_legacy == legacy_event_id("X", "Y|Z")

    secure_a = event_id("X|Y", "Z", timestamp)
    secure_b = event_id("X", "Y|Z", timestamp)
    assert secure_a != secure_b


def test_federation_vote_hash_includes_all_required_fields() -> None:
    """Federation vote hashes should include domain, node_id, shard_id, header_hash, timestamp, and event_id."""
    node_id = "test-node-1"
    shard_id = "records/test"
    header_hash = "a" * 64
    timestamp = "2026-03-09T00:00:00Z"
    event_id_hex = event_id(shard_id, header_hash, timestamp)

    vote_hash = federation_vote_hash(node_id, shard_id, header_hash, timestamp, event_id_hex)

    # Vote hash should be 32 bytes (BLAKE3 output)
    assert len(vote_hash) == 32

    # Different node_id should produce different hash (registry binding)
    different_node_hash = federation_vote_hash(
        "test-node-2", shard_id, header_hash, timestamp, event_id_hex
    )
    assert vote_hash != different_node_hash


def test_federation_vote_hash_is_deterministic() -> None:
    """Federation vote hashes should be deterministic for the same inputs."""
    node_id = "test-node-1"
    shard_id = "records/test"
    header_hash = "a" * 64
    timestamp = "2026-03-09T00:00:00Z"
    event_id_hex = event_id(shard_id, header_hash, timestamp)

    vote_hash_1 = federation_vote_hash(node_id, shard_id, header_hash, timestamp, event_id_hex)
    vote_hash_2 = federation_vote_hash(node_id, shard_id, header_hash, timestamp, event_id_hex)

    assert vote_hash_1 == vote_hash_2


def test_federation_vote_hash_prevents_field_injection() -> None:
    """Length-prefixing prevents '|' injection collisions across fields."""
    header_hash = "a" * 64
    timestamp = "2026-03-09T00:00:00Z"
    event_id_hex = "deadbeef"

    def legacy_vote_hash(node_id: str, shard_id: str) -> bytes:
        vote_data = HASH_SEPARATOR.join(
            ["olympus.federation.v1", node_id, shard_id, header_hash, timestamp, event_id_hex]
        )
        return blake3_hash([FEDERATION_PREFIX, b"|", vote_data.encode("utf-8")])

    colliding_legacy = legacy_vote_hash("node|A", "shard")
    assert colliding_legacy == legacy_vote_hash("node", "A|shard")

    secure_a = federation_vote_hash("node|A", "shard", header_hash, timestamp, event_id_hex)
    secure_b = federation_vote_hash("node", "A|shard", header_hash, timestamp, event_id_hex)
    assert secure_a != secure_b


def test_federation_signatures_bind_to_node_id() -> None:
    """Federation signatures should be bound to the specific node_id (registry binding)."""
    # Create a test registry with two nodes
    from protocol.federation import (
        FederationNode,
        FederationRegistry,
        sign_federated_header,
        verify_federated_header_signatures,
    )

    key1 = get_signing_key_from_seed(bytes([1]) * 32)
    key2 = get_signing_key_from_seed(bytes([2]) * 32)

    registry = FederationRegistry(
        nodes=(
            FederationNode(
                node_id="node-1",
                pubkey=bytes(key1.verify_key),
                endpoint="https://node1.example.com",
                operator="Operator 1",
                jurisdiction="test",
                status="active",
            ),
            FederationNode(
                node_id="node-2",
                pubkey=bytes(key2.verify_key),
                endpoint="https://node2.example.com",
                operator="Operator 2",
                jurisdiction="test",
                status="active",
            ),
        )
    )

    header = create_shard_header(
        shard_id="records/test",
        root_hash=bytes.fromhex("11" * 32),
        timestamp="2026-03-09T00:00:00Z",
    )

    # Sign with node-1's key and node_id
    sig1 = sign_federated_header(header, "node-1", key1, registry)

    # The signature should verify when node_id matches
    valid_sigs = verify_federated_header_signatures(header, [sig1], registry)
    assert len(valid_sigs) == 1

    # Create a signature with the wrong node_id but correct key
    # (This simulates a node trying to impersonate another node)
    sig_wrong_id = sign_federated_header(header, "node-2", key1, registry)

    # This should fail verification because the pubkey doesn't match node-2's registry entry
    valid_sigs = verify_federated_header_signatures(header, [sig_wrong_id], registry)
    assert len(valid_sigs) == 0


def test_domain_prefix_constants_are_immutable() -> None:
    """Domain prefixes should be protocol-critical constants."""
    # These values are hardcoded in the protocol and must never change
    assert FEDERATION_PREFIX == b"OLY:FEDERATION:V1"
    assert EVENT_PREFIX == b"OLY:EVENT:V1"

    # Verify they are used correctly in hash computations
    assert isinstance(HASH_SEPARATOR, str)
    assert HASH_SEPARATOR == "|"


def test_signature_replay_protection_via_event_id() -> None:
    """Event IDs should prevent signature replay across different headers."""
    from protocol.federation import FederationNode, FederationRegistry, sign_federated_header

    key = get_signing_key_from_seed(bytes([1]) * 32)
    registry = FederationRegistry(
        nodes=(
            FederationNode(
                node_id="test-node",
                pubkey=bytes(key.verify_key),
                endpoint="https://node1.example.com",
                operator="Operator 1",
                jurisdiction="test",
                status="active",
            ),
        )
    )

    # Create two different headers with same timestamp
    header1 = create_shard_header(
        shard_id="records/test",
        root_hash=bytes.fromhex("11" * 32),
        timestamp="2026-03-09T00:00:00Z",
    )
    header2 = create_shard_header(
        shard_id="records/test",
        root_hash=bytes.fromhex("22" * 32),
        timestamp="2026-03-09T00:00:00Z",
    )

    # Sign both headers
    sig1 = sign_federated_header(header1, "test-node", key, registry)
    sig2 = sign_federated_header(header2, "test-node", key, registry)

    # Signatures should be different because event IDs are different
    assert sig1.signature != sig2.signature

    # Event IDs should be different
    event_id_1 = event_id(header1["shard_id"], header1["header_hash"], header1["timestamp"])
    event_id_2 = event_id(header2["shard_id"], header2["header_hash"], header2["timestamp"])
    assert event_id_1 != event_id_2


def test_cross_shard_signature_isolation() -> None:
    """Signatures should be bound to specific shards via event_id."""
    # Create headers for different shards with same root and timestamp
    header_shard_a = create_shard_header(
        shard_id="records/shard-a",
        root_hash=bytes.fromhex("11" * 32),
        timestamp="2026-03-09T00:00:00Z",
    )
    header_shard_b = create_shard_header(
        shard_id="records/shard-b",
        root_hash=bytes.fromhex("11" * 32),
        timestamp="2026-03-09T00:00:00Z",
    )

    # Event IDs should be different even with same root_hash and timestamp
    event_id_a = event_id(
        header_shard_a["shard_id"],
        header_shard_a["header_hash"],
        header_shard_a["timestamp"],
    )
    event_id_b = event_id(
        header_shard_b["shard_id"],
        header_shard_b["header_hash"],
        header_shard_b["timestamp"],
    )

    assert event_id_a != event_id_b
