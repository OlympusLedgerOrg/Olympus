"""Tests for federation identity and quorum prototype helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from protocol.federation import (
    FederationNode,
    FederationRegistry,
    NodeSignature,
    append_quorum_certificate_to_ledger,
    build_federation_header_record,
    build_quorum_certificate,
    has_federation_quorum,
    sign_federated_header,
    verify_federated_header_signatures,
    verify_quorum_certificate,
)
from protocol.ledger import Ledger
from protocol.shards import (
    create_key_revocation_record,
    create_shard_header,
    create_superseding_signature,
    get_signing_key_from_seed,
    sign_header,
    verify_header_with_rotation,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "examples" / "federation_registry.json"


def _test_signing_key(seed_byte: int):
    """Return a deterministic test-only Ed25519 key for federation quorum tests."""
    return get_signing_key_from_seed(bytes([seed_byte]) * 32)


def test_federation_registry_loads_static_nodes() -> None:
    """Static federation registry should expose node identity metadata."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)

    assert len(registry.nodes) == 3
    assert registry.quorum_threshold() == 2
    assert registry.nodes[0] == FederationNode(
        node_id="olympus-node-1",
        pubkey=bytes.fromhex("10d7472a02f7338b0c7aeee1b81e447ee7c91081c2b190b89f05b7149ca934a7"),
        endpoint="https://node1.olympus.org",
        operator="City Records Office",
        jurisdiction="city-a",
        status="active",
    )


def test_federation_registry_rejects_duplicate_pubkeys() -> None:
    """Registry identity binding should reject pubkeys assigned to multiple node IDs."""
    shared_pubkey = _test_signing_key(1).verify_key.encode().hex()
    with pytest.raises(ValueError, match="pubkey"):
        FederationRegistry.from_dict(
            {
                "nodes": [
                    {
                        "node_id": "olympus-node-1",
                        "pubkey": shared_pubkey,
                        "endpoint": "https://node1.olympus.org",
                        "operator": "City Records Office",
                        "jurisdiction": "city-a",
                        "status": "active",
                    },
                    {
                        "node_id": "olympus-node-2",
                        "pubkey": shared_pubkey,
                        "endpoint": "https://node2.olympus.org",
                        "operator": "County Archive",
                        "jurisdiction": "county-b",
                        "status": "active",
                    },
                ]
            }
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
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1)),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2)),
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
        _test_signing_key(1),
    )
    wrong_header_signature = sign_federated_header(
        other_header,
        "olympus-node-2",
        _test_signing_key(2),
    )

    signatures = [duplicate_signature, duplicate_signature, wrong_header_signature]

    valid_signatures = verify_federated_header_signatures(header, signatures, registry)
    assert len(valid_signatures) == 1
    assert has_federation_quorum(header, signatures, registry) is False


def test_byzantine_simulation_partition_accepts_two_of_three_quorum() -> None:
    """A partition that still has 2/3 signatures should finalize the header."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("44" * 32),
        timestamp="2026-03-09T00:00:00Z",
    )

    # Simulate one node partitioned away while two nodes can still acknowledge.
    signatures = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1)),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2)),
    ]

    assert has_federation_quorum(header, signatures, registry) is True


def test_byzantine_simulation_mid_commit_node_kill_rejects_subquorum() -> None:
    """If a node dies mid-commit and only one signature remains, quorum must fail."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("55" * 32),
        timestamp="2026-03-09T00:00:01Z",
    )

    # Node 1 signs, then nodes 2 and 3 are unavailable/partitioned before ack.
    signatures = [sign_federated_header(header, "olympus-node-1", _test_signing_key(1))]

    assert has_federation_quorum(header, signatures, registry) is False


def test_quorum_certificate_is_verifiable_and_persisted_in_ledger() -> None:
    """Signed federation quorum certificates should be persisted as ledger metadata."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("66" * 32),
        timestamp="2026-03-09T00:00:02Z",
    )
    signatures = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1)),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2)),
    ]

    certificate = build_quorum_certificate(header, signatures, registry)
    assert verify_quorum_certificate(certificate, header, registry) is True

    ledger = Ledger()
    entry = append_quorum_certificate_to_ledger(
        ledger=ledger,
        header=header,
        signatures=signatures,
        registry=registry,
        canonicalization={"type": "federation-quorum.v1"},
    )
    assert entry.federation_quorum_certificate == certificate
    assert ledger.verify_chain() is True


def test_quorum_certificate_acknowledgments_are_canonicalized_for_determinism() -> None:
    """Quorum certificate signatures should be serialized in deterministic node-id order."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("99" * 32),
        timestamp="2026-03-09T00:00:03Z",
    )
    signatures = [
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2)),
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1)),
    ]

    certificate = build_quorum_certificate(header, signatures, registry)

    assert [ack["node_id"] for ack in certificate["acknowledgments"]] == [
        "olympus-node-1",
        "olympus-node-2",
    ]


def test_verify_quorum_certificate_ignores_duplicate_acknowledgments() -> None:
    """Duplicate acknowledgments should be filtered before signature validation."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("aa" * 32),
        timestamp="2026-03-09T00:00:04Z",
    )
    signature_one = sign_federated_header(header, "olympus-node-1", _test_signing_key(1))
    signature_two = sign_federated_header(header, "olympus-node-2", _test_signing_key(2))
    certificate = {
        "shard_id": header["shard_id"],
        "header_hash": header["header_hash"],
        "timestamp": header["timestamp"],
        "event_id": build_quorum_certificate(header, [signature_one, signature_two], registry)[
            "event_id"
        ],
        "quorum_threshold": registry.quorum_threshold(),
        "acknowledgments": [
            signature_one.to_dict(),
            signature_one.to_dict(),
            signature_two.to_dict(),
        ],
    }

    assert verify_quorum_certificate(certificate, header, registry) is True


def test_federation_signature_is_domain_separated_from_plain_header_signature() -> None:
    """Plain shard-header signatures must not verify as federation votes."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("bb" * 32),
        timestamp="2026-03-09T00:00:05Z",
    )
    plain_signature = NodeSignature(
        node_id="olympus-node-1",
        signature=sign_header(header, _test_signing_key(1)),
    )

    assert verify_federated_header_signatures(header, [plain_signature], registry) == []


def test_verify_quorum_certificate_rejects_event_id_replay() -> None:
    """Event identifier mismatches must invalidate quorum certificates."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("cc" * 32),
        timestamp="2026-03-09T00:00:06Z",
    )
    signatures = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1)),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2)),
    ]
    certificate = build_quorum_certificate(header, signatures, registry)
    replayed_certificate = {**certificate, "event_id": "00" * 32}

    assert verify_quorum_certificate(replayed_certificate, header, registry) is False


def test_node_key_rotation_with_superseding_signature() -> None:
    """Compromised node key rotation should preserve old-header verification via supersession."""
    old_key = _test_signing_key(1)
    new_key = _test_signing_key(9)
    old_verify_key = old_key.verify_key

    pre_compromise_header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("77" * 32),
        timestamp="2026-03-01T00:00:00Z",
    )
    pre_compromise_sig = sign_header(pre_compromise_header, old_key)
    assert (
        verify_header_with_rotation(pre_compromise_header, pre_compromise_sig, old_verify_key)
        is True
    )

    revocation = create_key_revocation_record(
        old_verify_key=old_verify_key,
        new_signing_key=new_key,
        compromise_timestamp="2026-03-02T00:00:00Z",
        last_good_sequence=10,
    )

    post_compromise_header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("88" * 32),
        timestamp="2026-03-03T00:00:00Z",
    )
    post_compromise_sig = sign_header(post_compromise_header, old_key)
    assert (
        verify_header_with_rotation(
            post_compromise_header,
            post_compromise_sig,
            old_verify_key,
            header_sequence=11,
            revocation_record=revocation,
        )
        is False
    )

    superseding = create_superseding_signature(
        header_hash=post_compromise_header["header_hash"],
        old_verify_key=old_verify_key,
        new_signing_key=new_key,
        supersedes_from=revocation["compromise_timestamp"],
    )
    assert (
        verify_header_with_rotation(
            post_compromise_header,
            post_compromise_sig,
            old_verify_key,
            header_sequence=11,
            revocation_record=revocation,
            superseding_signature=superseding,
        )
        is True
    )
