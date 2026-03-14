"""Tests for federation identity and quorum prototype helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from protocol.canonical_json import canonical_json_bytes
from protocol.federation import (
    DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS,
    FEDERATION_DOMAIN_TAG,
    DataAvailabilityChallenge,
    EpochKeyRotationRecord,
    FederationBehaviorSample,
    FederationFinalityStatus,
    FederationNode,
    FederationRegistry,
    FederationVoteMessage,
    GossipedShardHeader,
    NodeSignature,
    RecursiveChainProof,
    ShardHeaderForkEvidence,
    _to_int,
    append_quorum_certificate_to_ledger,
    build_federation_header_record,
    build_proactive_share_commitments,
    build_quorum_certificate,
    create_replication_proof,
    detect_compromise_signals,
    detect_shard_header_forks,
    has_federation_quorum,
    is_replay_epoch,
    quorum_certificate_hash,
    registry_forest_commitment,
    resolve_canonical_fork,
    serialize_vote_message,
    sign_federated_header,
    verify_data_availability,
    verify_epoch_key_rotation,
    verify_federated_header_signatures,
    verify_proactive_share_commitments,
    verify_quorum_certificate,
    verify_recursive_chain_proof,
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


def test_to_int_helper_converts_and_rejects_invalid() -> None:
    assert _to_int("5") == 5
    assert _to_int(7) == 7
    assert _to_int(None) is None
    assert _to_int("not-a-number") is None


def test_federation_registry_loads_static_nodes() -> None:
    """Static federation registry should expose node identity metadata."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)

    assert len(registry.nodes) == 3
    assert registry.quorum_threshold() == 2
    assert registry.nodes[0] == FederationNode(
        node_id="olympus-node-1",
        pubkey=bytes.fromhex("3e86f08f516951ff0c69815cfc4ed7cf1f0b44651aa5c7472f67623449c09425"),
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
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
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
        header, "olympus-node-1", _test_signing_key(1), registry
    )
    wrong_header_signature = sign_federated_header(
        other_header,
        "olympus-node-2",
        _test_signing_key(2),
        registry,
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
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
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
    signatures = [sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry)]

    assert has_federation_quorum(header, signatures, registry) is False


def test_byzantine_threshold_for_four_nodes_requires_three_signatures() -> None:
    """2/3 quorum should require three signatures when four active nodes are present."""
    registry = FederationRegistry.from_dict(
        {
            "nodes": [
                {
                    "node_id": "olympus-node-1",
                    "pubkey": _test_signing_key(1).verify_key.encode().hex(),
                    "endpoint": "https://node1.olympus.org",
                    "operator": "City Records Office",
                    "jurisdiction": "city-a",
                    "status": "active",
                },
                {
                    "node_id": "olympus-node-2",
                    "pubkey": _test_signing_key(2).verify_key.encode().hex(),
                    "endpoint": "https://node2.olympus.org",
                    "operator": "County Archive",
                    "jurisdiction": "county-b",
                    "status": "active",
                },
                {
                    "node_id": "olympus-node-3",
                    "pubkey": _test_signing_key(3).verify_key.encode().hex(),
                    "endpoint": "https://node3.olympus.org",
                    "operator": "State Auditor",
                    "jurisdiction": "state-c",
                    "status": "active",
                },
                {
                    "node_id": "olympus-node-4",
                    "pubkey": _test_signing_key(4).verify_key.encode().hex(),
                    "endpoint": "https://node4.olympus.org",
                    "operator": "Regional Clerk",
                    "jurisdiction": "region-d",
                    "status": "active",
                },
            ]
        }
    )
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("56" * 32),
        timestamp="2026-03-09T00:00:01Z",
    )

    two_signatures = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
    ]
    three_signatures = [
        *two_signatures,
        sign_federated_header(header, "olympus-node-3", _test_signing_key(3), registry),
    ]

    assert registry.quorum_threshold() == 3
    assert has_federation_quorum(header, two_signatures, registry) is False
    assert has_federation_quorum(header, three_signatures, registry) is True


def test_federated_vote_signatures_bind_round_and_height() -> None:
    """Votes must be bound to the consensus round and height metadata."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("57" * 32),
        timestamp="2026-03-09T00:00:01Z",
        height=7,
        round_number=3,
    )
    mismatched_round_header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("57" * 32),
        timestamp="2026-03-09T00:00:01Z",
        height=7,
        round_number=4,
    )

    signature = sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry)

    assert verify_federated_header_signatures(header, [signature], registry) != []
    assert verify_federated_header_signatures(mismatched_round_header, [signature], registry) == []


def test_quorum_certificate_is_verifiable_and_persisted_in_ledger() -> None:
    """Signed federation quorum certificates should be persisted as ledger metadata."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("66" * 32),
        timestamp="2026-03-09T00:00:02Z",
    )
    signatures = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
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


def test_federation_node_key_rotation_preserves_historical_quorum_verification() -> None:
    """Node key rotation should keep pre-rotation signatures verifiable via key history."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    old_node_one_key = _test_signing_key(1)
    new_node_one_key = _test_signing_key(9)
    rotated_registry = registry.rotate_node_key(
        node_id="olympus-node-1",
        new_pubkey=bytes(new_node_one_key.verify_key),
        rotated_at="2026-03-10T00:00:00Z",
    )

    historical_header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("6f" * 32),
        timestamp="2026-03-09T23:59:59Z",
    )
    historical_signatures = [
        sign_federated_header(
            historical_header, "olympus-node-1", old_node_one_key, rotated_registry
        ),
        sign_federated_header(
            historical_header, "olympus-node-2", _test_signing_key(2), rotated_registry
        ),
    ]

    assert has_federation_quorum(historical_header, historical_signatures, rotated_registry) is True


def test_federation_node_key_rotation_rejects_post_rotation_old_key_signatures() -> None:
    """After key rotation, old compromised keys must not satisfy quorum for new headers."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    old_node_one_key = _test_signing_key(1)
    new_node_one_key = _test_signing_key(9)
    rotated_registry = registry.rotate_node_key(
        node_id="olympus-node-1",
        new_pubkey=bytes(new_node_one_key.verify_key),
        rotated_at="2026-03-10T00:00:00Z",
    )
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("7f" * 32),
        timestamp="2026-03-10T00:00:01Z",
    )

    old_key_signatures = [
        sign_federated_header(header, "olympus-node-1", old_node_one_key, rotated_registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), rotated_registry),
    ]
    assert has_federation_quorum(header, old_key_signatures, rotated_registry) is False

    rotated_key_signatures = [
        sign_federated_header(header, "olympus-node-1", new_node_one_key, rotated_registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), rotated_registry),
    ]
    assert has_federation_quorum(header, rotated_key_signatures, rotated_registry) is True


def test_quorum_certificate_signatures_are_canonicalized_for_determinism() -> None:
    """Quorum certificate signatures should be serialized in deterministic node-id order."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("99" * 32),
        timestamp="2026-03-09T00:00:03Z",
    )
    signatures = [
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
    ]

    certificate = build_quorum_certificate(header, signatures, registry)

    assert certificate["scheme"] == "ed25519"
    assert [signature["node_id"] for signature in certificate["signatures"]] == [
        "olympus-node-1",
        "olympus-node-2",
    ]
    active_node_ids = sorted(node.node_id for node in registry.active_nodes())
    expected_bitmap = "".join(
        "1" if node_id in {"olympus-node-1", "olympus-node-2"} else "0"
        for node_id in active_node_ids
    )
    assert certificate["signer_bitmap"] == expected_bitmap


def test_verify_quorum_certificate_rejects_duplicate_signatures() -> None:
    """Duplicate signatures should invalidate canonical bitmap ordering."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("aa" * 32),
        timestamp="2026-03-09T00:00:04Z",
    )
    signature_one = sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry)
    signature_two = sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry)
    active_node_ids = sorted(node.node_id for node in registry.active_nodes())
    signer_bitmap = "".join(
        "1" if node_id in {"olympus-node-1", "olympus-node-2"} else "0"
        for node_id in active_node_ids
    )
    certificate = {
        "shard_id": header["shard_id"],
        "height": header["height"],
        "round": header["round"],
        "header_hash": header["header_hash"],
        "timestamp": header["timestamp"],
        "event_id": build_quorum_certificate(header, [signature_one, signature_two], registry)[
            "event_id"
        ],
        "federation_epoch": registry.epoch,
        "membership_hash": registry.membership_hash(),
        "validator_set_hash": registry.membership_hash(),
        "validator_count": len(registry.active_nodes()),
        "quorum_threshold": registry.quorum_threshold(),
        "scheme": "ed25519",
        "signer_bitmap": signer_bitmap,
        "signatures": [
            signature_one.to_dict(),
            signature_one.to_dict(),
            signature_two.to_dict(),
        ],
    }
    header["quorum_certificate_hash"] = quorum_certificate_hash(certificate)
    assert verify_quorum_certificate(certificate, header, registry) is False


def test_verify_quorum_certificate_rejects_conflicting_duplicate_node_votes() -> None:
    """A node must not contribute multiple conflicting signatures in one round."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("ab" * 32),
        timestamp="2026-03-09T00:00:04Z",
    )
    signature_one = sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry)
    signature_two = sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry)
    conflicting_signature_one = sign_federated_header(
        header,
        "olympus-node-1",
        _test_signing_key(9),
        registry,
    )
    active_node_ids = sorted(node.node_id for node in registry.active_nodes())
    signer_bitmap = "".join(
        "1" if node_id in {"olympus-node-1", "olympus-node-2"} else "0"
        for node_id in active_node_ids
    )
    certificate = {
        "shard_id": header["shard_id"],
        "height": header["height"],
        "round": header["round"],
        "header_hash": header["header_hash"],
        "timestamp": header["timestamp"],
        "event_id": build_quorum_certificate(header, [signature_one, signature_two], registry)[
            "event_id"
        ],
        "federation_epoch": registry.epoch,
        "membership_hash": registry.membership_hash(),
        "validator_set_hash": registry.membership_hash(),
        "validator_count": len(registry.active_nodes()),
        "quorum_threshold": registry.quorum_threshold(),
        "scheme": "ed25519",
        "signer_bitmap": signer_bitmap,
        "signatures": [
            signature_one.to_dict(),
            conflicting_signature_one.to_dict(),
            signature_two.to_dict(),
        ],
    }

    header["quorum_certificate_hash"] = quorum_certificate_hash(certificate)
    assert verify_quorum_certificate(certificate, header, registry) is False


def test_verify_quorum_certificate_rejects_signer_bitmap_mismatch() -> None:
    """Signer bitmap must match the exact signer set represented in signatures."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("ac" * 32),
        timestamp="2026-03-09T00:00:04Z",
    )
    signatures = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
    ]
    certificate = build_quorum_certificate(header, signatures, registry)
    first_bit = certificate["signer_bitmap"][0]
    flipped_first_bit = "0" if first_bit == "1" else "1"
    tampered_certificate = {
        **certificate,
        "signer_bitmap": flipped_first_bit + certificate["signer_bitmap"][1:],
    }

    header["quorum_certificate_hash"] = quorum_certificate_hash(tampered_certificate)
    assert verify_quorum_certificate(tampered_certificate, header, registry) is False


def test_verify_quorum_certificate_rejects_noncanonical_signature_order() -> None:
    """Signature order must follow canonical bitmap indexing of active nodes."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("ad" * 32),
        timestamp="2026-03-09T00:00:04Z",
    )
    signature_one = sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry)
    signature_two = sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry)

    canonical_certificate = build_quorum_certificate(
        header, [signature_one, signature_two], registry
    )
    header["quorum_certificate_hash"] = quorum_certificate_hash(canonical_certificate)
    swapped_certificate = {
        **canonical_certificate,
        "signatures": [
            signature_two.to_dict(),
            signature_one.to_dict(),
        ],
    }

    assert verify_quorum_certificate(canonical_certificate, header, registry) is True
    header["quorum_certificate_hash"] = quorum_certificate_hash(swapped_certificate)
    assert verify_quorum_certificate(swapped_certificate, header, registry) is False


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
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
    ]
    certificate = build_quorum_certificate(header, signatures, registry)
    replayed_certificate = {**certificate, "event_id": "00" * 32}

    header["quorum_certificate_hash"] = quorum_certificate_hash(replayed_certificate)
    assert verify_quorum_certificate(replayed_certificate, header, registry) is False


def test_verify_quorum_certificate_rejects_membership_hash_mismatch() -> None:
    """Certificates must be bound to the registry membership commitment."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("dd" * 32),
        timestamp="2026-03-09T00:00:07Z",
    )
    signatures = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
    ]
    certificate = build_quorum_certificate(header, signatures, registry)
    tampered_certificate = {**certificate, "membership_hash": "00" * 32}

    header["quorum_certificate_hash"] = quorum_certificate_hash(tampered_certificate)
    assert verify_quorum_certificate(tampered_certificate, header, registry) is False


def test_verify_quorum_certificate_rejects_validator_set_hash_mismatch() -> None:
    """Certificates must include the validator_set_hash binding."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("de" * 32),
        timestamp="2026-03-09T00:00:07Z",
    )
    signatures = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
    ]
    certificate = build_quorum_certificate(header, signatures, registry)
    tampered_certificate = {**certificate, "validator_set_hash": "ff" * 32}

    header["quorum_certificate_hash"] = quorum_certificate_hash(tampered_certificate)
    assert verify_quorum_certificate(tampered_certificate, header, registry) is False


def test_verify_quorum_certificate_rejects_epoch_mismatch() -> None:
    """Certificates must be bound to the federation epoch."""
    base_registry = FederationRegistry.from_file(REGISTRY_PATH)
    registry = FederationRegistry(nodes=base_registry.nodes, epoch=7)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("ee" * 32),
        timestamp="2026-03-09T00:00:08Z",
    )
    signatures = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
    ]
    certificate = build_quorum_certificate(header, signatures, registry)
    tampered_certificate = {**certificate, "federation_epoch": registry.epoch + 1}

    header["quorum_certificate_hash"] = quorum_certificate_hash(tampered_certificate)
    assert verify_quorum_certificate(tampered_certificate, header, registry) is False


def test_verify_quorum_certificate_uses_epoch_snapshot() -> None:
    """Verification should use registry snapshot for the certificate epoch."""
    base_registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("ef" * 32),
        timestamp="2026-03-10T00:00:00Z",
    )
    signatures = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), base_registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), base_registry),
    ]
    certificate = build_quorum_certificate(header, signatures, base_registry)
    header["quorum_certificate_hash"] = quorum_certificate_hash(certificate)

    future_registry = FederationRegistry(
        nodes=tuple(
            [
                *base_registry.nodes,
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
        snapshots={0: base_registry},
    )

    assert verify_quorum_certificate(certificate, header, future_registry) is True


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


# ---------------------------------------------------------------------------
# FederationVoteMessage, serialize_vote_message, FEDERATION_DOMAIN_TAG tests
# ---------------------------------------------------------------------------


def test_federation_domain_tag_constant_matches_expected_value() -> None:
    """FEDERATION_DOMAIN_TAG must equal the wire-protocol value."""
    assert FEDERATION_DOMAIN_TAG == "OLY:FEDERATION-VOTE:V1"


def test_federation_vote_message_is_frozen_dataclass() -> None:
    """FederationVoteMessage instances must be immutable."""
    msg = FederationVoteMessage(
        domain=FEDERATION_DOMAIN_TAG,
        node_id="test-node",
        event_id="e" * 64,
        shard_id="records/test",
        entry_seq=1,
        round_number=0,
        shard_root="a" * 64,
        timestamp="2026-03-10T00:00:00Z",
        epoch=0,
        validator_set_hash="b" * 64,
    )
    with pytest.raises((AttributeError, TypeError)):
        msg.node_id = "tampered"  # type: ignore[misc]


def test_serialize_vote_message_produces_canonical_json_bytes() -> None:
    """serialize_vote_message must return valid canonical JSON bytes."""
    msg = FederationVoteMessage(
        domain=FEDERATION_DOMAIN_TAG,
        node_id="node-1",
        event_id="e" * 64,
        shard_id="records/city-a",
        entry_seq=42,
        round_number=3,
        shard_root="a" * 64,
        timestamp="2026-03-10T00:00:00Z",
        epoch=1,
        validator_set_hash="b" * 64,
    )
    result = serialize_vote_message(msg)
    assert isinstance(result, bytes)
    # Must round-trip through canonical JSON
    expected = canonical_json_bytes(
        {
            "domain": FEDERATION_DOMAIN_TAG,
            "entry_seq": 42,
            "epoch": 1,
            "event_id": "e" * 64,
            "node_id": "node-1",
            "round_number": 3,
            "shard_id": "records/city-a",
            "shard_root": "a" * 64,
            "timestamp": "2026-03-10T00:00:00Z",
            "validator_set_hash": "b" * 64,
        }
    )
    assert result == expected


def test_serialize_vote_message_is_deterministic() -> None:
    """serialize_vote_message must produce identical bytes on repeated calls."""
    msg = FederationVoteMessage(
        domain=FEDERATION_DOMAIN_TAG,
        node_id="node-1",
        event_id="e" * 64,
        shard_id="records/city-a",
        entry_seq=1,
        round_number=0,
        shard_root="a" * 64,
        timestamp="2026-03-10T00:00:00Z",
        epoch=0,
        validator_set_hash="b" * 64,
    )
    assert serialize_vote_message(msg) == serialize_vote_message(msg)


def test_serialize_vote_message_differs_for_different_node_ids() -> None:
    """Changing node_id must produce different canonical bytes."""
    common_fields = dict(
        domain=FEDERATION_DOMAIN_TAG,
        event_id="e" * 64,
        shard_id="records/city-a",
        entry_seq=1,
        round_number=0,
        shard_root="a" * 64,
        timestamp="2026-03-10T00:00:00Z",
        epoch=0,
        validator_set_hash="b" * 64,
    )
    msg1 = FederationVoteMessage(
        node_id="node-1",
        domain=common_fields["domain"],
        event_id=common_fields["event_id"],
        shard_id=common_fields["shard_id"],
        entry_seq=common_fields["entry_seq"],
        round_number=common_fields["round_number"],
        shard_root=common_fields["shard_root"],
        timestamp=common_fields["timestamp"],
        epoch=common_fields["epoch"],
        validator_set_hash=common_fields["validator_set_hash"],
    )
    msg2 = FederationVoteMessage(
        node_id="node-2",
        domain=common_fields["domain"],
        event_id=common_fields["event_id"],
        shard_id=common_fields["shard_id"],
        entry_seq=common_fields["entry_seq"],
        round_number=common_fields["round_number"],
        shard_root=common_fields["shard_root"],
        timestamp=common_fields["timestamp"],
        epoch=common_fields["epoch"],
        validator_set_hash=common_fields["validator_set_hash"],
    )
    assert serialize_vote_message(msg1) != serialize_vote_message(msg2)


def test_serialize_vote_message_embeds_domain_tag() -> None:
    """The canonical bytes must contain the domain tag string."""
    msg = FederationVoteMessage(
        domain=FEDERATION_DOMAIN_TAG,
        node_id="node-1",
        event_id="e" * 64,
        shard_id="records/city-a",
        entry_seq=1,
        round_number=0,
        shard_root="a" * 64,
        timestamp="2026-03-10T00:00:00Z",
        epoch=0,
        validator_set_hash="b" * 64,
    )
    serialized = serialize_vote_message(msg)
    assert FEDERATION_DOMAIN_TAG.encode("utf-8") in serialized


def test_sign_and_verify_uses_canonical_vote_message() -> None:
    """sign_federated_header and verify round-trip through FederationVoteMessage."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("f1" * 32),
        timestamp="2026-03-10T12:00:00Z",
    )
    key = _test_signing_key(1)
    sig = sign_federated_header(header, "olympus-node-1", key, registry)
    valid = verify_federated_header_signatures(header, [sig], registry)
    assert len(valid) == 1
    assert valid[0].node_id == "olympus-node-1"


def test_verify_quorum_certificate_uses_registry_for_key_lookup() -> None:
    """verify_quorum_certificate must reject a tampered node_id that is not in the registry."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("f2" * 32),
        timestamp="2026-03-10T12:01:00Z",
    )
    sig1 = sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry)
    sig2 = sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry)
    certificate = build_quorum_certificate(header, [sig1, sig2], registry)

    # Tamper the node_id in one of the serialized signatures to a non-existent node
    tampered_signatures = list(certificate["signatures"])
    tampered_signatures[0] = {
        "node_id": "unknown-node",
        "signature": tampered_signatures[0]["signature"],
    }
    tampered_certificate = {**certificate, "signatures": tampered_signatures}

    assert verify_quorum_certificate(tampered_certificate, header, registry) is False


def test_verify_quorum_certificate_unique_nodes_counted_for_quorum() -> None:
    """verify_quorum_certificate must reject a bitmap with the same node appearing twice."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("f3" * 32),
        timestamp="2026-03-10T12:02:00Z",
    )
    sig1 = sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry)
    sig2 = sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry)
    certificate = build_quorum_certificate(header, [sig1, sig2], registry)

    # The bitmap already enforces one slot per active node — a duplicate node_id
    # inside the signatures list for a given bitmap slot should be rejected.
    # Construct a malformed certificate where both slots claim the same node_id.
    dup_signatures = [
        {"node_id": "olympus-node-1", "signature": sig1.signature},
        {"node_id": "olympus-node-1", "signature": sig1.signature},
    ]
    tampered_certificate = {**certificate, "signatures": dup_signatures}

    assert verify_quorum_certificate(tampered_certificate, header, registry) is False


def test_is_replay_epoch_flags_stale_epochs() -> None:
    assert is_replay_epoch(3, 4) is True
    assert is_replay_epoch(4, 4) is False


def test_resolve_canonical_fork_prefers_lexicographic_hash_on_signer_tie() -> None:
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    timestamp = "2026-03-10T12:00:00Z"
    header_a = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("01" * 32),
        timestamp=timestamp,
        height=8,
        round_number=2,
    )
    header_b = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("02" * 32),
        timestamp=timestamp,
        height=8,
        round_number=2,
    )

    sigs_a = [
        sign_federated_header(header_a, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header_a, "olympus-node-2", _test_signing_key(2), registry),
    ]
    sigs_b = [
        sign_federated_header(header_b, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header_b, "olympus-node-2", _test_signing_key(2), registry),
    ]
    cert_a = build_quorum_certificate(header_a, sigs_a, registry)
    cert_b = build_quorum_certificate(header_b, sigs_b, registry)

    selected = resolve_canonical_fork([(header_b, cert_b), (header_a, cert_a)], registry)

    assert selected is not None
    selected_header, _ = selected
    assert selected_header["header_hash"] == min(header_a["header_hash"], header_b["header_hash"])


def test_resolve_canonical_fork_rejects_timestamp_outliers() -> None:
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header_a = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("03" * 32),
        timestamp="2026-03-10T12:00:00Z",
        height=9,
        round_number=3,
    )
    header_b = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("05" * 32),
        timestamp="2026-03-10T12:01:00Z",
        height=9,
        round_number=3,
    )
    header_outlier = create_shard_header(
        shard_id="records/city-a",
        root_hash=bytes.fromhex("04" * 32),
        timestamp="2026-03-10T12:30:00Z",
        height=9,
        round_number=3,
    )
    cert_a = build_quorum_certificate(
        header_a,
        [
            sign_federated_header(header_a, "olympus-node-1", _test_signing_key(1), registry),
            sign_federated_header(header_a, "olympus-node-2", _test_signing_key(2), registry),
        ],
        registry,
    )
    cert_b = build_quorum_certificate(
        header_b,
        [
            sign_federated_header(header_b, "olympus-node-1", _test_signing_key(1), registry),
            sign_federated_header(header_b, "olympus-node-2", _test_signing_key(2), registry),
        ],
        registry,
    )
    cert_outlier = build_quorum_certificate(
        header_outlier,
        [
            sign_federated_header(
                header_outlier, "olympus-node-1", _test_signing_key(1), registry
            ),
            sign_federated_header(
                header_outlier, "olympus-node-2", _test_signing_key(2), registry
            ),
        ],
        registry,
    )

    selected = resolve_canonical_fork(
        [(header_a, cert_a), (header_b, cert_b), (header_outlier, cert_outlier)],
        registry,
        max_clock_skew_seconds=DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS,
    )

    assert selected is not None
    selected_header, _ = selected
    assert selected_header["header_hash"] == min(header_a["header_hash"], header_b["header_hash"])


def test_proactive_share_commitments_round_trip_verification() -> None:
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    commitments = build_proactive_share_commitments(
        registry,
        epoch=5,
        refresh_nonce="rotation-window-5",
    )

    assert verify_proactive_share_commitments(
        registry,
        epoch=5,
        refresh_nonce="rotation-window-5",
        commitments=commitments,
    )


def test_detect_compromise_signals_flags_double_vote_and_spike() -> None:
    signals = detect_compromise_signals(
        [
            FederationBehaviorSample("node-1", 1, "a" * 64),
            FederationBehaviorSample("node-1", 1, "b" * 64),
            FederationBehaviorSample("node-1", 2, "c" * 64),
            FederationBehaviorSample("node-1", 3, "d" * 64),
            FederationBehaviorSample("node-1", 4, "e" * 64),
            FederationBehaviorSample("node-2", 1, "f" * 64),
            FederationBehaviorSample("node-2", 2, "g" * 64),
            FederationBehaviorSample("node-3", 1, "h" * 64),
            FederationBehaviorSample("node-3", 2, "i" * 64),
        ]
    )

    assert signals["node-1"] == ("double_vote_detected", "participation_spike_detected")
    assert "node-2" not in signals


# =============================================================================
# T1: Steward-Guardian Equivocation Detection Tests (Shadow Ledger Mitigation)
# =============================================================================


def test_shard_header_fork_evidence_validates_fields() -> None:
    """ShardHeaderForkEvidence should reject invalid field values."""
    sig1 = NodeSignature(node_id="node-1", signature="ab" * 32)
    sig2 = NodeSignature(node_id="node-2", signature="cd" * 32)

    # Valid evidence should pass
    evidence = ShardHeaderForkEvidence(
        shard_id="records/city-a",
        seq=42,
        conflicting_header_hashes=("aa" * 32, "bb" * 32),
        observer_ids=("peer-1", "peer-2"),
        signatures_a=(sig1,),
        signatures_b=(sig2,),
        detected_at="2026-03-14T12:00:00Z",
    )
    assert evidence.shard_id == "records/city-a"
    assert evidence.seq == 42

    # Should reject empty shard_id
    with pytest.raises(ValueError, match="shard_id"):
        ShardHeaderForkEvidence(
            shard_id="",
            seq=42,
            conflicting_header_hashes=("aa" * 32, "bb" * 32),
            observer_ids=("peer-1",),
            signatures_a=(),
            signatures_b=(),
            detected_at="2026-03-14T12:00:00Z",
        )

    # Should reject less than 2 conflicting hashes
    with pytest.raises(ValueError, match="conflicting_header_hashes"):
        ShardHeaderForkEvidence(
            shard_id="records/city-a",
            seq=42,
            conflicting_header_hashes=("aa" * 32,),
            observer_ids=("peer-1",),
            signatures_a=(),
            signatures_b=(),
            detected_at="2026-03-14T12:00:00Z",
        )


def test_shard_header_fork_evidence_detects_colluding_guardians() -> None:
    """colluding_guardians() should return nodes that signed both conflicting headers."""
    sig1_a = NodeSignature(node_id="node-1", signature="aa" * 32)
    sig2_a = NodeSignature(node_id="node-2", signature="bb" * 32)
    sig1_b = NodeSignature(node_id="node-1", signature="cc" * 32)  # Same node signed both
    sig3_b = NodeSignature(node_id="node-3", signature="dd" * 32)

    evidence = ShardHeaderForkEvidence(
        shard_id="records/city-a",
        seq=42,
        conflicting_header_hashes=("aa" * 32, "bb" * 32),
        observer_ids=("peer-1", "peer-2"),
        signatures_a=(sig1_a, sig2_a),
        signatures_b=(sig1_b, sig3_b),
        detected_at="2026-03-14T12:00:00Z",
    )

    colluders = evidence.colluding_guardians()
    assert colluders == ("node-1",)  # node-1 signed both headers


def test_detect_shard_header_forks_finds_equivocation() -> None:
    """detect_shard_header_forks should detect conflicting headers at same seq."""
    sig1 = NodeSignature(node_id="node-1", signature="aa" * 32)
    sig2 = NodeSignature(node_id="node-2", signature="bb" * 32)

    observations = {
        "peer-1": GossipedShardHeader(
            peer_id="peer-1",
            shard_id="records/city-a",
            seq=42,
            header_hash="11" * 32,
            root_hash="aa" * 32,
            timestamp="2026-03-14T12:00:00Z",
            signatures=(sig1,),
        ),
        "peer-2": GossipedShardHeader(
            peer_id="peer-2",
            shard_id="records/city-a",
            seq=42,
            header_hash="22" * 32,  # Different header hash at same seq
            root_hash="bb" * 32,
            timestamp="2026-03-14T12:00:01Z",
            signatures=(sig2,),
        ),
    }

    evidences = detect_shard_header_forks(observations)

    assert len(evidences) == 1
    evidence = evidences[0]
    assert evidence.shard_id == "records/city-a"
    assert evidence.seq == 42
    assert set(evidence.conflicting_header_hashes) == {"11" * 32, "22" * 32}


def test_detect_shard_header_forks_no_conflict_when_hashes_match() -> None:
    """detect_shard_header_forks should not report forks when headers agree."""
    sig1 = NodeSignature(node_id="node-1", signature="aa" * 32)
    sig2 = NodeSignature(node_id="node-2", signature="bb" * 32)

    observations = {
        "peer-1": GossipedShardHeader(
            peer_id="peer-1",
            shard_id="records/city-a",
            seq=42,
            header_hash="11" * 32,
            root_hash="aa" * 32,
            timestamp="2026-03-14T12:00:00Z",
            signatures=(sig1,),
        ),
        "peer-2": GossipedShardHeader(
            peer_id="peer-2",
            shard_id="records/city-a",
            seq=42,
            header_hash="11" * 32,  # Same header hash = no conflict
            root_hash="aa" * 32,
            timestamp="2026-03-14T12:00:01Z",
            signatures=(sig2,),
        ),
    }

    evidences = detect_shard_header_forks(observations)
    assert len(evidences) == 0


def test_registry_forest_commitment_is_deterministic() -> None:
    """registry_forest_commitment should produce deterministic commitments."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)

    commitment1 = registry_forest_commitment(registry)
    commitment2 = registry_forest_commitment(registry)

    assert commitment1 == commitment2
    assert len(commitment1) == 64  # 32 bytes hex-encoded


def test_registry_forest_commitment_changes_with_membership() -> None:
    """registry_forest_commitment should change when membership changes."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    commitment_before = registry_forest_commitment(registry)

    rotated_registry = registry.rotate_node_key(
        node_id="olympus-node-1",
        new_pubkey=_test_signing_key(9).verify_key.encode(),
        rotated_at="2026-03-14T12:00:00Z",
    )
    commitment_after = registry_forest_commitment(rotated_registry)

    assert commitment_before != commitment_after


# =============================================================================
# T2: State Suppression Tests (Missing Shard Attack Mitigation)
# =============================================================================


def test_data_availability_challenge_validation() -> None:
    """DataAvailabilityChallenge should validate all required fields."""
    challenge = DataAvailabilityChallenge(
        shard_id="records/city-a",
        header_hash="aa" * 32,
        challenger_id="guardian-1",
        challenge_nonce="nonce-123",
        issued_at="2026-03-14T12:00:00Z",
        response_deadline="2026-03-14T12:05:00Z",
    )
    assert challenge.shard_id == "records/city-a"
    assert len(challenge.challenge_hash()) == 64

    with pytest.raises(ValueError, match="shard_id"):
        DataAvailabilityChallenge(
            shard_id="",
            header_hash="aa" * 32,
            challenger_id="guardian-1",
            challenge_nonce="nonce-123",
            issued_at="2026-03-14T12:00:00Z",
            response_deadline="2026-03-14T12:05:00Z",
        )


def test_replication_proof_creation_and_verification() -> None:
    """create_replication_proof and verify_data_availability should work together."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    signing_key = _test_signing_key(1)

    challenge = DataAvailabilityChallenge(
        shard_id="records/city-a",
        header_hash="aa" * 32,
        challenger_id="guardian-2",
        challenge_nonce="nonce-456",
        issued_at="2026-03-14T12:00:00Z",
        response_deadline="2026-03-14T12:05:00Z",
    )

    proof = create_replication_proof(
        challenge=challenge,
        guardian_id="olympus-node-1",
        signing_key=signing_key,
        ledger_tail_hash="bb" * 32,
        proof_sample_indices=(0, 5, 10),
        proof_sample_hashes=("cc" * 32, "dd" * 32, "ee" * 32),
        replicated_at="2026-03-14T12:01:00Z",
    )

    assert proof.guardian_id == "olympus-node-1"
    assert proof.merkle_root_verified is True
    assert verify_data_availability(challenge, proof, registry) is True


def test_replication_proof_rejects_wrong_challenge() -> None:
    """verify_data_availability should reject proofs for different challenges."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    signing_key = _test_signing_key(1)

    challenge1 = DataAvailabilityChallenge(
        shard_id="records/city-a",
        header_hash="aa" * 32,
        challenger_id="guardian-2",
        challenge_nonce="nonce-111",
        issued_at="2026-03-14T12:00:00Z",
        response_deadline="2026-03-14T12:05:00Z",
    )

    challenge2 = DataAvailabilityChallenge(
        shard_id="records/city-a",
        header_hash="aa" * 32,
        challenger_id="guardian-2",
        challenge_nonce="nonce-222",  # Different nonce
        issued_at="2026-03-14T12:00:00Z",
        response_deadline="2026-03-14T12:05:00Z",
    )

    proof = create_replication_proof(
        challenge=challenge1,
        guardian_id="olympus-node-1",
        signing_key=signing_key,
        ledger_tail_hash="bb" * 32,
        proof_sample_indices=(0,),
        proof_sample_hashes=("cc" * 32,),
        replicated_at="2026-03-14T12:01:00Z",
    )

    # Should fail because proof was for challenge1, not challenge2
    assert verify_data_availability(challenge2, proof, registry) is False


def test_federation_finality_status_tracks_state() -> None:
    """FederationFinalityStatus should track header finalization progress."""
    status = FederationFinalityStatus(
        shard_id="records/city-a",
        seq=42,
        header_hash="aa" * 32,
        status=FederationFinalityStatus.STATUS_PROPOSED,
        availability_proofs=(),
        quorum_signatures=(),
        finalized_at=None,
    )

    assert status.is_final() is False
    assert status.status == "PROPOSED"

    # Verify finalized status
    final_status = FederationFinalityStatus(
        shard_id="records/city-a",
        seq=42,
        header_hash="aa" * 32,
        status=FederationFinalityStatus.STATUS_FEDERATION_FINAL,
        availability_proofs=(),
        quorum_signatures=(),
        finalized_at="2026-03-14T12:10:00Z",
    )

    assert final_status.is_final() is True


def test_federation_finality_availability_threshold() -> None:
    """availability_threshold_met should require 2/3 of Guardians."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    signing_key1 = _test_signing_key(1)
    signing_key2 = _test_signing_key(2)

    challenge = DataAvailabilityChallenge(
        shard_id="records/city-a",
        header_hash="aa" * 32,
        challenger_id="external",
        challenge_nonce="nonce-789",
        issued_at="2026-03-14T12:00:00Z",
        response_deadline="2026-03-14T12:05:00Z",
    )

    proof1 = create_replication_proof(
        challenge=challenge,
        guardian_id="olympus-node-1",
        signing_key=signing_key1,
        ledger_tail_hash="bb" * 32,
        proof_sample_indices=(),
        proof_sample_hashes=(),
        replicated_at="2026-03-14T12:01:00Z",
    )

    proof2 = create_replication_proof(
        challenge=challenge,
        guardian_id="olympus-node-2",
        signing_key=signing_key2,
        ledger_tail_hash="bb" * 32,
        proof_sample_indices=(),
        proof_sample_hashes=(),
        replicated_at="2026-03-14T12:01:00Z",
    )

    # With 3 nodes and 2/3 threshold, need 2 proofs
    status_one_proof = FederationFinalityStatus(
        shard_id="records/city-a",
        seq=42,
        header_hash="aa" * 32,
        status=FederationFinalityStatus.STATUS_AVAILABILITY_PENDING,
        availability_proofs=(proof1,),
        quorum_signatures=(),
        finalized_at=None,
    )
    assert status_one_proof.availability_threshold_met(registry) is False

    status_two_proofs = FederationFinalityStatus(
        shard_id="records/city-a",
        seq=42,
        header_hash="aa" * 32,
        status=FederationFinalityStatus.STATUS_AVAILABILITY_VERIFIED,
        availability_proofs=(proof1, proof2),
        quorum_signatures=(),
        finalized_at=None,
    )
    assert status_two_proofs.availability_threshold_met(registry) is True


# =============================================================================
# T3: Long-Range Key Compromise Tests (Recursive SNARK Chain Proofs)
# =============================================================================


def test_recursive_chain_proof_validation() -> None:
    """RecursiveChainProof should validate all required fields."""
    proof = RecursiveChainProof(
        proof_type=RecursiveChainProof.PROOF_TYPE_GROTH16,
        previous_root="aa" * 32,
        current_root="bb" * 32,
        epoch_start=5,
        epoch_end=10,
        transition_count=100,
        proof_data="proof-data-hex",
        public_inputs=("aa" * 32, "bb" * 32, "5", "10"),
        verification_key_hash="cc" * 32,
        created_at="2026-03-14T12:00:00Z",
    )

    assert proof.proof_type == "groth16"
    assert proof.transition_count == 100
    assert len(proof.proof_commitment_hash()) == 64

    # Should reject invalid proof type
    with pytest.raises(ValueError, match="proof_type"):
        RecursiveChainProof(
            proof_type="invalid",
            previous_root="aa" * 32,
            current_root="bb" * 32,
            epoch_start=5,
            epoch_end=10,
            transition_count=100,
            proof_data="proof-data-hex",
            public_inputs=(),
            verification_key_hash="cc" * 32,
            created_at="2026-03-14T12:00:00Z",
        )

    # Should reject epoch_end < epoch_start
    with pytest.raises(ValueError, match="epoch_end"):
        RecursiveChainProof(
            proof_type="groth16",
            previous_root="aa" * 32,
            current_root="bb" * 32,
            epoch_start=10,
            epoch_end=5,
            transition_count=100,
            proof_data="proof-data-hex",
            public_inputs=(),
            verification_key_hash="cc" * 32,
            created_at="2026-03-14T12:00:00Z",
        )


def test_recursive_chain_proof_commitment_is_deterministic() -> None:
    """proof_commitment_hash should be deterministic."""
    proof = RecursiveChainProof(
        proof_type="groth16",
        previous_root="aa" * 32,
        current_root="bb" * 32,
        epoch_start=5,
        epoch_end=10,
        transition_count=100,
        proof_data="proof-data-hex",
        public_inputs=(),
        verification_key_hash="cc" * 32,
        created_at="2026-03-14T12:00:00Z",
    )

    hash1 = proof.proof_commitment_hash()
    hash2 = proof.proof_commitment_hash()

    assert hash1 == hash2


def test_epoch_key_rotation_record_validation() -> None:
    """EpochKeyRotationRecord should validate fields correctly."""
    sig1 = NodeSignature(node_id="witness-1", signature="aa" * 32)

    record = EpochKeyRotationRecord(
        node_id="guardian-1",
        epoch=5,
        old_pubkey_hash="11" * 32,
        new_pubkey_hash="22" * 32,
        rotated_at="2026-03-14T12:00:00Z",
        rotation_signature="signature-hex",
        witness_signatures=(sig1,),
    )

    assert record.node_id == "guardian-1"
    assert record.epoch == 5

    # Should reject same old and new pubkey hash
    with pytest.raises(ValueError, match="new_pubkey_hash"):
        EpochKeyRotationRecord(
            node_id="guardian-1",
            epoch=5,
            old_pubkey_hash="11" * 32,
            new_pubkey_hash="11" * 32,  # Same as old
            rotated_at="2026-03-14T12:00:00Z",
            rotation_signature="signature-hex",
            witness_signatures=(),
        )


def test_verify_epoch_key_rotation_validates_signature() -> None:
    """verify_epoch_key_rotation should validate the rotation signature."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    old_key = _test_signing_key(1)
    new_key = _test_signing_key(9)

    # Compute expected hashes
    from protocol.hashes import HASH_SEPARATOR, hash_bytes

    old_pubkey_hash = hash_bytes(old_key.verify_key.encode()).hex()
    new_pubkey_hash = hash_bytes(new_key.verify_key.encode()).hex()

    # Create the rotation payload
    rotation_payload = HASH_SEPARATOR.join([
        "olympus-node-1",
        "5",
        old_pubkey_hash,
        new_pubkey_hash,
        "2026-03-14T12:00:00Z",
    ]).encode()
    rotation_hash = hash_bytes(rotation_payload)

    # Sign with old key
    signed = old_key.sign(rotation_hash)
    rotation_signature = signed.signature.hex()

    # Create witness signature
    witness_key = _test_signing_key(2)
    witness_signed = witness_key.sign(rotation_hash)
    witness_sig = NodeSignature(
        node_id="olympus-node-2",
        signature=witness_signed.signature.hex(),
    )

    record = EpochKeyRotationRecord(
        node_id="olympus-node-1",
        epoch=5,
        old_pubkey_hash=old_pubkey_hash,
        new_pubkey_hash=new_pubkey_hash,
        rotated_at="2026-03-14T12:00:00Z",
        rotation_signature=rotation_signature,
        witness_signatures=(witness_sig,),
    )

    result = verify_epoch_key_rotation(
        record=record,
        old_verify_key=old_key.verify_key,
        registry=registry,
        min_witnesses=1,
    )

    assert result is True


def test_verify_recursive_chain_proof_checks_vk_hash() -> None:
    """verify_recursive_chain_proof should verify verification key hash."""
    from protocol.canonical_json import canonical_json_bytes
    from protocol.hashes import hash_bytes

    vk = {"type": "groth16", "curve": "bn128"}
    vk_hash = hash_bytes(canonical_json_bytes(vk)).hex()

    proof = RecursiveChainProof(
        proof_type="groth16",
        previous_root="aa" * 32,
        current_root="bb" * 32,
        epoch_start=5,
        epoch_end=10,
        transition_count=100,
        proof_data="proof-data-hex",
        public_inputs=("aa" * 32, "bb" * 32, "5", "10"),
        verification_key_hash=vk_hash,
        created_at="2026-03-14T12:00:00Z",
    )

    # Should pass with correct VK hash
    result = verify_recursive_chain_proof(proof, vk, vk_hash)
    assert result is True

    # Should fail with wrong VK hash
    result_wrong = verify_recursive_chain_proof(proof, vk, "wrong" * 16)
    assert result_wrong is False
