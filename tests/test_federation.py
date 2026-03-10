"""Tests for federation identity and quorum prototype helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from protocol.canonical_json import canonical_json_bytes
from protocol.federation import (
    FEDERATION_DOMAIN_TAG,
    FederationNode,
    FederationRegistry,
    FederationVoteMessage,
    NodeSignature,
    _to_int,
    append_quorum_certificate_to_ledger,
    build_federation_header_record,
    build_quorum_certificate,
    has_federation_quorum,
    serialize_vote_message,
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
        "quorum_threshold": registry.quorum_threshold(),
        "scheme": "ed25519",
        "signer_bitmap": signer_bitmap,
        "signatures": [
            signature_one.to_dict(),
            signature_one.to_dict(),
            signature_two.to_dict(),
        ],
    }

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
        "quorum_threshold": registry.quorum_threshold(),
        "scheme": "ed25519",
        "signer_bitmap": signer_bitmap,
        "signatures": [
            signature_one.to_dict(),
            conflicting_signature_one.to_dict(),
            signature_two.to_dict(),
        ],
    }

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
    swapped_certificate = {
        **canonical_certificate,
        "signatures": [
            signature_two.to_dict(),
            signature_one.to_dict(),
        ],
    }

    assert verify_quorum_certificate(canonical_certificate, header, registry) is True
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

    assert verify_quorum_certificate(tampered_certificate, header, registry) is False


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
