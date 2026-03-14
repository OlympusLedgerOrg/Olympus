"""Property-based federation consensus invariants."""

from __future__ import annotations

from pathlib import Path

from hypothesis import assume, given, strategies as st

from protocol.federation import (
    FederationRegistry,
    build_quorum_certificate,
    has_federation_quorum,
    quorum_certificate_hash,
    sign_federated_header,
    verify_quorum_certificate,
)
from protocol.shards import create_shard_header, get_signing_key_from_seed


REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "examples" / "federation_registry.json"


def _test_signing_key(seed_byte: int):
    """Return a deterministic test-only Ed25519 key for federation property tests."""
    return get_signing_key_from_seed(bytes([seed_byte]) * 32)


header_heights = st.integers(min_value=0, max_value=10)
header_rounds = st.integers(min_value=0, max_value=10)
root_hashes = st.binary(min_size=32, max_size=32)
quorum_signers = st.lists(st.sampled_from([1, 2, 3]), min_size=2, max_size=3, unique=True)


@given(root_hashes, header_heights, header_rounds, quorum_signers)
def test_quorum_certificate_binding_is_unique(
    root_hash: bytes, height: int, round_number: int, signer_seeds: list[int]
) -> None:
    """A header cannot have two distinct valid quorum certificates."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/property-a",
        root_hash=root_hash,
        timestamp="2026-03-10T00:00:00Z",
        height=height,
        round_number=round_number,
    )
    signatures = [
        sign_federated_header(header, f"olympus-node-{seed}", _test_signing_key(seed), registry)
        for seed in signer_seeds
    ]
    certificate = build_quorum_certificate(header, signatures, registry)
    assert verify_quorum_certificate(certificate, header, registry) is True

    # Reorder signatures to produce a distinct certificate for the same header.
    alternate_certificate = {**certificate, "signatures": list(reversed(certificate["signatures"]))}
    assume(alternate_certificate != certificate)
    header["quorum_certificate_hash"] = quorum_certificate_hash(alternate_certificate)
    assert verify_quorum_certificate(alternate_certificate, header, registry) is False


@given(root_hashes, header_heights, header_rounds)
def test_validator_set_tampering_invalidates_certificate(
    root_hash: bytes, height: int, round_number: int
) -> None:
    """Changing the validator set snapshot must invalidate an existing certificate."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/property-b",
        root_hash=root_hash,
        timestamp="2026-03-11T00:00:00Z",
        height=height,
        round_number=round_number,
    )
    signatures = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
    ]
    certificate = build_quorum_certificate(header, signatures, registry)
    assert verify_quorum_certificate(certificate, header, registry) is True

    tampered_registry = FederationRegistry.from_dict(
        {
            "nodes": [
                *[node.to_dict() for node in registry.nodes],
                {
                    "node_id": "olympus-node-9",
                    "pubkey": _test_signing_key(9).verify_key.encode().hex(),
                    "endpoint": "https://node9.olympus.org",
                    "operator": "Adversarial Operator",
                    "jurisdiction": "city-z",
                    "status": "active",
                },
            ]
        }
    )
    assert verify_quorum_certificate(certificate, header, tampered_registry) is False


@given(root_hashes, header_heights, header_rounds)
def test_duplicate_signatures_never_satisfy_quorum(
    root_hash: bytes, height: int, round_number: int
) -> None:
    """Duplicate votes from the same node must not satisfy quorum thresholds."""
    registry = FederationRegistry.from_file(REGISTRY_PATH)
    header = create_shard_header(
        shard_id="records/property-c",
        root_hash=root_hash,
        timestamp="2026-03-12T00:00:00Z",
        height=height,
        round_number=round_number,
    )
    duplicate_signature = sign_federated_header(
        header, "olympus-node-1", _test_signing_key(1), registry
    )
    duplicated_signatures = [duplicate_signature, duplicate_signature]

    assert has_federation_quorum(header, duplicated_signatures, registry) is False
