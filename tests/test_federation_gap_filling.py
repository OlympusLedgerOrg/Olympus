"""Gap-filling tests for federation identity, quorum, and adversarial helpers.

Covers paths not exercised in test_federation.py:
  - DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS constant contract
  - Inactive-node filtering from active_nodes() and quorum
  - verify_proactive_share_commitments rejection paths
  - detect_compromise_signals clean and spike-only paths
  - ShardHeaderForkEvidence.colluding_guardians() empty case
  - Multi-shard fork isolation
  - FederationRegistry.rotate_node_key on unknown node
  - resolve_canonical_fork edge cases (empty, single candidate)
  - quorum_certificate_hash determinism
  - create_replication_proof error paths
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from protocol.federation import (
    DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS,
    DataAvailabilityChallenge,
    FederationBehaviorSample,
    FederationRegistry,
    GossipedShardHeader,
    NodeSignature,
    ShardHeaderForkEvidence,
    build_proactive_share_commitments,
    build_quorum_certificate,
    create_replication_proof,
    detect_compromise_signals,
    detect_shard_header_forks,
    has_federation_quorum,
    quorum_certificate_hash,
    resolve_canonical_fork,
    sign_federated_header,
    verify_data_availability,
    verify_proactive_share_commitments,
)
from protocol.shards import create_shard_header, get_signing_key_from_seed


REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "examples" / "federation_registry.json"


def _test_signing_key(seed_byte: int):
    return get_signing_key_from_seed(bytes([seed_byte]) * 32)


def _three_node_registry() -> FederationRegistry:
    return FederationRegistry.from_file(REGISTRY_PATH)


def _four_node_registry() -> FederationRegistry:
    return FederationRegistry.from_dict(
        {
            "nodes": [
                {
                    "node_id": f"olympus-node-{i}",
                    "pubkey": _test_signing_key(i).verify_key.encode().hex(),
                    "endpoint": f"https://node{i}.olympus.org",
                    "operator": f"Operator {i}",
                    "jurisdiction": f"zone-{i}",
                    "status": "active",
                }
                for i in range(1, 5)
            ]
        }
    )


# =============================================================================
# DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS
# =============================================================================


def test_default_clock_skew_constant_is_positive_integer() -> None:
    """Clock skew constant must be a positive integer (wire-protocol contract)."""
    assert isinstance(DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS, int)
    assert DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS > 0


def test_default_clock_skew_constant_is_reasonable_bound() -> None:
    """Clock skew should be at most one hour; tighter than that avoids replay windows."""
    assert DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS <= 3600


# =============================================================================
# Inactive node filtering
# =============================================================================


def test_inactive_nodes_excluded_from_active_nodes() -> None:
    """Nodes with status != 'active' must not appear in active_nodes()."""
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
                    "status": "inactive",
                },
                {
                    "node_id": "olympus-node-3",
                    "pubkey": _test_signing_key(3).verify_key.encode().hex(),
                    "endpoint": "https://node3.olympus.org",
                    "operator": "State Auditor",
                    "jurisdiction": "state-c",
                    "status": "suspended",
                },
            ]
        }
    )

    active = registry.active_nodes()
    active_ids = {n.node_id for n in active}

    assert "olympus-node-1" in active_ids
    assert "olympus-node-2" not in active_ids
    assert "olympus-node-3" not in active_ids


def test_inactive_node_signature_does_not_satisfy_quorum() -> None:
    """A signature from an inactive node must not count toward quorum."""
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
                    "status": "inactive",
                },
            ]
        }
    )

    header = create_shard_header(
        shard_id="records.city-a",
        root_hash=bytes.fromhex("ab" * 32),
        timestamp="2026-03-15T00:00:00Z",
    )

    # 2 active + 1 inactive; quorum threshold for 2 active nodes is 2
    active_sig_1 = sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry)
    inactive_sig = sign_federated_header(header, "olympus-node-3", _test_signing_key(3), registry)

    # One active signature should not reach quorum alone
    assert has_federation_quorum(header, [active_sig_1, inactive_sig], registry) is False

    # Two active signatures should reach quorum
    active_sig_2 = sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry)
    assert has_federation_quorum(header, [active_sig_1, active_sig_2], registry) is True


def test_quorum_threshold_counts_only_active_nodes() -> None:
    """quorum_threshold() must be derived from active node count, not total."""
    registry = FederationRegistry.from_dict(
        {
            "nodes": [
                {
                    "node_id": f"olympus-node-{i}",
                    "pubkey": _test_signing_key(i).verify_key.encode().hex(),
                    "endpoint": f"https://node{i}.olympus.org",
                    "operator": f"Op {i}",
                    "jurisdiction": f"zone-{i}",
                    "status": "active" if i <= 2 else "inactive",
                }
                for i in range(1, 5)
            ]
        }
    )

    # 2 active nodes -> ceil(2 * 2/3) = 2
    assert registry.quorum_threshold() == 2


# =============================================================================
# verify_proactive_share_commitments rejection paths
# =============================================================================


def test_verify_proactive_share_commitments_rejects_wrong_epoch() -> None:
    """Commitments generated for epoch N must not verify under epoch N+1."""
    registry = _three_node_registry()
    commitments = build_proactive_share_commitments(
        registry,
        epoch=5,
        refresh_nonce="rotation-window-5",
    )

    assert (
        verify_proactive_share_commitments(
            registry,
            epoch=6,  # wrong epoch
            refresh_nonce="rotation-window-5",
            commitments=commitments,
        )
        is False
    )


def test_verify_proactive_share_commitments_rejects_wrong_nonce() -> None:
    """Commitments generated with nonce A must not verify under nonce B."""
    registry = _three_node_registry()
    commitments = build_proactive_share_commitments(
        registry,
        epoch=5,
        refresh_nonce="rotation-window-5",
    )

    assert (
        verify_proactive_share_commitments(
            registry,
            epoch=5,
            refresh_nonce="rotation-window-TAMPERED",
            commitments=commitments,
        )
        is False
    )


def test_verify_proactive_share_commitments_rejects_empty_commitments() -> None:
    """Empty commitments must not verify."""
    registry = _three_node_registry()

    assert (
        verify_proactive_share_commitments(
            registry,
            epoch=5,
            refresh_nonce="rotation-window-5",
            commitments={},
        )
        is False
    )


def test_verify_proactive_share_commitments_rejects_wrong_registry() -> None:
    """Commitments built for registry R must not verify against a different registry."""
    registry_a = _three_node_registry()
    registry_b = _four_node_registry()

    commitments = build_proactive_share_commitments(
        registry_a,
        epoch=5,
        refresh_nonce="rotation-window-5",
    )

    assert (
        verify_proactive_share_commitments(
            registry_b,
            epoch=5,
            refresh_nonce="rotation-window-5",
            commitments=commitments,
        )
        is False
    )


# =============================================================================
# detect_compromise_signals — clean and spike-only paths
# =============================================================================


def test_detect_compromise_signals_returns_empty_for_normal_behavior() -> None:
    """Nodes with unique votes per round and normal participation should not be flagged."""
    signals = detect_compromise_signals(
        [
            FederationBehaviorSample("node-1", 1, "a" * 64),
            FederationBehaviorSample("node-1", 2, "b" * 64),
            FederationBehaviorSample("node-2", 1, "c" * 64),
            FederationBehaviorSample("node-2", 2, "d" * 64),
            FederationBehaviorSample("node-3", 1, "e" * 64),
            FederationBehaviorSample("node-3", 2, "f" * 64),
        ]
    )

    assert signals == {}


def test_detect_compromise_signals_flags_double_vote_without_spike() -> None:
    """A double vote at one round should flag only double_vote, not spike."""
    # Two votes from node-1 at round 1, normal participation otherwise
    signals = detect_compromise_signals(
        [
            FederationBehaviorSample("node-1", 1, "a" * 64),
            FederationBehaviorSample("node-1", 1, "b" * 64),  # double vote
            FederationBehaviorSample("node-1", 2, "c" * 64),
            FederationBehaviorSample("node-2", 1, "d" * 64),
            FederationBehaviorSample("node-2", 2, "e" * 64),
        ]
    )

    assert "node-1" in signals
    assert "double_vote_detected" in signals["node-1"]
    assert "node-2" not in signals


def test_detect_compromise_signals_isolates_flags_per_node() -> None:
    """Signal flags must be per-node and not bleed across nodes."""
    signals = detect_compromise_signals(
        [
            FederationBehaviorSample("node-1", 1, "a" * 64),
            FederationBehaviorSample("node-1", 1, "b" * 64),  # double vote on node-1
            FederationBehaviorSample("node-2", 1, "c" * 64),
            FederationBehaviorSample("node-2", 2, "d" * 64),
            FederationBehaviorSample("node-3", 1, "e" * 64),
        ]
    )

    assert "node-1" in signals
    assert "node-2" not in signals
    assert "node-3" not in signals


# =============================================================================
# ShardHeaderForkEvidence.colluding_guardians() — empty case
# =============================================================================


def test_colluding_guardians_returns_empty_when_no_shared_signers() -> None:
    """colluding_guardians() must return empty when no node signed both headers."""
    evidence = ShardHeaderForkEvidence(
        shard_id="records.city-a",
        seq=42,
        conflicting_header_hashes=("aa" * 32, "bb" * 32),
        observer_ids=("peer-1", "peer-2"),
        signatures_a=(NodeSignature(node_id="node-1", signature="aa" * 32),),
        signatures_b=(NodeSignature(node_id="node-2", signature="bb" * 32),),
        detected_at="2026-03-14T12:00:00Z",
    )

    assert evidence.colluding_guardians() == ()


def test_colluding_guardians_returns_all_double_signers() -> None:
    """colluding_guardians() must include every node that appears in both signature sets."""
    evidence = ShardHeaderForkEvidence(
        shard_id="records.city-a",
        seq=99,
        conflicting_header_hashes=("cc" * 32, "dd" * 32),
        observer_ids=("peer-1", "peer-2", "peer-3"),
        signatures_a=(
            NodeSignature(node_id="node-1", signature="11" * 32),
            NodeSignature(node_id="node-2", signature="22" * 32),
        ),
        signatures_b=(
            NodeSignature(node_id="node-1", signature="33" * 32),
            NodeSignature(node_id="node-2", signature="44" * 32),
            NodeSignature(node_id="node-3", signature="55" * 32),
        ),
        detected_at="2026-03-14T12:00:00Z",
    )

    colluders = set(evidence.colluding_guardians())
    assert colluders == {"node-1", "node-2"}
    assert "node-3" not in colluders


# =============================================================================
# Multi-shard fork isolation
# =============================================================================


def test_detect_shard_header_forks_does_not_conflate_different_shards() -> None:
    """Conflicting hashes on different shard_ids must not produce cross-shard fork evidence."""
    observations = {
        "peer-1": GossipedShardHeader(
            peer_id="peer-1",
            shard_id="records.city-a",
            seq=1,
            header_hash="11" * 32,
            root_hash="aa" * 32,
            timestamp="2026-03-14T12:00:00Z",
            signatures=(NodeSignature(node_id="node-1", signature="aa" * 32),),
        ),
        "peer-2": GossipedShardHeader(
            peer_id="peer-2",
            shard_id="records.city-b",  # different shard — not a conflict
            seq=1,
            header_hash="22" * 32,
            root_hash="bb" * 32,
            timestamp="2026-03-14T12:00:01Z",
            signatures=(NodeSignature(node_id="node-2", signature="bb" * 32),),
        ),
    }

    evidences = detect_shard_header_forks(observations)
    assert len(evidences) == 0


def test_detect_shard_header_forks_handles_multiple_independent_conflicts() -> None:
    """Forks on distinct shards must each produce separate evidence entries."""
    observations = {
        "peer-1": GossipedShardHeader(
            peer_id="peer-1",
            shard_id="records.city-a",
            seq=1,
            header_hash="11" * 32,
            root_hash="aa" * 32,
            timestamp="2026-03-14T12:00:00Z",
            signatures=(NodeSignature(node_id="node-1", signature="aa" * 32),),
        ),
        "peer-2": GossipedShardHeader(
            peer_id="peer-2",
            shard_id="records.city-a",
            seq=1,
            header_hash="22" * 32,  # conflict on city-a
            root_hash="bb" * 32,
            timestamp="2026-03-14T12:00:01Z",
            signatures=(NodeSignature(node_id="node-2", signature="bb" * 32),),
        ),
        "peer-3": GossipedShardHeader(
            peer_id="peer-3",
            shard_id="records.county-b",
            seq=5,
            header_hash="33" * 32,
            root_hash="cc" * 32,
            timestamp="2026-03-14T12:00:00Z",
            signatures=(NodeSignature(node_id="node-1", signature="cc" * 32),),
        ),
        "peer-4": GossipedShardHeader(
            peer_id="peer-4",
            shard_id="records.county-b",
            seq=5,
            header_hash="44" * 32,  # conflict on county-b
            root_hash="dd" * 32,
            timestamp="2026-03-14T12:00:01Z",
            signatures=(NodeSignature(node_id="node-2", signature="dd" * 32),),
        ),
    }

    evidences = detect_shard_header_forks(observations)
    shard_ids = {e.shard_id for e in evidences}

    assert len(evidences) == 2
    assert "records.city-a" in shard_ids
    assert "records.county-b" in shard_ids


# =============================================================================
# FederationRegistry.rotate_node_key on unknown node
# =============================================================================


def test_rotate_node_key_raises_on_unknown_node_id() -> None:
    """rotate_node_key must raise when the node_id does not exist in the registry."""
    registry = _three_node_registry()

    with pytest.raises((ValueError, KeyError)):
        registry.rotate_node_key(
            node_id="olympus-node-999",  # does not exist
            new_pubkey=_test_signing_key(9).verify_key.encode(),
            rotated_at="2026-03-15T00:00:00Z",
        )


def test_rotate_node_key_raises_on_same_pubkey() -> None:
    """rotate_node_key must reject a rotation to the same public key."""
    registry = _three_node_registry()
    same_key = _test_signing_key(1).verify_key.encode()

    with pytest.raises(ValueError):
        registry.rotate_node_key(
            node_id="olympus-node-1",
            new_pubkey=same_key,
            rotated_at="2026-03-15T00:00:00Z",
        )


# =============================================================================
# resolve_canonical_fork edge cases
# =============================================================================


def test_resolve_canonical_fork_returns_none_on_empty_input() -> None:
    """resolve_canonical_fork must return None when given no candidates."""
    registry = _three_node_registry()
    result = resolve_canonical_fork([], registry)
    assert result is None


def test_resolve_canonical_fork_returns_sole_candidate_directly() -> None:
    """A single valid candidate must be returned without comparison."""
    registry = _three_node_registry()
    header = create_shard_header(
        shard_id="records.city-a",
        root_hash=bytes.fromhex("f0" * 32),
        timestamp="2026-03-15T00:00:00Z",
        height=1,
        round_number=0,
    )
    sigs = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
    ]
    cert = build_quorum_certificate(header, sigs, registry)

    result = resolve_canonical_fork([(header, cert)], registry)

    assert result is not None
    selected_header, _ = result
    assert selected_header["header_hash"] == header["header_hash"]


def test_resolve_canonical_fork_prefers_higher_signer_count() -> None:
    """Among candidates at the same height/round, prefer more signers."""
    registry = _four_node_registry()
    timestamp = "2026-03-15T00:00:00Z"

    header_a = create_shard_header(
        shard_id="records.city-a",
        root_hash=bytes.fromhex("f1" * 32),
        timestamp=timestamp,
        height=5,
        round_number=1,
    )
    header_b = create_shard_header(
        shard_id="records.city-a",
        root_hash=bytes.fromhex("f2" * 32),
        timestamp=timestamp,
        height=5,
        round_number=1,
    )

    # header_a: 3 signers (quorum minimum); header_b: 4 signers (all nodes)
    cert_a = build_quorum_certificate(
        header_a,
        [
            sign_federated_header(header_a, "olympus-node-1", _test_signing_key(1), registry),
            sign_federated_header(header_a, "olympus-node-2", _test_signing_key(2), registry),
            sign_federated_header(header_a, "olympus-node-3", _test_signing_key(3), registry),
        ],
        registry,
    )
    cert_b = build_quorum_certificate(
        header_b,
        [
            sign_federated_header(header_b, "olympus-node-1", _test_signing_key(1), registry),
            sign_federated_header(header_b, "olympus-node-2", _test_signing_key(2), registry),
            sign_federated_header(header_b, "olympus-node-3", _test_signing_key(3), registry),
            sign_federated_header(header_b, "olympus-node-4", _test_signing_key(4), registry),
        ],
        registry,
    )

    result = resolve_canonical_fork([(header_a, cert_a), (header_b, cert_b)], registry)
    assert result is not None
    selected_header, _ = result
    assert selected_header["header_hash"] == header_b["header_hash"]


# =============================================================================
# quorum_certificate_hash determinism
# =============================================================================


def test_quorum_certificate_hash_is_deterministic() -> None:
    """quorum_certificate_hash must return identical output on repeated calls."""
    registry = _three_node_registry()
    header = create_shard_header(
        shard_id="records.city-a",
        root_hash=bytes.fromhex("ca" * 32),
        timestamp="2026-03-15T12:00:00Z",
    )
    sigs = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
    ]
    cert = build_quorum_certificate(header, sigs, registry)

    hash1 = quorum_certificate_hash(cert)
    hash2 = quorum_certificate_hash(cert)

    assert hash1 == hash2
    assert isinstance(hash1, str)
    assert len(hash1) == 64  # 32 bytes hex-encoded


def test_quorum_certificate_hash_changes_on_mutation() -> None:
    """Mutating any field of the certificate must change its hash."""
    registry = _three_node_registry()
    header = create_shard_header(
        shard_id="records.city-a",
        root_hash=bytes.fromhex("cb" * 32),
        timestamp="2026-03-15T12:01:00Z",
    )
    sigs = [
        sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
        sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
    ]
    cert = build_quorum_certificate(header, sigs, registry)

    original_hash = quorum_certificate_hash(cert)
    tampered_cert = {**cert, "federation_epoch": cert["federation_epoch"] + 1}
    tampered_hash = quorum_certificate_hash(tampered_cert)

    assert original_hash != tampered_hash


# =============================================================================
# create_replication_proof error paths
# =============================================================================


def test_create_replication_proof_rejects_mismatched_sample_lengths() -> None:
    """proof_sample_indices and proof_sample_hashes must have the same length."""
    challenge = DataAvailabilityChallenge(
        shard_id="records.city-a",
        header_hash="aa" * 32,
        challenger_id="guardian-2",
        challenge_nonce="nonce-err-1",
        issued_at="2026-03-15T12:00:00Z",
        response_deadline="2026-03-15T12:05:00Z",
    )

    with pytest.raises((ValueError, AssertionError)):
        create_replication_proof(
            challenge=challenge,
            guardian_id="olympus-node-1",
            signing_key=_test_signing_key(1),
            ledger_tail_hash="bb" * 32,
            proof_sample_indices=(0, 1, 2),
            proof_sample_hashes=("cc" * 32,),  # length mismatch
            replicated_at="2026-03-15T12:01:00Z",
        )


def test_verify_data_availability_rejects_unknown_guardian() -> None:
    """verify_data_availability must reject a proof from a node not in the registry."""
    registry = _three_node_registry()
    challenge = DataAvailabilityChallenge(
        shard_id="records.city-a",
        header_hash="aa" * 32,
        challenger_id="guardian-2",
        challenge_nonce="nonce-err-2",
        issued_at="2026-03-15T12:00:00Z",
        response_deadline="2026-03-15T12:05:00Z",
    )

    proof = create_replication_proof(
        challenge=challenge,
        guardian_id="unknown-node-999",  # not in registry
        signing_key=_test_signing_key(9),
        ledger_tail_hash="bb" * 32,
        proof_sample_indices=(0,),
        proof_sample_hashes=("cc" * 32,),
        replicated_at="2026-03-15T12:01:00Z",
    )

    assert verify_data_availability(challenge, proof, registry) is False


def test_verify_data_availability_rejects_tampered_ledger_tail() -> None:
    """verify_data_availability must reject a proof where ledger_tail_hash was modified."""
    registry = _three_node_registry()
    signing_key = _test_signing_key(1)

    challenge = DataAvailabilityChallenge(
        shard_id="records.city-a",
        header_hash="aa" * 32,
        challenger_id="guardian-2",
        challenge_nonce="nonce-err-3",
        issued_at="2026-03-15T12:00:00Z",
        response_deadline="2026-03-15T12:05:00Z",
    )

    proof = create_replication_proof(
        challenge=challenge,
        guardian_id="olympus-node-1",
        signing_key=signing_key,
        ledger_tail_hash="bb" * 32,
        proof_sample_indices=(0,),
        proof_sample_hashes=("cc" * 32,),
        replicated_at="2026-03-15T12:01:00Z",
    )

    # Tamper: replace ledger_tail_hash with different value
    tampered_proof = dataclasses.replace(proof, ledger_tail_hash="ff" * 32)

    assert verify_data_availability(challenge, tampered_proof, registry) is False
