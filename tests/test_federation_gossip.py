"""
Tests for protocol/federation/gossip.py.

Covers: resolve_canonical_fork, proactive share commitments, compromise
detection, VRF selection, committee/leader election, commit-reveal entropy,
and ledger certificate appending.
"""

from __future__ import annotations

from pathlib import Path

import nacl.signing
import pytest

from protocol.federation import (
    FederationBehaviorSample,
    FederationRegistry,
    build_quorum_certificate,
    sign_federated_header,
)
from protocol.federation.gossip import (
    append_quorum_certificate_to_ledger,
    build_proactive_share_commitments,
    build_vrf_reveal_commitment,
    derive_vrf_round_entropy,
    detect_compromise_signals,
    resolve_canonical_fork,
    select_vrf_committee,
    select_vrf_leader,
    verify_proactive_share_commitments,
    vrf_selection_scores,
)
from protocol.ledger import Ledger
from protocol.shards import create_shard_header, get_signing_key_from_seed


REPO_ROOT = Path(__file__).parent.parent
REGISTRY_PATH = REPO_ROOT / "examples" / "federation_registry.json"


def _test_signing_key(seed_byte: int) -> nacl.signing.SigningKey:
    return get_signing_key_from_seed(bytes([seed_byte]) * 32)


def _make_registry() -> FederationRegistry:
    return FederationRegistry.from_file(REGISTRY_PATH)


def _make_signed_candidate(
    registry: FederationRegistry,
    root_hex: str = "11" * 32,
    timestamp: str = "2026-03-17T00:00:00Z",
    height: int = 1,
    round_number: int = 0,
    shard_id: str = "records/city-a",
    num_signers: int = 2,
) -> tuple[dict, dict]:
    """Build a header + quorum certificate for fork resolution tests."""
    header = create_shard_header(
        shard_id=shard_id,
        root_hash=bytes.fromhex(root_hex),
        timestamp=timestamp,
        height=height,
        round_number=round_number,
    )
    sigs = [
        sign_federated_header(header, f"olympus-node-{i + 1}", _test_signing_key(i + 1), registry)
        for i in range(num_signers)
    ]
    cert = build_quorum_certificate(header, sigs, registry)
    return header, cert


# ---------------------------------------------------------------------------
# resolve_canonical_fork
# ---------------------------------------------------------------------------


class TestResolveCanonicalFork:
    def test_empty_candidates_returns_none(self):
        registry = _make_registry()
        assert resolve_canonical_fork([], registry) is None

    def test_single_valid_candidate_selected(self):
        registry = _make_registry()
        header, cert = _make_signed_candidate(registry)
        result = resolve_canonical_fork([(header, cert)], registry)
        assert result is not None
        assert result[0]["header_hash"] == header["header_hash"]

    def test_higher_signer_count_wins(self):
        registry = _make_registry()
        h2, c2 = _make_signed_candidate(registry, root_hex="22" * 32, num_signers=2)
        h3, c3 = _make_signed_candidate(registry, root_hex="33" * 32, num_signers=3)
        result = resolve_canonical_fork([(h2, c2), (h3, c3)], registry)
        assert result is not None
        assert result[0]["header_hash"] == h3["header_hash"]

    def test_same_signer_count_lexicographic_tiebreak(self):
        registry = _make_registry()
        ha, ca = _make_signed_candidate(registry, root_hex="aa" * 32, num_signers=2)
        hb, cb = _make_signed_candidate(registry, root_hex="11" * 32, num_signers=2)
        result = resolve_canonical_fork([(ha, ca), (hb, cb)], registry)
        assert result is not None
        # Lexicographically lower header_hash wins when signer counts tie
        winner_hash = result[0]["header_hash"]
        assert winner_hash == min(ha["header_hash"], hb["header_hash"])

    def test_replay_epoch_filtered_out(self):
        registry = _make_registry()
        header, cert = _make_signed_candidate(registry)
        # Candidate epoch < current_epoch → filtered
        result = resolve_canonical_fork(
            [(header, cert)], registry, current_epoch=cert["federation_epoch"] + 1
        )
        assert result is None

    def test_negative_epoch_raises(self):
        registry = _make_registry()
        header, cert = _make_signed_candidate(registry)
        with pytest.raises(ValueError, match="epoch must be an integer >= 0"):
            resolve_canonical_fork([(header, cert)], registry, current_epoch=-1)

    def test_negative_clock_skew_raises(self):
        registry = _make_registry()
        header, cert = _make_signed_candidate(registry)
        with pytest.raises(ValueError, match="max_clock_skew_seconds must be >= 0"):
            resolve_canonical_fork([(header, cert)], registry, max_clock_skew_seconds=-1)

    def test_invalid_quorum_certificate_filtered(self):
        registry = _make_registry()
        header, cert = _make_signed_candidate(registry)
        # Tamper with signature to make cert invalid
        cert["signatures"][0]["signature"] = "00" * 64
        result = resolve_canonical_fork([(header, cert)], registry)
        assert result is None

    def test_mismatched_slot_raises(self):
        registry = _make_registry()
        h1, c1 = _make_signed_candidate(registry, height=1)
        h2, c2 = _make_signed_candidate(registry, height=2, root_hex="22" * 32)
        with pytest.raises(ValueError, match="same shard_id, height, and round"):
            resolve_canonical_fork([(h1, c1), (h2, c2)], registry)

    def test_malformed_timestamp_in_cert_skipped(self):
        registry = _make_registry()
        header, cert = _make_signed_candidate(registry)
        cert["timestamp"] = "not-a-timestamp"
        result = resolve_canonical_fork([(header, cert)], registry)
        assert result is None


# ---------------------------------------------------------------------------
# Proactive share commitments
# ---------------------------------------------------------------------------


class TestProactiveShareCommitments:
    def test_build_returns_commitments_for_all_active_nodes(self):
        registry = _make_registry()
        commitments = build_proactive_share_commitments(registry, epoch=1, refresh_nonce="abc")
        assert len(commitments) == len(list(registry.active_nodes()))
        for node in registry.active_nodes():
            assert node.node_id in commitments
            assert len(commitments[node.node_id]) == 64  # hex-encoded BLAKE3

    def test_deterministic_output(self):
        registry = _make_registry()
        c1 = build_proactive_share_commitments(registry, epoch=1, refresh_nonce="abc")
        c2 = build_proactive_share_commitments(registry, epoch=1, refresh_nonce="abc")
        assert c1 == c2

    def test_different_epoch_different_commitments(self):
        registry = _make_registry()
        c1 = build_proactive_share_commitments(registry, epoch=1, refresh_nonce="abc")
        c2 = build_proactive_share_commitments(registry, epoch=2, refresh_nonce="abc")
        assert c1 != c2

    def test_different_nonce_different_commitments(self):
        registry = _make_registry()
        c1 = build_proactive_share_commitments(registry, epoch=1, refresh_nonce="abc")
        c2 = build_proactive_share_commitments(registry, epoch=1, refresh_nonce="xyz")
        assert c1 != c2

    def test_negative_epoch_raises(self):
        registry = _make_registry()
        with pytest.raises(ValueError, match="non-negative"):
            build_proactive_share_commitments(registry, epoch=-1, refresh_nonce="abc")

    def test_empty_nonce_raises(self):
        registry = _make_registry()
        with pytest.raises(ValueError, match="non-empty"):
            build_proactive_share_commitments(registry, epoch=1, refresh_nonce="")

    def test_verify_matching_commitments(self):
        registry = _make_registry()
        commitments = build_proactive_share_commitments(registry, epoch=1, refresh_nonce="abc")
        assert verify_proactive_share_commitments(
            registry, epoch=1, refresh_nonce="abc", commitments=commitments
        )

    def test_verify_mismatched_commitments(self):
        registry = _make_registry()
        commitments = build_proactive_share_commitments(registry, epoch=1, refresh_nonce="abc")
        # Tamper with one commitment
        first_key = next(iter(commitments))
        commitments[first_key] = "ff" * 32
        assert not verify_proactive_share_commitments(
            registry, epoch=1, refresh_nonce="abc", commitments=commitments
        )


# ---------------------------------------------------------------------------
# detect_compromise_signals
# ---------------------------------------------------------------------------


class TestDetectCompromiseSignals:
    def test_empty_samples_returns_empty(self):
        assert detect_compromise_signals([]) == {}

    def test_no_compromise_with_normal_behavior(self):
        samples = [
            FederationBehaviorSample("node-1", 1, "aa" * 32),
            FederationBehaviorSample("node-2", 1, "aa" * 32),
        ]
        result = detect_compromise_signals(samples)
        assert result == {}

    def test_double_vote_detected(self):
        samples = [
            FederationBehaviorSample("node-1", 1, "aa" * 32),
            FederationBehaviorSample("node-1", 1, "bb" * 32),  # different hash, same round
        ]
        result = detect_compromise_signals(samples)
        assert "node-1" in result
        assert "double_vote_detected" in result["node-1"]

    def test_participation_spike_detected(self):
        # node-1 has many samples, others have 1 each
        samples = [FederationBehaviorSample("node-1", i, "aa" * 32) for i in range(20)]
        samples.append(FederationBehaviorSample("node-2", 1, "bb" * 32))
        samples.append(FederationBehaviorSample("node-3", 1, "cc" * 32))
        result = detect_compromise_signals(samples, spike_multiplier=2.0)
        assert "node-1" in result
        assert "participation_spike_detected" in result["node-1"]

    def test_spike_multiplier_below_one_raises(self):
        with pytest.raises(ValueError, match="spike_multiplier must be >= 1.0"):
            detect_compromise_signals([], spike_multiplier=0.5)

    def test_double_vote_and_spike_combined(self):
        # node-1 double-votes AND has a spike
        samples = [FederationBehaviorSample("node-1", i, f"{i:064x}") for i in range(30)]
        samples[1] = FederationBehaviorSample("node-1", 0, "ff" * 32)  # double vote on round 0
        samples.append(FederationBehaviorSample("node-2", 1, "bb" * 32))
        result = detect_compromise_signals(samples, spike_multiplier=1.5)
        assert "node-1" in result
        signals = result["node-1"]
        assert "double_vote_detected" in signals
        assert "participation_spike_detected" in signals


# ---------------------------------------------------------------------------
# VRF selection scores and committee
# ---------------------------------------------------------------------------


class TestVRFSelection:
    def test_vrf_scores_deterministic(self):
        registry = _make_registry()
        s1 = vrf_selection_scores(shard_id="test", round_number=0, registry=registry)
        s2 = vrf_selection_scores(shard_id="test", round_number=0, registry=registry)
        assert s1 == s2

    def test_vrf_scores_returns_all_active_nodes(self):
        registry = _make_registry()
        scores = vrf_selection_scores(shard_id="test", round_number=0, registry=registry)
        active_nodes = list(registry.active_nodes())
        assert len(scores) == len(active_nodes)

    def test_vrf_scores_sorted_by_score(self):
        registry = _make_registry()
        scores = vrf_selection_scores(shard_id="test", round_number=0, registry=registry)
        score_values = [s for _, s in scores]
        assert score_values == sorted(score_values)

    def test_different_rounds_give_different_scores(self):
        registry = _make_registry()
        s1 = vrf_selection_scores(shard_id="test", round_number=0, registry=registry)
        s2 = vrf_selection_scores(shard_id="test", round_number=1, registry=registry)
        assert s1 != s2

    def test_negative_round_raises(self):
        registry = _make_registry()
        with pytest.raises(ValueError, match="non-negative"):
            vrf_selection_scores(shard_id="test", round_number=-1, registry=registry)

    def test_negative_epoch_raises(self):
        registry = _make_registry()
        with pytest.raises(ValueError, match="non-negative"):
            vrf_selection_scores(shard_id="test", round_number=0, registry=registry, epoch=-1)

    def test_invalid_round_entropy_raises(self):
        registry = _make_registry()
        with pytest.raises(ValueError, match="valid hex string"):
            vrf_selection_scores(
                shard_id="test", round_number=0, registry=registry, round_entropy="not-hex!"
            )

    def test_round_entropy_changes_scores(self):
        registry = _make_registry()
        s1 = vrf_selection_scores(shard_id="test", round_number=0, registry=registry)
        s2 = vrf_selection_scores(
            shard_id="test", round_number=0, registry=registry, round_entropy="aa" * 32
        )
        assert s1 != s2


class TestVRFCommittee:
    def test_select_committee(self):
        registry = _make_registry()
        committee = select_vrf_committee(
            shard_id="test", round_number=0, registry=registry, committee_size=2
        )
        assert len(committee) == 2
        assert all(isinstance(nid, str) for nid in committee)

    def test_committee_size_too_large_raises(self):
        registry = _make_registry()
        with pytest.raises(ValueError, match="cannot exceed"):
            select_vrf_committee(
                shard_id="test", round_number=0, registry=registry, committee_size=100
            )

    def test_committee_size_zero_raises(self):
        registry = _make_registry()
        with pytest.raises(ValueError, match="positive"):
            select_vrf_committee(
                shard_id="test", round_number=0, registry=registry, committee_size=0
            )

    def test_select_leader(self):
        registry = _make_registry()
        leader = select_vrf_leader(shard_id="test", round_number=0, registry=registry)
        assert isinstance(leader, str)

    def test_leader_is_first_committee_member(self):
        registry = _make_registry()
        leader = select_vrf_leader(shard_id="test", round_number=0, registry=registry)
        committee = select_vrf_committee(
            shard_id="test", round_number=0, registry=registry, committee_size=1
        )
        assert leader == committee[0]


# ---------------------------------------------------------------------------
# Commit-reveal and entropy derivation
# ---------------------------------------------------------------------------


class TestCommitRevealEntropy:
    def test_build_reveal_commitment_deterministic(self):
        c1 = build_vrf_reveal_commitment(node_id="node-1", reveal="secret")
        c2 = build_vrf_reveal_commitment(node_id="node-1", reveal="secret")
        assert c1 == c2
        assert len(c1) == 64  # hex-encoded BLAKE3

    def test_different_reveal_different_commitment(self):
        c1 = build_vrf_reveal_commitment(node_id="node-1", reveal="secret-a")
        c2 = build_vrf_reveal_commitment(node_id="node-1", reveal="secret-b")
        assert c1 != c2

    def test_different_node_different_commitment(self):
        c1 = build_vrf_reveal_commitment(node_id="node-1", reveal="secret")
        c2 = build_vrf_reveal_commitment(node_id="node-2", reveal="secret")
        assert c1 != c2

    def test_derive_entropy_basic(self):
        commitment = build_vrf_reveal_commitment(node_id="node-1", reveal="secret")
        entropy = derive_vrf_round_entropy(
            shard_id="test",
            round_number=0,
            epoch=1,
            commitments={"node-1": commitment},
            reveals={"node-1": "secret"},
        )
        assert len(entropy) == 64  # hex-encoded

    def test_derive_entropy_deterministic(self):
        commitment = build_vrf_reveal_commitment(node_id="node-1", reveal="secret")
        e1 = derive_vrf_round_entropy(
            shard_id="test",
            round_number=0,
            epoch=1,
            commitments={"node-1": commitment},
            reveals={"node-1": "secret"},
        )
        e2 = derive_vrf_round_entropy(
            shard_id="test",
            round_number=0,
            epoch=1,
            commitments={"node-1": commitment},
            reveals={"node-1": "secret"},
        )
        assert e1 == e2

    def test_derive_entropy_mismatched_reveal_raises(self):
        commitment = build_vrf_reveal_commitment(node_id="node-1", reveal="secret")
        with pytest.raises(ValueError, match="does not match commitment"):
            derive_vrf_round_entropy(
                shard_id="test",
                round_number=0,
                epoch=1,
                commitments={"node-1": commitment},
                reveals={"node-1": "wrong-secret"},
            )

    def test_derive_entropy_missing_commitment_raises(self):
        with pytest.raises(ValueError, match="Missing commitment"):
            derive_vrf_round_entropy(
                shard_id="test",
                round_number=0,
                epoch=1,
                commitments={},
                reveals={"node-1": "secret"},
            )

    def test_derive_entropy_negative_round_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            derive_vrf_round_entropy(
                shard_id="test",
                round_number=-1,
                epoch=1,
                commitments={},
                reveals={"node-1": "secret"},
            )

    def test_derive_entropy_negative_epoch_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            derive_vrf_round_entropy(
                shard_id="test",
                round_number=0,
                epoch=-1,
                commitments={},
                reveals={"node-1": "secret"},
            )

    def test_derive_entropy_empty_reveals_raises(self):
        with pytest.raises(ValueError, match="At least one reveal"):
            derive_vrf_round_entropy(
                shard_id="test",
                round_number=0,
                epoch=1,
                commitments={},
                reveals={},
            )

    def test_derive_entropy_with_proof_transcript_hashes(self):
        commitment = build_vrf_reveal_commitment(node_id="node-1", reveal="secret")
        entropy = derive_vrf_round_entropy(
            shard_id="test",
            round_number=0,
            epoch=1,
            commitments={"node-1": commitment},
            reveals={"node-1": "secret"},
            proof_transcript_hashes={"node-1": "cc" * 32},
        )
        assert len(entropy) == 64

    def test_derive_entropy_missing_proof_transcript_hash_raises(self):
        commitment = build_vrf_reveal_commitment(node_id="node-1", reveal="secret")
        with pytest.raises(ValueError, match="Missing proof transcript hash"):
            derive_vrf_round_entropy(
                shard_id="test",
                round_number=0,
                epoch=1,
                commitments={"node-1": commitment},
                reveals={"node-1": "secret"},
                proof_transcript_hashes={"node-2": "dd" * 32},  # wrong node
            )


# ---------------------------------------------------------------------------
# append_quorum_certificate_to_ledger
# ---------------------------------------------------------------------------


class TestAppendQuorumCertificateToLedger:
    def test_appends_entry(self):
        registry = _make_registry()
        header = create_shard_header(
            shard_id="records/city-a",
            root_hash=bytes.fromhex("11" * 32),
            timestamp="2026-03-17T00:00:00Z",
        )
        sigs = [
            sign_federated_header(header, "olympus-node-1", _test_signing_key(1), registry),
            sign_federated_header(header, "olympus-node-2", _test_signing_key(2), registry),
        ]
        ledger = Ledger()
        entry = append_quorum_certificate_to_ledger(
            ledger=ledger,
            header=header,
            signatures=sigs,
            registry=registry,
            canonicalization={"format": "json", "version": "1.0"},
        )
        assert entry is not None
        assert len(ledger.entries) == 1
        assert entry.shard_id == "records/city-a"
