"""
Tests for recursive redaction proof composition (protocol/halo2_backend.py).

Coverage:
- RedactionEvent creation, hashing, and serialization
- RecursiveProofAccumulator event chaining and finalization
- RecursiveRedactionProof serialization round-trip
- verify_recursive_redaction_proof structural verification
- Tamper detection: modified event hashes, broken chain linkage
- Halo2Prover.prove_recursive and Halo2Verifier.verify_recursive
  raise NotImplementedError (Phase 1+)
"""

import pytest

from protocol.halo2_backend import (
    RECURSIVE_REDACTION_CIRCUIT,
    Halo2Prover,
    Halo2Verifier,
    RecursiveProofAccumulator,
    RecursiveRedactionProof,
    RedactionEvent,
    verify_recursive_redaction_proof,
)


# ---------------------------------------------------------------------------
# RedactionEvent
# ---------------------------------------------------------------------------


class TestRedactionEvent:
    """Tests for the RedactionEvent data model."""

    def test_creation(self):
        """Can create a RedactionEvent with all fields."""
        event = RedactionEvent(
            event_index=0,
            document_id="doc1",
            version=1,
            revealed_indices=[0, 2],
            original_root="999",
            redacted_commitment="111",
            revealed_count=2,
            timestamp="2026-03-12T18:00:00Z",
            zk_proof={"pi_a": []},
            previous_event_hash="",
        )
        assert event.event_index == 0
        assert event.document_id == "doc1"
        assert event.revealed_count == 2

    def test_compute_hash_deterministic(self):
        """Same event always produces the same hash."""
        event = RedactionEvent(
            event_index=0,
            document_id="doc1",
            version=1,
            revealed_indices=[0, 2],
            original_root="999",
            redacted_commitment="111",
            revealed_count=2,
            timestamp="2026-03-12T18:00:00Z",
            zk_proof={},
            previous_event_hash="",
        )
        h1 = event.compute_hash()
        h2 = event.compute_hash()
        assert h1 == h2
        assert len(h1) == 64  # 32 bytes hex

    def test_compute_hash_changes_with_index(self):
        """Different event_index produces a different hash."""
        base = dict(
            document_id="doc1",
            version=1,
            revealed_indices=[0],
            original_root="999",
            redacted_commitment="111",
            revealed_count=1,
            timestamp="2026-03-12T18:00:00Z",
            zk_proof={},
            previous_event_hash="",
        )
        e0 = RedactionEvent(event_index=0, **base)
        e1 = RedactionEvent(event_index=1, **base)
        assert e0.compute_hash() != e1.compute_hash()

    def test_serialization_round_trip(self):
        """to_dict / from_dict preserves all fields."""
        event = RedactionEvent(
            event_index=3,
            document_id="docX",
            version=4,
            revealed_indices=[1, 3, 5],
            original_root="12345",
            redacted_commitment="67890",
            revealed_count=3,
            timestamp="2026-01-01T00:00:00Z",
            zk_proof={"pi_a": ["a"], "pi_b": ["b"]},
            previous_event_hash="abcdef",
        )
        restored = RedactionEvent.from_dict(event.to_dict())
        assert restored == event

    def test_frozen(self):
        """RedactionEvent is immutable."""
        event = RedactionEvent(
            event_index=0,
            document_id="d",
            version=1,
            revealed_indices=[0],
            original_root="0",
            redacted_commitment="0",
            revealed_count=1,
            timestamp="t",
            zk_proof={},
            previous_event_hash="",
        )
        with pytest.raises(AttributeError):
            event.event_index = 5  # type: ignore[misc]


# ---------------------------------------------------------------------------
# RecursiveProofAccumulator
# ---------------------------------------------------------------------------


class TestRecursiveProofAccumulator:
    """Tests for the accumulator that chains redaction events."""

    def test_empty_accumulator(self):
        """Freshly created accumulator has zero events."""
        acc = RecursiveProofAccumulator(document_id="d", original_root="0")
        assert acc.event_count == 0
        assert acc.get_events() == []

    def test_add_single_event(self):
        """Adding one event returns it and increments the count."""
        acc = RecursiveProofAccumulator(document_id="d", original_root="0")
        event = acc.add_event(
            revealed_indices=[0],
            redacted_commitment="1",
            revealed_count=1,
            zk_proof={"dummy": True},
            timestamp="2026-03-12T18:00:00Z",
        )
        assert acc.event_count == 1
        assert event.event_index == 0
        assert event.previous_event_hash == ""

    def test_chain_linkage(self):
        """Second event references hash of first event."""
        acc = RecursiveProofAccumulator(document_id="d", original_root="0")
        e0 = acc.add_event(
            revealed_indices=[0],
            redacted_commitment="1",
            revealed_count=1,
            zk_proof={},
            timestamp="2026-03-12T18:00:00Z",
        )
        e1 = acc.add_event(
            revealed_indices=[1],
            redacted_commitment="2",
            revealed_count=1,
            zk_proof={},
            timestamp="2026-03-12T18:01:00Z",
        )
        assert e1.previous_event_hash == e0.compute_hash()
        assert e1.event_index == 1

    def test_add_event_rejects_empty_indices(self):
        """Empty revealed_indices raises ValueError."""
        acc = RecursiveProofAccumulator(document_id="d", original_root="0")
        with pytest.raises(ValueError, match="non-empty"):
            acc.add_event(
                revealed_indices=[],
                redacted_commitment="1",
                revealed_count=0,
                zk_proof={},
            )

    def test_add_event_rejects_negative_count(self):
        """Negative revealed_count raises ValueError."""
        acc = RecursiveProofAccumulator(document_id="d", original_root="0")
        with pytest.raises(ValueError, match="non-negative"):
            acc.add_event(
                revealed_indices=[0],
                redacted_commitment="1",
                revealed_count=-1,
                zk_proof={},
            )

    def test_finalize_produces_proof(self):
        """finalize() returns a RecursiveRedactionProof with correct metadata."""
        acc = RecursiveProofAccumulator(document_id="doc1", original_root="999")
        acc.add_event(
            revealed_indices=[0, 2],
            redacted_commitment="111",
            revealed_count=2,
            zk_proof={},
            timestamp="2026-03-12T18:00:00Z",
        )
        acc.add_event(
            revealed_indices=[1],
            redacted_commitment="222",
            revealed_count=1,
            zk_proof={},
            timestamp="2026-03-12T18:01:00Z",
        )

        proof = acc.finalize(ledger_root="aabbcc")
        assert proof.document_id == "doc1"
        assert proof.event_count == 2
        assert proof.original_root == "999"
        assert proof.ledger_root == "aabbcc"
        assert len(proof.event_hashes) == 2
        assert proof.current_state_hash == proof.event_hashes[-1]
        assert proof.recursive_proof == b""  # Phase 1+
        assert proof.timestamp != ""

    def test_finalize_without_events_raises(self):
        """finalize() with no events raises ValueError."""
        acc = RecursiveProofAccumulator(document_id="d", original_root="0")
        with pytest.raises(ValueError, match="no redaction events"):
            acc.finalize(ledger_root="root")

    def test_get_events_returns_copy(self):
        """get_events() returns a copy, not the internal list."""
        acc = RecursiveProofAccumulator(document_id="d", original_root="0")
        acc.add_event(
            revealed_indices=[0],
            redacted_commitment="1",
            revealed_count=1,
            zk_proof={},
        )
        events = acc.get_events()
        events.clear()
        assert acc.event_count == 1  # internal list unaffected


# ---------------------------------------------------------------------------
# RecursiveRedactionProof serialization
# ---------------------------------------------------------------------------


class TestRecursiveRedactionProofSerialization:
    """Tests for RecursiveRedactionProof to_dict / from_dict."""

    def test_round_trip(self):
        """Serialization and deserialization preserves all fields."""
        proof = RecursiveRedactionProof(
            document_id="doc1",
            event_count=3,
            current_state_hash="abc",
            original_root="999",
            ledger_root="fff",
            recursive_proof=b"\x01\x02\x03",
            proof_version="1.0.0",
            timestamp="2026-03-12T18:00:00Z",
            event_hashes=["h1", "h2", "h3"],
        )
        restored = RecursiveRedactionProof.from_dict(proof.to_dict())
        assert restored.document_id == proof.document_id
        assert restored.event_count == proof.event_count
        assert restored.current_state_hash == proof.current_state_hash
        assert restored.original_root == proof.original_root
        assert restored.ledger_root == proof.ledger_root
        assert restored.recursive_proof == proof.recursive_proof
        assert restored.proof_version == proof.proof_version
        assert restored.timestamp == proof.timestamp
        assert restored.event_hashes == proof.event_hashes

    def test_from_dict_defaults(self):
        """from_dict handles missing optional fields gracefully."""
        data = {
            "document_id": "d",
            "event_count": 1,
            "current_state_hash": "h",
            "original_root": "0",
            "ledger_root": "r",
            "recursive_proof": "",
        }
        proof = RecursiveRedactionProof.from_dict(data)
        assert proof.proof_version == "1.0.0"
        assert proof.timestamp == ""
        assert proof.event_hashes == []


# ---------------------------------------------------------------------------
# verify_recursive_redaction_proof
# ---------------------------------------------------------------------------


class TestVerifyRecursiveRedactionProof:
    """Tests for the structural verification function."""

    @staticmethod
    def _make_accumulator_and_proof():
        """Helper: build a 3-event accumulator and finalize."""
        acc = RecursiveProofAccumulator(document_id="doc1", original_root="999")
        acc.add_event(
            revealed_indices=[0],
            redacted_commitment="c1",
            revealed_count=1,
            zk_proof={},
            timestamp="2026-03-12T18:00:00Z",
        )
        acc.add_event(
            revealed_indices=[1, 2],
            redacted_commitment="c2",
            revealed_count=2,
            zk_proof={},
            timestamp="2026-03-12T18:01:00Z",
        )
        acc.add_event(
            revealed_indices=[0, 1, 2],
            redacted_commitment="c3",
            revealed_count=3,
            zk_proof={},
            timestamp="2026-03-12T18:02:00Z",
        )
        events = acc.get_events()
        proof = acc.finalize(ledger_root="ledger_root_abc")
        return events, proof

    def test_valid_proof_without_events(self):
        """Structural verification passes without supplying events."""
        _, proof = self._make_accumulator_and_proof()
        assert verify_recursive_redaction_proof(proof) is True

    def test_valid_proof_with_events(self):
        """Full verification passes when original events are provided."""
        events, proof = self._make_accumulator_and_proof()
        assert verify_recursive_redaction_proof(proof, events=events) is True

    def test_rejects_zero_event_count(self):
        """Proof with event_count=0 is rejected."""
        proof = RecursiveRedactionProof(
            document_id="d",
            event_count=0,
            current_state_hash="",
            original_root="0",
            ledger_root="r",
            recursive_proof=b"",
            event_hashes=[],
        )
        assert verify_recursive_redaction_proof(proof) is False

    def test_rejects_mismatched_event_count(self):
        """Proof is rejected when event_count != len(event_hashes)."""
        _, proof = self._make_accumulator_and_proof()
        # Tamper: claim there are 2 events but keep 3 hashes
        proof.event_count = 2
        assert verify_recursive_redaction_proof(proof) is False

    def test_rejects_wrong_current_state_hash(self):
        """Proof is rejected when current_state_hash doesn't match last hash."""
        _, proof = self._make_accumulator_and_proof()
        proof.current_state_hash = "tampered"
        assert verify_recursive_redaction_proof(proof) is False

    def test_rejects_tampered_event_hash(self):
        """Verification fails if an event hash in the proof was tampered."""
        events, proof = self._make_accumulator_and_proof()
        proof.event_hashes[1] = "bad_hash"
        assert verify_recursive_redaction_proof(proof, events=events) is False

    def test_rejects_wrong_event_list_length(self):
        """Verification fails if event list length doesn't match."""
        events, proof = self._make_accumulator_and_proof()
        assert verify_recursive_redaction_proof(proof, events=events[:2]) is False

    def test_rejects_broken_chain_linkage(self):
        """Verification detects broken previous_event_hash linkage."""
        acc = RecursiveProofAccumulator(document_id="d", original_root="0")
        acc.add_event(
            revealed_indices=[0],
            redacted_commitment="c1",
            revealed_count=1,
            zk_proof={},
            timestamp="2026-01-01T00:00:00Z",
        )
        acc.add_event(
            revealed_indices=[1],
            redacted_commitment="c2",
            revealed_count=1,
            zk_proof={},
            timestamp="2026-01-01T00:01:00Z",
        )

        events = acc.get_events()
        proof = acc.finalize(ledger_root="root")

        # Manually create a tampered second event with wrong linkage
        tampered_e1 = RedactionEvent(
            event_index=events[1].event_index,
            document_id=events[1].document_id,
            version=events[1].version,
            revealed_indices=events[1].revealed_indices,
            original_root=events[1].original_root,
            redacted_commitment=events[1].redacted_commitment,
            revealed_count=events[1].revealed_count,
            timestamp=events[1].timestamp,
            zk_proof=events[1].zk_proof,
            previous_event_hash="wrong_hash",
        )

        # The tampered event has a different hash, so it won't match event_hashes
        tampered_events = [events[0], tampered_e1]
        assert verify_recursive_redaction_proof(proof, events=tampered_events) is False

    def test_rejects_non_empty_first_event_previous_hash(self):
        """First event must have empty previous_event_hash."""
        # Build a single event with non-empty previous_event_hash
        bad_event = RedactionEvent(
            event_index=0,
            document_id="d",
            version=1,
            revealed_indices=[0],
            original_root="0",
            redacted_commitment="1",
            revealed_count=1,
            timestamp="2026-01-01T00:00:00Z",
            zk_proof={},
            previous_event_hash="should_be_empty",
        )
        proof = RecursiveRedactionProof(
            document_id="d",
            event_count=1,
            current_state_hash=bad_event.compute_hash(),
            original_root="0",
            ledger_root="r",
            recursive_proof=b"",
            event_hashes=[bad_event.compute_hash()],
        )
        assert verify_recursive_redaction_proof(proof, events=[bad_event]) is False


# ---------------------------------------------------------------------------
# Halo2Prover / Halo2Verifier recursive methods (Phase 1+ placeholders)
# ---------------------------------------------------------------------------


class TestHalo2RecursivePlaceholders:
    """Confirm that recursive Halo2 methods raise NotImplementedError."""

    def test_prove_recursive_not_implemented(self):
        """Halo2Prover.prove_recursive raises NotImplementedError."""
        prover = Halo2Prover()
        with pytest.raises(NotImplementedError, match="Phase 1"):
            prover.prove_recursive(events=[], ledger_root="r")

    def test_verify_recursive_not_implemented(self):
        """Halo2Verifier.verify_recursive raises NotImplementedError."""
        verifier = Halo2Verifier()
        proof = RecursiveRedactionProof(
            document_id="d",
            event_count=1,
            current_state_hash="h",
            original_root="0",
            ledger_root="r",
            recursive_proof=b"",
            event_hashes=["h"],
        )
        with pytest.raises(NotImplementedError, match="Phase 1"):
            verifier.verify_recursive(proof)


# ---------------------------------------------------------------------------
# Integration: end-to-end accumulate → finalize → verify
# ---------------------------------------------------------------------------


class TestEndToEndRecursiveProof:
    """Integration tests for the full recursive proof flow."""

    def test_single_event_round_trip(self):
        """Single-event accumulation produces a verifiable proof."""
        acc = RecursiveProofAccumulator(document_id="doc1", original_root="12345")
        acc.add_event(
            revealed_indices=[0, 1],
            redacted_commitment="67890",
            revealed_count=2,
            zk_proof={"pi_a": [], "pi_b": [], "pi_c": []},
            timestamp="2026-03-12T20:00:00Z",
        )

        proof = acc.finalize(ledger_root="ledger_root_hex")
        events = acc.get_events()

        assert verify_recursive_redaction_proof(proof) is True
        assert verify_recursive_redaction_proof(proof, events=events) is True

    def test_many_events_round_trip(self):
        """Multiple-event accumulation verifies correctly."""
        acc = RecursiveProofAccumulator(document_id="doc2", original_root="99999")

        for i in range(10):
            acc.add_event(
                revealed_indices=[i % 5],
                redacted_commitment=str(i * 100),
                revealed_count=1,
                zk_proof={"event": i},
                timestamp=f"2026-03-12T18:{i:02d}:00Z",
            )

        proof = acc.finalize(ledger_root="some_root")
        events = acc.get_events()

        assert proof.event_count == 10
        assert len(proof.event_hashes) == 10
        assert verify_recursive_redaction_proof(proof) is True
        assert verify_recursive_redaction_proof(proof, events=events) is True

    def test_recursive_circuit_constant(self):
        """RECURSIVE_REDACTION_CIRCUIT constant is defined."""
        assert RECURSIVE_REDACTION_CIRCUIT == "recursive_redaction_composition"
