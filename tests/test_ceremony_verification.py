"""
Tests for the ceremony verification tools.

These tests verify the integrity checking logic without requiring
actual trusted setup ceremonies or network access to the drand beacon.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from ceremony.verification_tools.beacon import (
    DRAND_GENESIS_TIME,
    DRAND_PERIOD,
    BeaconRound,
    compute_beacon_round_at_time,
    compute_first_beacon_round_after,
)
from ceremony.verification_tools.contribution import (
    Contribution,
    ContributionPhase,
    compute_artifact_hash,
    compute_contribution_hash,
    create_contribution,
    sign_contribution,
    verify_contribution,
)
from ceremony.verification_tools.transcript import (
    GENESIS_HASH,
    CeremonyPhase,
    Participant,
    create_transcript,
    load_transcript,
    save_transcript,
    verify_transcript,
)


# Test fixtures
@pytest.fixture
def sample_beacon_round() -> BeaconRound:
    """A sample beacon round with valid randomness."""
    # Note: This is synthetic data for testing
    return BeaconRound(
        round_number=12345,
        randomness="a" * 64,  # Synthetic - not a real beacon value
        signature="b" * 128,  # Synthetic signature
        previous_signature="c" * 128,  # Synthetic previous signature
        timestamp=DRAND_GENESIS_TIME + (12345 - 1) * DRAND_PERIOD,
    )


@pytest.fixture
def sample_keypair() -> tuple[str, str]:
    """Generate a test Ed25519 keypair."""
    import nacl.signing

    signing_key = nacl.signing.SigningKey.generate()
    private_key_hex = signing_key.encode().hex()
    public_key_hex = signing_key.verify_key.encode().hex()
    return private_key_hex, public_key_hex


@pytest.fixture
def sample_participant(sample_keypair: tuple[str, str]) -> Participant:
    """Create a sample participant."""
    _, public_key = sample_keypair
    return Participant(
        participant_id="test-participant-001",
        name="Test Contributor",
        pubkey=public_key,
        registration_timestamp="2024-01-01T00:00:00Z",
        attestation_url="https://example.com/attestation",
    )


class TestBeaconRound:
    """Tests for BeaconRound operations."""

    def test_beacon_round_to_dict(self, sample_beacon_round: BeaconRound) -> None:
        """Test serialization to dictionary."""
        data = sample_beacon_round.to_dict()
        assert data["round"] == 12345
        assert data["randomness"] == "a" * 64
        assert data["signature"] == "b" * 128

    def test_beacon_round_from_dict(self, sample_beacon_round: BeaconRound) -> None:
        """Test deserialization from dictionary."""
        data = sample_beacon_round.to_dict()
        restored = BeaconRound.from_dict(data)
        assert restored.round_number == sample_beacon_round.round_number
        assert restored.randomness == sample_beacon_round.randomness

    def test_beacon_round_hash_blake3(self, sample_beacon_round: BeaconRound) -> None:
        """Test BLAKE3 hashing of beacon round."""
        hash_bytes = sample_beacon_round.hash_blake3()
        assert len(hash_bytes) == 32
        # Same input should produce same hash
        assert hash_bytes == sample_beacon_round.hash_blake3()

    def test_compute_beacon_round_at_time(self) -> None:
        """Test computing beacon round from timestamp."""
        # Genesis time should give round 1
        assert compute_beacon_round_at_time(DRAND_GENESIS_TIME) == 1
        # One period after genesis should give round 2
        assert compute_beacon_round_at_time(DRAND_GENESIS_TIME + DRAND_PERIOD) == 2
        # 100 periods after genesis
        assert compute_beacon_round_at_time(DRAND_GENESIS_TIME + 100 * DRAND_PERIOD) == 101

    def test_compute_beacon_round_before_genesis_raises(self) -> None:
        """Test that timestamps before genesis raise ValueError."""
        with pytest.raises(ValueError, match="before drand genesis"):
            compute_beacon_round_at_time(DRAND_GENESIS_TIME - 1)

    def test_compute_first_beacon_round_after(self) -> None:
        """Test computing first beacon round after a timestamp."""
        # Just after genesis should give round 2
        result = compute_first_beacon_round_after(DRAND_GENESIS_TIME + 1)
        assert result == 2


class TestContribution:
    """Tests for Contribution operations."""

    def test_contribution_to_dict(
        self, sample_keypair: tuple[str, str], sample_beacon_round: BeaconRound
    ) -> None:
        """Test serialization to dictionary."""
        _, pubkey = sample_keypair
        contrib = Contribution(
            contribution_id="test-contrib-001",
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id="participant-001",
            participant_pubkey=pubkey,
            timestamp="2024-01-01T00:00:00Z",
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            beacon_round=sample_beacon_round,
        )

        data = contrib.to_dict()
        assert data["contribution_id"] == "test-contrib-001"
        assert data["phase"] == "phase1_ptau"
        assert data["sequence_number"] == 1

    def test_contribution_from_dict(
        self, sample_keypair: tuple[str, str], sample_beacon_round: BeaconRound
    ) -> None:
        """Test deserialization from dictionary."""
        _, pubkey = sample_keypair
        original = Contribution(
            contribution_id="test-contrib-001",
            phase=ContributionPhase.PHASE2_CIRCUIT,
            sequence_number=5,
            participant_id="participant-001",
            participant_pubkey=pubkey,
            timestamp="2024-01-01T00:00:00Z",
            previous_hash="e" * 64,
            artifact_hash="f" * 64,
            beacon_round=sample_beacon_round,
        )

        restored = Contribution.from_dict(original.to_dict())
        assert restored.contribution_id == original.contribution_id
        assert restored.phase == original.phase
        assert restored.sequence_number == original.sequence_number

    def test_contribution_hash_deterministic(self, sample_keypair: tuple[str, str]) -> None:
        """Test that contribution hash is deterministic."""
        _, pubkey = sample_keypair
        contrib = Contribution(
            contribution_id="test-contrib-001",
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id="participant-001",
            participant_pubkey=pubkey,
            timestamp="2024-01-01T00:00:00Z",
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            beacon_round=None,
        )

        hash1 = compute_contribution_hash(contrib)
        hash2 = compute_contribution_hash(contrib)
        assert hash1 == hash2
        assert len(hash1) == 32

    def test_contribution_hash_includes_beacon(
        self, sample_keypair: tuple[str, str], sample_beacon_round: BeaconRound
    ) -> None:
        """Test that beacon round affects contribution hash."""
        _, pubkey = sample_keypair

        contrib_no_beacon = Contribution(
            contribution_id="test-contrib-001",
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id="participant-001",
            participant_pubkey=pubkey,
            timestamp="2024-01-01T00:00:00Z",
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            beacon_round=None,
        )

        contrib_with_beacon = Contribution(
            contribution_id="test-contrib-001",
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id="participant-001",
            participant_pubkey=pubkey,
            timestamp="2024-01-01T00:00:00Z",
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            beacon_round=sample_beacon_round,
        )

        hash_no_beacon = compute_contribution_hash(contrib_no_beacon)
        hash_with_beacon = compute_contribution_hash(contrib_with_beacon)
        assert hash_no_beacon != hash_with_beacon

    def test_sign_and_verify_contribution(self, sample_keypair: tuple[str, str]) -> None:
        """Test signing and verifying a contribution."""
        private_key, pubkey = sample_keypair

        contrib = Contribution(
            contribution_id="test-contrib-001",
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id="participant-001",
            participant_pubkey=pubkey,
            timestamp="2024-01-01T00:00:00Z",
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            beacon_round=None,
        )

        # Sign
        signature = sign_contribution(contrib, private_key)
        contrib.signature = signature

        # Verify
        is_valid, errors = verify_contribution(contrib, verify_signature=True)
        assert is_valid, f"Verification failed: {errors}"

    def test_verify_contribution_invalid_signature(self, sample_keypair: tuple[str, str]) -> None:
        """Test that invalid signatures are rejected."""
        _, pubkey = sample_keypair

        contrib = Contribution(
            contribution_id="test-contrib-001",
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id="participant-001",
            participant_pubkey=pubkey,
            timestamp="2024-01-01T00:00:00Z",
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            beacon_round=None,
            signature="invalid" * 16,  # Wrong signature
        )

        is_valid, errors = verify_contribution(contrib, verify_signature=True)
        assert not is_valid
        assert any("Signature" in e or "signature" in e for e in errors)

    def test_verify_contribution_missing_signature(self, sample_keypair: tuple[str, str]) -> None:
        """Test that missing signatures are flagged."""
        _, pubkey = sample_keypair

        contrib = Contribution(
            contribution_id="test-contrib-001",
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id="participant-001",
            participant_pubkey=pubkey,
            timestamp="2024-01-01T00:00:00Z",
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            beacon_round=None,
            signature="",
        )

        is_valid, errors = verify_contribution(contrib, verify_signature=True)
        assert not is_valid
        assert any("Missing signature" in e for e in errors)

    def test_verify_contribution_without_signature_check(
        self, sample_keypair: tuple[str, str]
    ) -> None:
        """Test verification with signature check disabled."""
        _, pubkey = sample_keypair

        contrib = Contribution(
            contribution_id="test-contrib-001",
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id="participant-001",
            participant_pubkey=pubkey,
            timestamp="2024-01-01T00:00:00Z",
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            beacon_round=None,
            signature="",
        )

        is_valid, errors = verify_contribution(contrib, verify_signature=False)
        assert is_valid, f"Verification failed: {errors}"

    def test_create_contribution(self, sample_keypair: tuple[str, str]) -> None:
        """Test the create_contribution helper."""
        private_key, pubkey = sample_keypair

        contrib = create_contribution(
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id="participant-001",
            participant_pubkey=pubkey,
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            signing_key_hex=private_key,
        )

        assert contrib.contribution_id  # Should be auto-generated
        assert contrib.signature  # Should be signed
        assert contrib.timestamp  # Should have timestamp

        # Should verify
        is_valid, errors = verify_contribution(contrib, verify_signature=True)
        assert is_valid, f"Verification failed: {errors}"


class TestTranscript:
    """Tests for CeremonyTranscript operations."""

    def test_create_transcript(self) -> None:
        """Test creating a new transcript."""
        transcript = create_transcript(
            circuit_name="redaction_validity",
            circuit_version="1.0.0",
            ptau_source="hermez",
        )

        assert transcript.transcript_id
        assert transcript.circuit_name == "redaction_validity"
        assert transcript.circuit_version == "1.0.0"
        assert transcript.phase == CeremonyPhase.PHASE1

    def test_add_participant(self, sample_participant: Participant) -> None:
        """Test adding a participant to a transcript."""
        transcript = create_transcript(
            circuit_name="test_circuit",
            circuit_version="1.0.0",
        )

        transcript.add_participant(sample_participant)
        assert len(transcript.participants) == 1
        assert transcript.participants[0].participant_id == sample_participant.participant_id

    def test_add_duplicate_participant_raises(self, sample_participant: Participant) -> None:
        """Test that duplicate participants are rejected."""
        transcript = create_transcript(
            circuit_name="test_circuit",
            circuit_version="1.0.0",
        )

        transcript.add_participant(sample_participant)
        with pytest.raises(ValueError, match="already registered"):
            transcript.add_participant(sample_participant)

    def test_add_contribution_to_transcript(
        self, sample_keypair: tuple[str, str], sample_participant: Participant
    ) -> None:
        """Test adding a contribution to a transcript."""
        private_key, pubkey = sample_keypair
        transcript = create_transcript(
            circuit_name="test_circuit",
            circuit_version="1.0.0",
        )

        transcript.add_participant(sample_participant)

        contrib = create_contribution(
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id=sample_participant.participant_id,
            participant_pubkey=pubkey,
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            signing_key_hex=private_key,
        )

        entry = transcript.add_contribution(contrib)
        assert len(transcript.phase1_entries) == 1
        assert entry.contribution_hash

    def test_advance_to_phase2(
        self, sample_keypair: tuple[str, str], sample_participant: Participant
    ) -> None:
        """Test advancing from Phase 1 to Phase 2."""
        private_key, pubkey = sample_keypair
        transcript = create_transcript(
            circuit_name="test_circuit",
            circuit_version="1.0.0",
        )

        transcript.add_participant(sample_participant)

        # Add Phase 1 contribution
        contrib = create_contribution(
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id=sample_participant.participant_id,
            participant_pubkey=pubkey,
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            signing_key_hex=private_key,
        )
        transcript.add_contribution(contrib)

        # Advance
        transcript.advance_to_phase2()
        assert transcript.phase == CeremonyPhase.PHASE2

    def test_phase1_contribution_rejected_in_phase2(
        self, sample_keypair: tuple[str, str], sample_participant: Participant
    ) -> None:
        """Test that Phase 1 contributions are rejected after advancing to Phase 2."""
        private_key, pubkey = sample_keypair
        transcript = create_transcript(
            circuit_name="test_circuit",
            circuit_version="1.0.0",
        )

        transcript.add_participant(sample_participant)

        # Add Phase 1 contribution and advance to Phase 2
        contrib1 = create_contribution(
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id=sample_participant.participant_id,
            participant_pubkey=pubkey,
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            signing_key_hex=private_key,
        )
        transcript.add_contribution(contrib1)
        transcript.advance_to_phase2()

        # Try to add another Phase 1 contribution - should fail
        contrib2 = create_contribution(
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=2,
            participant_id=sample_participant.participant_id,
            participant_pubkey=pubkey,
            previous_hash=GENESIS_HASH,
            artifact_hash="e" * 64,
            signing_key_hex=private_key,
        )

        with pytest.raises(ValueError, match="Phase 1 contributions only allowed in Phase 1"):
            transcript.add_contribution(contrib2)

    def test_advance_to_phase2_without_contributions_raises(self) -> None:
        """Test that advancing without contributions raises."""
        transcript = create_transcript(
            circuit_name="test_circuit",
            circuit_version="1.0.0",
        )

        with pytest.raises(ValueError, match="At least one Phase 1"):
            transcript.advance_to_phase2()

    def test_finalize_transcript(
        self, sample_keypair: tuple[str, str], sample_participant: Participant
    ) -> None:
        """Test finalizing a transcript."""
        private_key, pubkey = sample_keypair
        transcript = create_transcript(
            circuit_name="test_circuit",
            circuit_version="1.0.0",
        )

        transcript.add_participant(sample_participant)

        # Add Phase 1 contribution
        contrib1 = create_contribution(
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id=sample_participant.participant_id,
            participant_pubkey=pubkey,
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            signing_key_hex=private_key,
        )
        transcript.add_contribution(contrib1)

        # Advance to Phase 2
        transcript.advance_to_phase2()

        # Add Phase 2 contribution
        contrib2 = create_contribution(
            phase=ContributionPhase.PHASE2_CIRCUIT,
            sequence_number=1,
            participant_id=sample_participant.participant_id,
            participant_pubkey=pubkey,
            previous_hash=GENESIS_HASH,
            artifact_hash="e" * 64,
            signing_key_hex=private_key,
        )
        transcript.add_contribution(contrib2)

        # Finalize
        vkey_hash = "f" * 64
        transcript.finalize(vkey_hash)

        assert transcript.phase == CeremonyPhase.FINALIZED
        assert transcript.final_verification_key_hash == vkey_hash
        assert transcript.ceremony_end

    def test_transcript_serialization_roundtrip(
        self, sample_keypair: tuple[str, str], sample_participant: Participant
    ) -> None:
        """Test saving and loading a transcript."""
        private_key, pubkey = sample_keypair
        transcript = create_transcript(
            circuit_name="test_circuit",
            circuit_version="1.0.0",
        )

        transcript.add_participant(sample_participant)

        contrib = create_contribution(
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id=sample_participant.participant_id,
            participant_pubkey=pubkey,
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            signing_key_hex=private_key,
        )
        transcript.add_contribution(contrib)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = Path(f.name)

        try:
            save_transcript(transcript, path)
            restored = load_transcript(path)

            assert restored.transcript_id == transcript.transcript_id
            assert restored.circuit_name == transcript.circuit_name
            assert len(restored.participants) == len(transcript.participants)
            assert len(restored.phase1_entries) == len(transcript.phase1_entries)
        finally:
            path.unlink(missing_ok=True)

    def test_verify_transcript_valid(
        self, sample_keypair: tuple[str, str], sample_participant: Participant
    ) -> None:
        """Test verifying a valid transcript."""
        private_key, pubkey = sample_keypair
        transcript = create_transcript(
            circuit_name="test_circuit",
            circuit_version="1.0.0",
        )

        transcript.add_participant(sample_participant)

        contrib = create_contribution(
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id=sample_participant.participant_id,
            participant_pubkey=pubkey,
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            signing_key_hex=private_key,
        )
        transcript.add_contribution(contrib)

        is_valid, errors = verify_transcript(transcript)
        assert is_valid, f"Verification failed: {errors}"

    def test_verify_transcript_chain_integrity(
        self, sample_keypair: tuple[str, str], sample_participant: Participant
    ) -> None:
        """Test that chain integrity is verified."""
        private_key, pubkey = sample_keypair
        transcript = create_transcript(
            circuit_name="test_circuit",
            circuit_version="1.0.0",
        )

        transcript.add_participant(sample_participant)

        # Add first contribution
        contrib1 = create_contribution(
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id=sample_participant.participant_id,
            participant_pubkey=pubkey,
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            signing_key_hex=private_key,
        )
        entry1 = transcript.add_contribution(contrib1)

        # Add second contribution chained to first
        contrib2 = create_contribution(
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=2,
            participant_id=sample_participant.participant_id,
            participant_pubkey=pubkey,
            previous_hash=entry1.contribution_hash,
            artifact_hash="e" * 64,
            signing_key_hex=private_key,
        )
        transcript.add_contribution(contrib2)

        is_valid, errors = verify_transcript(transcript)
        assert is_valid, f"Verification failed: {errors}"

    def test_transcript_hash_deterministic(
        self, sample_keypair: tuple[str, str], sample_participant: Participant
    ) -> None:
        """Test that transcript hash is deterministic."""
        private_key, pubkey = sample_keypair
        transcript = create_transcript(
            circuit_name="test_circuit",
            circuit_version="1.0.0",
        )

        transcript.add_participant(sample_participant)

        contrib = create_contribution(
            phase=ContributionPhase.PHASE1_PTAU,
            sequence_number=1,
            participant_id=sample_participant.participant_id,
            participant_pubkey=pubkey,
            previous_hash=GENESIS_HASH,
            artifact_hash="d" * 64,
            signing_key_hex=private_key,
        )
        transcript.add_contribution(contrib)

        hash1 = transcript.compute_transcript_hash()
        hash2 = transcript.compute_transcript_hash()
        assert hash1 == hash2
        assert len(hash1) == 32


class TestArtifactHashing:
    """Tests for artifact file hashing."""

    def test_compute_artifact_hash(self) -> None:
        """Test hashing an artifact file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test artifact content")
            path = Path(f.name)

        try:
            hash_hex = compute_artifact_hash(path)
            assert len(hash_hex) == 64  # 32 bytes as hex
            # Same content should give same hash
            assert compute_artifact_hash(path) == hash_hex
        finally:
            path.unlink(missing_ok=True)

    def test_compute_artifact_hash_different_content(self) -> None:
        """Test that different content gives different hashes."""
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(b"content A")
            path1 = Path(f1.name)

        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(b"content B")
            path2 = Path(f2.name)

        try:
            hash1 = compute_artifact_hash(path1)
            hash2 = compute_artifact_hash(path2)
            assert hash1 != hash2
        finally:
            path1.unlink(missing_ok=True)
            path2.unlink(missing_ok=True)
