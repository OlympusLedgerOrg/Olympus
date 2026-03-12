"""
Ceremony Transcript Format and Verification

This module implements the ceremony transcript format and verification.
A transcript is a reproducible, verifiable record of a trusted setup ceremony.

Transcript Structure:
1. Header: Ceremony metadata (circuit name, version, dates)
2. Participants: List of registered participants with public keys
3. Phase 1 (PTAU): Powers of Tau contributions
4. Phase 2 (Circuit): Circuit-specific contributions
5. Finalization: Final verification key hash and beacon anchor

All transcripts are JSON files stored in the ceremony/transcript/ directory.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import blake3

from .beacon import BeaconRound, verify_beacon_randomness
from .contribution import (
    Contribution,
    ContributionPhase,
    compute_contribution_hash,
    verify_contribution,
)


# Domain separation prefix for transcript hashing
TRANSCRIPT_PREFIX = b"OLYMPUS:CEREMONY:TRANSCRIPT:V1"

# Genesis hash for the first contribution in each phase
GENESIS_HASH = "0" * 64


class CeremonyPhase(Enum):
    """Overall ceremony phase."""

    PHASE1 = "phase1"
    PHASE2 = "phase2"
    FINALIZED = "finalized"


@dataclass
class Participant:
    """
    A registered ceremony participant.

    Attributes:
        participant_id: Unique identifier for the participant
        name: Human-readable name
        pubkey: Ed25519 public key (hex-encoded)
        registration_timestamp: When the participant registered
        attestation_url: Optional URL to participant's attestation
    """

    participant_id: str
    name: str
    pubkey: str
    registration_timestamp: str
    attestation_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "participant_id": self.participant_id,
            "name": self.name,
            "pubkey": self.pubkey,
            "registration_timestamp": self.registration_timestamp,
            "attestation_url": self.attestation_url,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Participant:
        """Deserialize from dictionary."""
        return cls(
            participant_id=data["participant_id"],
            name=data["name"],
            pubkey=data["pubkey"],
            registration_timestamp=data["registration_timestamp"],
            attestation_url=data.get("attestation_url", ""),
        )


@dataclass
class TranscriptEntry:
    """
    A single entry in the ceremony transcript.

    This wraps a Contribution with additional transcript metadata.
    """

    contribution: Contribution
    contribution_hash: str
    verification_status: str = "pending"
    verification_timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "contribution": self.contribution.to_dict(),
            "contribution_hash": self.contribution_hash,
            "verification_status": self.verification_status,
            "verification_timestamp": self.verification_timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TranscriptEntry:
        """Deserialize from dictionary."""
        return cls(
            contribution=Contribution.from_dict(data["contribution"]),
            contribution_hash=data["contribution_hash"],
            verification_status=data.get("verification_status", "pending"),
            verification_timestamp=data.get("verification_timestamp", ""),
        )


@dataclass
class CeremonyTranscript:
    """
    A complete ceremony transcript.

    The transcript is append-only during the ceremony and becomes
    immutable once finalized.

    Attributes:
        transcript_id: Unique identifier for this transcript
        circuit_name: Name of the circuit (e.g., "redaction_validity")
        circuit_version: Version of the circuit
        ceremony_start: ISO 8601 timestamp of ceremony start
        ceremony_end: ISO 8601 timestamp of ceremony end (empty if ongoing)
        phase: Current phase of the ceremony
        ptau_source: Source of the Powers of Tau file
        participants: List of registered participants
        phase1_entries: Phase 1 (PTAU) transcript entries
        phase2_entries: Phase 2 (circuit-specific) transcript entries
        final_verification_key_hash: BLAKE3 hash of final vkey (after finalization)
        final_beacon_anchor: Beacon round used for finalization
    """

    transcript_id: str
    circuit_name: str
    circuit_version: str
    ceremony_start: str
    ceremony_end: str = ""
    phase: CeremonyPhase = CeremonyPhase.PHASE1
    ptau_source: str = ""
    participants: list[Participant] = field(default_factory=list)
    phase1_entries: list[TranscriptEntry] = field(default_factory=list)
    phase2_entries: list[TranscriptEntry] = field(default_factory=list)
    final_verification_key_hash: str = ""
    final_beacon_anchor: BeaconRound | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON storage."""
        return {
            "transcript_id": self.transcript_id,
            "circuit_name": self.circuit_name,
            "circuit_version": self.circuit_version,
            "ceremony_start": self.ceremony_start,
            "ceremony_end": self.ceremony_end,
            "phase": self.phase.value,
            "ptau_source": self.ptau_source,
            "participants": [p.to_dict() for p in self.participants],
            "phase1_entries": [e.to_dict() for e in self.phase1_entries],
            "phase2_entries": [e.to_dict() for e in self.phase2_entries],
            "final_verification_key_hash": self.final_verification_key_hash,
            "final_beacon_anchor": (
                self.final_beacon_anchor.to_dict() if self.final_beacon_anchor else None
            ),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CeremonyTranscript:
        """Deserialize from dictionary."""
        final_beacon = data.get("final_beacon_anchor")
        return cls(
            transcript_id=data["transcript_id"],
            circuit_name=data["circuit_name"],
            circuit_version=data["circuit_version"],
            ceremony_start=data["ceremony_start"],
            ceremony_end=data.get("ceremony_end", ""),
            phase=CeremonyPhase(data["phase"]),
            ptau_source=data.get("ptau_source", ""),
            participants=[Participant.from_dict(p) for p in data.get("participants", [])],
            phase1_entries=[TranscriptEntry.from_dict(e) for e in data.get("phase1_entries", [])],
            phase2_entries=[TranscriptEntry.from_dict(e) for e in data.get("phase2_entries", [])],
            final_verification_key_hash=data.get("final_verification_key_hash", ""),
            final_beacon_anchor=BeaconRound.from_dict(final_beacon) if final_beacon else None,
        )

    def add_participant(self, participant: Participant) -> None:
        """Add a participant to the ceremony."""
        if self.phase == CeremonyPhase.FINALIZED:
            raise ValueError("Cannot add participants to finalized ceremony")

        # Check for duplicate
        for existing in self.participants:
            if existing.participant_id == participant.participant_id:
                raise ValueError(f"Participant {participant.participant_id} already registered")
            if existing.pubkey == participant.pubkey:
                raise ValueError(f"Public key {participant.pubkey[:16]}... already registered")

        self.participants.append(participant)

    def add_contribution(self, contribution: Contribution) -> TranscriptEntry:
        """
        Add a contribution to the transcript.

        Args:
            contribution: The contribution to add

        Returns:
            The created transcript entry

        Raises:
            ValueError: If the contribution is invalid or out of sequence
        """
        if self.phase == CeremonyPhase.FINALIZED:
            raise ValueError("Cannot add contributions to finalized ceremony")

        # Verify participant is registered
        participant_found = False
        for participant in self.participants:
            if participant.pubkey == contribution.participant_pubkey:
                participant_found = True
                break

        if not participant_found:
            raise ValueError(
                f"Participant with pubkey {contribution.participant_pubkey[:16]}... not registered"
            )

        # Get expected previous hash and entries list
        if contribution.phase == ContributionPhase.PHASE1_PTAU:
            entries = self.phase1_entries
            if self.phase not in (CeremonyPhase.PHASE1, CeremonyPhase.PHASE2):
                raise ValueError("Phase 1 contributions only allowed in Phase 1")
        else:
            entries = self.phase2_entries
            if self.phase != CeremonyPhase.PHASE2:
                raise ValueError("Phase 2 contributions only allowed in Phase 2")

        expected_sequence = len(entries) + 1
        if contribution.sequence_number != expected_sequence:
            raise ValueError(
                f"Invalid sequence number: expected {expected_sequence}, "
                f"got {contribution.sequence_number}"
            )

        if entries:
            expected_previous = entries[-1].contribution_hash
        else:
            expected_previous = GENESIS_HASH

        # Verify contribution
        is_valid, errors = verify_contribution(
            contribution,
            expected_previous_hash=expected_previous,
            verify_signature=True,
        )

        if not is_valid:
            raise ValueError(f"Invalid contribution: {'; '.join(errors)}")

        # Compute contribution hash
        contribution_hash = compute_contribution_hash(contribution).hex()

        # Create entry
        from protocol.timestamps import current_timestamp

        entry = TranscriptEntry(
            contribution=contribution,
            contribution_hash=contribution_hash,
            verification_status="verified",
            verification_timestamp=current_timestamp(),
        )

        entries.append(entry)
        return entry

    def advance_to_phase2(self) -> None:
        """
        Advance the ceremony from Phase 1 to Phase 2.

        Requires at least one Phase 1 contribution.
        """
        if self.phase != CeremonyPhase.PHASE1:
            raise ValueError(f"Can only advance from Phase 1, currently in {self.phase.value}")

        if not self.phase1_entries:
            raise ValueError("At least one Phase 1 contribution required")

        self.phase = CeremonyPhase.PHASE2

    def finalize(
        self,
        verification_key_hash: str,
        beacon_anchor: BeaconRound | None = None,
    ) -> None:
        """
        Finalize the ceremony.

        Args:
            verification_key_hash: BLAKE3 hash of the final verification key
            beacon_anchor: Optional beacon round for final anchor

        Raises:
            ValueError: If ceremony cannot be finalized
        """
        if self.phase == CeremonyPhase.FINALIZED:
            raise ValueError("Ceremony already finalized")

        if self.phase != CeremonyPhase.PHASE2:
            raise ValueError("Must be in Phase 2 to finalize")

        if not self.phase2_entries:
            raise ValueError("At least one Phase 2 contribution required")

        from protocol.timestamps import current_timestamp

        self.final_verification_key_hash = verification_key_hash
        self.final_beacon_anchor = beacon_anchor
        self.ceremony_end = current_timestamp()
        self.phase = CeremonyPhase.FINALIZED

    def compute_transcript_hash(self) -> bytes:
        """
        Compute the overall transcript hash.

        This hash binds together the entire ceremony history.

        Returns:
            32-byte BLAKE3 hash
        """
        # Hash all contribution hashes in order
        all_hashes = []
        for entry in self.phase1_entries:
            all_hashes.append(entry.contribution_hash)
        for entry in self.phase2_entries:
            all_hashes.append(entry.contribution_hash)

        if self.final_verification_key_hash:
            all_hashes.append(self.final_verification_key_hash)

        combined = "|".join(all_hashes).encode("utf-8")
        return blake3.blake3(TRANSCRIPT_PREFIX + b"|" + combined).digest()


def load_transcript(path: Path) -> CeremonyTranscript:
    """
    Load a ceremony transcript from a JSON file.

    Args:
        path: Path to the transcript JSON file

    Returns:
        The deserialized CeremonyTranscript object

    Raises:
        ValueError: If the file cannot be parsed
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return CeremonyTranscript.from_dict(data)


def save_transcript(transcript: CeremonyTranscript, path: Path) -> None:
    """
    Save a ceremony transcript to a JSON file.

    Args:
        transcript: The transcript to save
        path: Path to write the JSON file
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(transcript.to_dict(), f, indent=2)
        f.write("\n")


def verify_transcript(transcript: CeremonyTranscript) -> tuple[bool, list[str]]:
    """
    Verify the integrity of a ceremony transcript.

    Checks:
    1. All contributions are valid and correctly sequenced
    2. All signatures are valid
    3. All beacon randomness is correctly derived
    4. Chain integrity is maintained

    Args:
        transcript: The transcript to verify

    Returns:
        Tuple of (is_valid, list of error messages)
    """
    errors: list[str] = []

    # Build participant pubkey index
    registered_pubkeys = {p.pubkey for p in transcript.participants}

    # Verify Phase 1 entries
    previous_hash = GENESIS_HASH
    for i, entry in enumerate(transcript.phase1_entries):
        contrib = entry.contribution

        # Check participant is registered
        if contrib.participant_pubkey not in registered_pubkeys:
            errors.append(f"Phase 1 entry {i + 1}: participant pubkey not registered")

        # Check sequence
        if contrib.sequence_number != i + 1:
            errors.append(
                f"Phase 1 entry {i + 1}: sequence mismatch "
                f"(expected {i + 1}, got {contrib.sequence_number})"
            )

        # Verify contribution
        is_valid, contrib_errors = verify_contribution(
            contrib,
            expected_previous_hash=previous_hash,
            verify_signature=True,
        )
        if not is_valid:
            for err in contrib_errors:
                errors.append(f"Phase 1 entry {i + 1}: {err}")

        # Verify contribution hash matches
        expected_hash = compute_contribution_hash(contrib).hex()
        if entry.contribution_hash != expected_hash:
            errors.append(
                f"Phase 1 entry {i + 1}: contribution hash mismatch "
                f"(expected {expected_hash[:16]}..., got {entry.contribution_hash[:16]}...)"
            )

        previous_hash = entry.contribution_hash

    # Verify Phase 2 entries
    previous_hash = GENESIS_HASH
    for i, entry in enumerate(transcript.phase2_entries):
        contrib = entry.contribution

        # Check participant is registered
        if contrib.participant_pubkey not in registered_pubkeys:
            errors.append(f"Phase 2 entry {i + 1}: participant pubkey not registered")

        # Check sequence
        if contrib.sequence_number != i + 1:
            errors.append(
                f"Phase 2 entry {i + 1}: sequence mismatch "
                f"(expected {i + 1}, got {contrib.sequence_number})"
            )

        # Verify contribution
        is_valid, contrib_errors = verify_contribution(
            contrib,
            expected_previous_hash=previous_hash,
            verify_signature=True,
        )
        if not is_valid:
            for err in contrib_errors:
                errors.append(f"Phase 2 entry {i + 1}: {err}")

        # Verify contribution hash matches
        expected_hash = compute_contribution_hash(contrib).hex()
        if entry.contribution_hash != expected_hash:
            errors.append(
                f"Phase 2 entry {i + 1}: contribution hash mismatch "
                f"(expected {expected_hash[:16]}..., got {entry.contribution_hash[:16]}...)"
            )

        previous_hash = entry.contribution_hash

    # Verify final beacon anchor if present
    if transcript.final_beacon_anchor:
        if not verify_beacon_randomness(transcript.final_beacon_anchor):
            errors.append("Final beacon anchor randomness verification failed")

    # Check minimum contribution requirements for finalized ceremonies
    if transcript.phase == CeremonyPhase.FINALIZED:
        if not transcript.phase1_entries:
            errors.append("Finalized ceremony has no Phase 1 contributions")
        if not transcript.phase2_entries:
            errors.append("Finalized ceremony has no Phase 2 contributions")
        if not transcript.final_verification_key_hash:
            errors.append("Finalized ceremony missing verification key hash")

    return len(errors) == 0, errors


def create_transcript(
    *,
    circuit_name: str,
    circuit_version: str,
    ptau_source: str = "",
) -> CeremonyTranscript:
    """
    Create a new ceremony transcript.

    Args:
        circuit_name: Name of the circuit
        circuit_version: Version of the circuit
        ptau_source: Source of the Powers of Tau file

    Returns:
        A new CeremonyTranscript object
    """
    from protocol.timestamps import current_timestamp

    # Generate transcript ID
    id_preimage = f"{circuit_name}|{circuit_version}|{current_timestamp()}"
    transcript_id = blake3.blake3(id_preimage.encode("utf-8")).hexdigest()[:16]

    return CeremonyTranscript(
        transcript_id=transcript_id,
        circuit_name=circuit_name,
        circuit_version=circuit_version,
        ceremony_start=current_timestamp(),
        ptau_source=ptau_source,
    )


if __name__ == "__main__":
    # CLI for transcript operations
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Transcript verification")
    parser.add_argument("--verify", type=Path, help="Verify a transcript file")
    parser.add_argument("--show", type=Path, help="Show transcript summary")
    parser.add_argument("--hash", type=Path, help="Compute transcript hash")

    args = parser.parse_args()

    if args.verify:
        transcript = load_transcript(args.verify)
        is_valid, errors = verify_transcript(transcript)
        if is_valid:
            print(f"✓ Transcript {transcript.transcript_id} verified successfully")
            print(f"  Circuit: {transcript.circuit_name} v{transcript.circuit_version}")
            print(f"  Phase 1 contributions: {len(transcript.phase1_entries)}")
            print(f"  Phase 2 contributions: {len(transcript.phase2_entries)}")
            print(f"  Status: {transcript.phase.value}")
            sys.exit(0)
        else:
            print(f"✗ Transcript {transcript.transcript_id} verification FAILED:")
            for error in errors:
                print(f"  - {error}")
            sys.exit(1)

    elif args.show:
        transcript = load_transcript(args.show)
        print(f"Transcript ID: {transcript.transcript_id}")
        print(f"Circuit: {transcript.circuit_name} v{transcript.circuit_version}")
        print(f"Phase: {transcript.phase.value}")
        print(f"Started: {transcript.ceremony_start}")
        if transcript.ceremony_end:
            print(f"Ended: {transcript.ceremony_end}")
        print(f"Participants: {len(transcript.participants)}")
        print(f"Phase 1 contributions: {len(transcript.phase1_entries)}")
        print(f"Phase 2 contributions: {len(transcript.phase2_entries)}")
        if transcript.final_verification_key_hash:
            print(f"Final vkey hash: {transcript.final_verification_key_hash[:32]}...")

    elif args.hash:
        transcript = load_transcript(args.hash)
        transcript_hash = transcript.compute_transcript_hash().hex()
        print(f"Transcript hash: {transcript_hash}")

    else:
        parser.print_help()
