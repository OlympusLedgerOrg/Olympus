"""
Ceremony Verification Tools

This package provides Python tools for verifying Groth16 trusted setup ceremonies.
All verification is deterministic and independently reproducible.
"""

from ceremony.verification_tools.beacon import (
    BeaconRound,
    fetch_beacon_round,
    verify_beacon_randomness,
)
from ceremony.verification_tools.contribution import (
    Contribution,
    compute_contribution_hash,
    verify_contribution,
)
from ceremony.verification_tools.transcript import (
    CeremonyPhase,
    CeremonyTranscript,
    TranscriptEntry,
    load_transcript,
    verify_transcript,
)


__all__ = [
    # Beacon
    "BeaconRound",
    "fetch_beacon_round",
    "verify_beacon_randomness",
    # Contribution
    "Contribution",
    "compute_contribution_hash",
    "verify_contribution",
    # Transcript
    "CeremonyPhase",
    "CeremonyTranscript",
    "TranscriptEntry",
    "load_transcript",
    "verify_transcript",
]
