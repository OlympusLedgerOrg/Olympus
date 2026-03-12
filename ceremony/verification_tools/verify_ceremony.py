#!/usr/bin/env python3
"""
Ceremony Verification Script

This is the main public verification script that allows anyone to independently
verify a trusted setup ceremony. It requires only the transcript files and
optional network access to the drand beacon.

Usage:
    python -m ceremony.verification_tools.verify_ceremony ceremony/transcript/ceremony_id.json
    python -m ceremony.verification_tools.verify_ceremony --help

The script verifies:
1. Chain integrity (each contribution builds on the previous)
2. Signature validity (all contributions are properly signed)
3. Beacon binding (randomness is anchored to public beacon)
4. Hash consistency (all hashes match their computed values)
5. Minimum contributor requirements (≥3 for production)

Exit codes:
    0 - Verification successful
    1 - Verification failed
    2 - Invalid arguments or missing files
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .transcript import CeremonyPhase, load_transcript, verify_transcript


def print_header(text: str) -> None:
    """Print a section header."""
    print(f"\n{'=' * 60}")
    print(f" {text}")
    print("=" * 60)


def print_success(text: str) -> None:
    """Print a success message."""
    print(f"✓ {text}")


def print_failure(text: str) -> None:
    """Print a failure message."""
    print(f"✗ {text}")


def print_warning(text: str) -> None:
    """Print a warning message."""
    print(f"⚠ {text}")


def print_info(text: str) -> None:
    """Print an info message."""
    print(f"  {text}")


def verify_ceremony_verbose(transcript_path: Path, *, require_production: bool = False) -> bool:
    """
    Verify a ceremony transcript with verbose output.

    Args:
        transcript_path: Path to the transcript JSON file
        require_production: If True, require ≥3 contributors per phase

    Returns:
        True if verification passed, False otherwise
    """
    print_header("OLYMPUS TRUSTED SETUP CEREMONY VERIFICATION")
    print_info(f"Transcript: {transcript_path}")

    # Load transcript
    try:
        transcript = load_transcript(transcript_path)
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        print_failure(f"Failed to load transcript: {e}")
        return False

    print_info(f"Transcript ID: {transcript.transcript_id}")
    print_info(f"Circuit: {transcript.circuit_name} v{transcript.circuit_version}")
    print_info(f"Phase: {transcript.phase.value}")

    # Verify basic transcript integrity
    print_header("1. TRANSCRIPT INTEGRITY")

    is_valid, errors = verify_transcript(transcript)

    if is_valid:
        print_success("Transcript structure is valid")
    else:
        print_failure("Transcript structure is INVALID:")
        for error in errors:
            print_info(f"- {error}")
        return False

    # Verify participants
    print_header("2. PARTICIPANTS")
    print_info(f"Registered participants: {len(transcript.participants)}")

    for i, participant in enumerate(transcript.participants, 1):
        print_info(f"  {i}. {participant.name} ({participant.participant_id})")
        print_info(f"     Key: {participant.pubkey[:16]}...{participant.pubkey[-8:]}")
        if participant.attestation_url:
            print_info(f"     Attestation: {participant.attestation_url}")

    # Verify Phase 1 contributions
    print_header("3. PHASE 1 (POWERS OF TAU)")
    print_info(f"Contributions: {len(transcript.phase1_entries)}")

    if not transcript.phase1_entries:
        print_warning("No Phase 1 contributions (acceptable for development)")
    else:
        for i, entry in enumerate(transcript.phase1_entries, 1):
            contrib = entry.contribution
            participant_name = "Unknown"
            for p in transcript.participants:
                if p.pubkey == contrib.participant_pubkey:
                    participant_name = p.name
                    break

            print_info(f"  {i}. {participant_name}")
            print_info(
                f"     Hash: {entry.contribution_hash[:16]}...{entry.contribution_hash[-8:]}"
            )
            print_info(f"     Time: {contrib.timestamp}")
            if contrib.beacon_round:
                print_info(f"     Beacon: round {contrib.beacon_round.round_number}")

    # Verify Phase 2 contributions
    print_header("4. PHASE 2 (CIRCUIT-SPECIFIC)")
    print_info(f"Contributions: {len(transcript.phase2_entries)}")

    if not transcript.phase2_entries:
        print_warning("No Phase 2 contributions (ceremony incomplete)")
    else:
        for i, entry in enumerate(transcript.phase2_entries, 1):
            contrib = entry.contribution
            participant_name = "Unknown"
            for p in transcript.participants:
                if p.pubkey == contrib.participant_pubkey:
                    participant_name = p.name
                    break

            print_info(f"  {i}. {participant_name}")
            print_info(
                f"     Hash: {entry.contribution_hash[:16]}...{entry.contribution_hash[-8:]}"
            )
            print_info(f"     Time: {contrib.timestamp}")
            if contrib.beacon_round:
                print_info(f"     Beacon: round {contrib.beacon_round.round_number}")

    # Verify finalization
    print_header("5. FINALIZATION")

    if transcript.phase == CeremonyPhase.FINALIZED:
        print_success("Ceremony is finalized")
        print_info(f"  End time: {transcript.ceremony_end}")
        print_info(f"  Verification key hash: {transcript.final_verification_key_hash[:32]}...")
        if transcript.final_beacon_anchor:
            print_info(f"  Final beacon: round {transcript.final_beacon_anchor.round_number}")
    else:
        print_warning(f"Ceremony not finalized (current phase: {transcript.phase.value})")

    # Production readiness check
    print_header("6. PRODUCTION READINESS")

    production_ready = True
    min_contributors = 3

    if len(transcript.phase1_entries) < min_contributors:
        print_warning(
            f"Phase 1 has {len(transcript.phase1_entries)} contributors (need ≥{min_contributors})"
        )
        production_ready = False

    if len(transcript.phase2_entries) < min_contributors:
        print_warning(
            f"Phase 2 has {len(transcript.phase2_entries)} contributors (need ≥{min_contributors})"
        )
        production_ready = False

    if transcript.phase != CeremonyPhase.FINALIZED:
        print_warning("Ceremony not finalized")
        production_ready = False

    # Check for unique contributors (same person shouldn't contribute twice)
    phase1_contributors = {e.contribution.participant_pubkey for e in transcript.phase1_entries}
    phase2_contributors = {e.contribution.participant_pubkey for e in transcript.phase2_entries}

    if len(phase1_contributors) < len(transcript.phase1_entries):
        print_warning("Some participants contributed multiple times to Phase 1")

    if len(phase2_contributors) < len(transcript.phase2_entries):
        print_warning("Some participants contributed multiple times to Phase 2")

    if production_ready:
        print_success("Ceremony meets production requirements")
    else:
        print_warning("Ceremony does NOT meet production requirements")
        if require_production:
            return False

    # Compute and display transcript hash
    print_header("7. TRANSCRIPT HASH")

    transcript_hash = transcript.compute_transcript_hash().hex()
    print_info(f"BLAKE3: {transcript_hash}")
    print_info("")
    print_info("Share this hash to allow others to verify they have")
    print_info("the same transcript.")

    # Final verdict
    print_header("VERIFICATION RESULT")

    print_success("All integrity checks passed")
    if production_ready:
        print_success("Ceremony is production-ready")
    else:
        print_warning("Ceremony is NOT production-ready (development only)")

    return True


def main() -> int:
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="Verify an Olympus trusted setup ceremony transcript",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Verify a ceremony transcript:
    python -m ceremony.verification_tools.verify_ceremony transcript.json

  Require production-level security:
    python -m ceremony.verification_tools.verify_ceremony --production transcript.json

Exit codes:
  0 - Verification successful
  1 - Verification failed
  2 - Invalid arguments or missing files
        """,
    )

    parser.add_argument(
        "transcript",
        type=Path,
        help="Path to the ceremony transcript JSON file",
    )

    parser.add_argument(
        "--production",
        action="store_true",
        help="Require production-level security (≥3 contributors per phase)",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output verification result as JSON",
    )

    args = parser.parse_args()

    if not args.transcript.exists():
        if args.json:
            print(json.dumps({"valid": False, "error": "Transcript file not found"}))
        else:
            print_failure(f"Transcript file not found: {args.transcript}")
        return 2

    if args.json:
        # JSON output mode - quiet verification
        try:
            transcript = load_transcript(args.transcript)
            is_valid, errors = verify_transcript(transcript)

            result = {
                "valid": is_valid,
                "transcript_id": transcript.transcript_id,
                "circuit": transcript.circuit_name,
                "version": transcript.circuit_version,
                "phase": transcript.phase.value,
                "phase1_contributors": len(transcript.phase1_entries),
                "phase2_contributors": len(transcript.phase2_entries),
                "finalized": transcript.phase == CeremonyPhase.FINALIZED,
                "transcript_hash": transcript.compute_transcript_hash().hex(),
                "errors": errors,
            }

            if args.production:
                production_ready = (
                    len(transcript.phase1_entries) >= 3
                    and len(transcript.phase2_entries) >= 3
                    and transcript.phase == CeremonyPhase.FINALIZED
                )
                result["production_ready"] = production_ready
                if not production_ready:
                    result["valid"] = False

            print(json.dumps(result, indent=2))
            return 0 if result["valid"] else 1

        except Exception as e:
            print(json.dumps({"valid": False, "error": str(e)}))
            return 1

    else:
        # Verbose output mode
        success = verify_ceremony_verbose(args.transcript, require_production=args.production)
        return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
