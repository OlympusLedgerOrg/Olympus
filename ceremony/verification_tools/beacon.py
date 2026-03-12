"""
Deterministic Randomness Beacon Integration

This module provides integration with the drand (League of Entropy) randomness
beacon for ceremony contribution binding.

Protocol:
1. Each contribution round waits for a beacon round after the previous contribution
2. The beacon randomness is hashed into the contribution
3. This prevents grinding attacks where a malicious coordinator replays contributions

Beacon Source:
- Network: drand mainnet (https://api.drand.sh)
- Chain: default chain (8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce)
- Frequency: Every 30 seconds

Security Note:
The beacon binding is a defense-in-depth measure. The primary security
guarantee comes from the 1-of-N honest participant assumption.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

import blake3


# DRAND mainnet configuration
DRAND_MAINNET_URL = "https://api.drand.sh"
DRAND_CHAIN_HASH = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
DRAND_GENESIS_TIME = 1595431050
DRAND_PERIOD = 30  # seconds


@dataclass(frozen=True)
class BeaconRound:
    """
    A single drand beacon round.

    Attributes:
        round_number: The beacon round number (monotonically increasing)
        randomness: The 32-byte randomness value (hex-encoded)
        signature: BLS signature from the beacon (hex-encoded)
        previous_signature: BLS signature of the previous round (hex-encoded)
        timestamp: Unix timestamp when this round was published
    """

    round_number: int
    randomness: str
    signature: str
    previous_signature: str
    timestamp: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON storage."""
        return {
            "round": self.round_number,
            "randomness": self.randomness,
            "signature": self.signature,
            "previous_signature": self.previous_signature,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BeaconRound:
        """Deserialize from dictionary."""
        return cls(
            round_number=data["round"],
            randomness=data["randomness"],
            signature=data["signature"],
            previous_signature=data["previous_signature"],
            timestamp=data["timestamp"],
        )

    def hash_blake3(self) -> bytes:
        """
        Compute BLAKE3 hash of the beacon round for contribution binding.

        Returns:
            32-byte BLAKE3 hash
        """
        # Hash the canonical representation: round_number || randomness
        data = f"{self.round_number}|{self.randomness}".encode()
        return blake3.blake3(data).digest()

    def hash_sha256(self) -> bytes:
        """
        Compute SHA-256 hash for compatibility with drand verification.

        Returns:
            32-byte SHA-256 hash
        """
        # drand randomness is SHA-256(signature)
        return hashlib.sha256(bytes.fromhex(self.signature)).digest()


def compute_beacon_round_at_time(unix_time: int) -> int:
    """
    Compute which beacon round corresponds to a given Unix timestamp.

    Args:
        unix_time: Unix timestamp in seconds

    Returns:
        The beacon round number active at that time

    Raises:
        ValueError: If timestamp is before drand genesis
    """
    if unix_time < DRAND_GENESIS_TIME:
        raise ValueError(f"Timestamp {unix_time} is before drand genesis ({DRAND_GENESIS_TIME})")

    elapsed = unix_time - DRAND_GENESIS_TIME
    return (elapsed // DRAND_PERIOD) + 1


def compute_first_beacon_round_after(unix_time: int) -> int:
    """
    Compute the first beacon round after a given Unix timestamp.

    This is used to determine which beacon round to use for a contribution
    that was made at a specific time.

    Args:
        unix_time: Unix timestamp in seconds

    Returns:
        The first beacon round number after that time
    """
    current_round = compute_beacon_round_at_time(unix_time)
    # The round_number we computed is the round active at that time,
    # so the first round *after* is current_round + 1
    return current_round + 1


def fetch_beacon_round(
    round_number: int,
    *,
    base_url: str = DRAND_MAINNET_URL,
    chain_hash: str = DRAND_CHAIN_HASH,
    timeout: float = 30.0,
) -> BeaconRound:
    """
    Fetch a specific beacon round from the drand network.

    Args:
        round_number: The beacon round to fetch
        base_url: drand API base URL
        chain_hash: Chain hash identifier
        timeout: Request timeout in seconds

    Returns:
        The beacon round data

    Raises:
        ValueError: If the round cannot be fetched or is invalid
        RuntimeError: If network request fails
    """
    import urllib.error
    import urllib.request

    url = f"{base_url}/{chain_hash}/public/{round_number}"

    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to fetch beacon round {round_number}: {e}") from e
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON from beacon API: {e}") from e

    # Validate required fields
    required_fields = ["round", "randomness", "signature", "previous_signature"]
    for field in required_fields:
        if field not in data:
            raise ValueError(f"Beacon response missing field: {field}")

    # Compute timestamp from round number
    timestamp = DRAND_GENESIS_TIME + (data["round"] - 1) * DRAND_PERIOD

    return BeaconRound(
        round_number=data["round"],
        randomness=data["randomness"],
        signature=data["signature"],
        previous_signature=data["previous_signature"],
        timestamp=timestamp,
    )


def fetch_latest_beacon_round(
    *,
    base_url: str = DRAND_MAINNET_URL,
    chain_hash: str = DRAND_CHAIN_HASH,
    timeout: float = 30.0,
) -> BeaconRound:
    """
    Fetch the latest beacon round from the drand network.

    Args:
        base_url: drand API base URL
        chain_hash: Chain hash identifier
        timeout: Request timeout in seconds

    Returns:
        The latest beacon round data

    Raises:
        RuntimeError: If network request fails
    """
    import urllib.error
    import urllib.request

    url = f"{base_url}/{chain_hash}/public/latest"

    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to fetch latest beacon round: {e}") from e

    timestamp = DRAND_GENESIS_TIME + (data["round"] - 1) * DRAND_PERIOD

    return BeaconRound(
        round_number=data["round"],
        randomness=data["randomness"],
        signature=data["signature"],
        previous_signature=data["previous_signature"],
        timestamp=timestamp,
    )


def verify_beacon_randomness(beacon: BeaconRound) -> bool:
    """
    Verify that beacon randomness is correctly derived from the signature.

    The drand protocol defines randomness as SHA-256(signature).

    Args:
        beacon: The beacon round to verify

    Returns:
        True if the randomness is valid, False otherwise
    """
    try:
        # Compute expected randomness from signature
        expected_randomness = hashlib.sha256(bytes.fromhex(beacon.signature)).hexdigest()
        return expected_randomness == beacon.randomness
    except ValueError:
        # Invalid hex in signature or randomness
        return False


def wait_for_beacon_round(
    round_number: int,
    *,
    base_url: str = DRAND_MAINNET_URL,
    chain_hash: str = DRAND_CHAIN_HASH,
    poll_interval: float = 5.0,
    max_wait: float = 120.0,
) -> BeaconRound:
    """
    Wait for a specific beacon round to become available.

    This is useful during live ceremonies when waiting for the next
    beacon round after a contribution.

    Args:
        round_number: The beacon round to wait for
        base_url: drand API base URL
        chain_hash: Chain hash identifier
        poll_interval: Seconds between poll attempts
        max_wait: Maximum seconds to wait

    Returns:
        The beacon round data

    Raises:
        TimeoutError: If the round is not available within max_wait
    """
    start_time = time.time()

    while time.time() - start_time < max_wait:
        try:
            beacon = fetch_beacon_round(
                round_number, base_url=base_url, chain_hash=chain_hash, timeout=poll_interval
            )
            return beacon
        except (RuntimeError, ValueError):
            # Round not yet available, wait and retry
            time.sleep(poll_interval)

    raise TimeoutError(f"Beacon round {round_number} not available after {max_wait}s")


if __name__ == "__main__":
    # CLI for beacon verification
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Beacon randomness verification")
    parser.add_argument("--fetch-round", type=int, help="Fetch and display a specific round")
    parser.add_argument(
        "--fetch-latest", action="store_true", help="Fetch and display latest round"
    )
    parser.add_argument(
        "--verify-round",
        type=int,
        help="Fetch and verify a specific round",
    )
    parser.add_argument(
        "--round-at-time",
        type=int,
        help="Compute beacon round for Unix timestamp",
    )

    args = parser.parse_args()

    if args.fetch_round:
        beacon = fetch_beacon_round(args.fetch_round)
        print(json.dumps(beacon.to_dict(), indent=2))

    elif args.fetch_latest:
        beacon = fetch_latest_beacon_round()
        print(json.dumps(beacon.to_dict(), indent=2))

    elif args.verify_round:
        beacon = fetch_beacon_round(args.verify_round)
        if verify_beacon_randomness(beacon):
            print(f"✓ Beacon round {args.verify_round} verified successfully")
            print(f"  Randomness: {beacon.randomness}")
            print(f"  BLAKE3: {beacon.hash_blake3().hex()}")
            sys.exit(0)
        else:
            print(f"✗ Beacon round {args.verify_round} verification FAILED")
            sys.exit(1)

    elif args.round_at_time:
        round_num = compute_beacon_round_at_time(args.round_at_time)
        print(f"Beacon round at Unix time {args.round_at_time}: {round_num}")

    else:
        parser.print_help()
