"""
Partition awareness and fork resolution utilities.

These helpers implement dynamic quorum detection with frozen watermarks and a
deterministic fork-choice rule that combines elapsed rounds, quorum weight, and
a VRF-style tie-breaker. Chains are validated for proof-of-elapsed-time using
consensus round progression (block height), not wall-clock ordering.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from math import ceil

from .hashes import hash_bytes
from .timestamps import current_timestamp


@dataclass(frozen=True)
class ConsensusBlock:
    """Minimal consensus block metadata needed for fork resolution."""

    round_number: int
    quorum_weight: int
    vrf_hash: str
    timestamp: str

    def __post_init__(self) -> None:
        if self.round_number < 0:
            raise ValueError("round_number must be non-negative")
        if self.quorum_weight < 0:
            raise ValueError("quorum_weight must be non-negative")
        if not isinstance(self.vrf_hash, str) or not self.vrf_hash:
            raise ValueError("vrf_hash must be a non-empty hex string")
        try:
            vrf_bytes = bytes.fromhex(self.vrf_hash)
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError("vrf_hash must be hex-encoded") from exc
        if len(vrf_bytes) != 32:
            raise ValueError("vrf_hash must decode to 32 bytes")
        try:
            datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be ISO 8601 with optional Z suffix") from exc


@dataclass(frozen=True)
class ConsensusChainState:
    """Frozen chain watermark captured when quorum is lost."""

    round_number: int
    chain: tuple[ConsensusBlock, ...]

    def __post_init__(self) -> None:
        if self.round_number < 0:
            raise ValueError("round_number must be non-negative")
        validate_proof_of_wait(self.chain)


def validate_proof_of_wait(chain: Sequence[ConsensusBlock]) -> None:
    """
    Assert that a chain carries a valid proof-of-wait.

    Proof-of-elapsed-time is based on consensus round progression (height), not
    wall-clock timestamps. A valid chain must advance by exactly one round at
    each step so elapsed rounds cannot be fabricated by timestamp skew.
    """
    if not chain:
        raise ValueError("chain cannot be empty")
    previous_round = -1
    for block in chain:
        if previous_round >= 0 and block.round_number != previous_round + 1:
            raise ValueError("round numbers must advance by exactly one per block")
        if block.round_number <= previous_round:
            raise ValueError("round numbers must be strictly increasing")
        previous_round = block.round_number


def proof_of_elapsed_rounds(chain: Sequence[ConsensusBlock]) -> int:
    """Return the elapsed consensus rounds proved by a validated chain."""
    validate_proof_of_wait(chain)
    return chain[-1].round_number - chain[0].round_number


def find_first_divergent_round(
    chain_a: Sequence[ConsensusBlock], chain_b: Sequence[ConsensusBlock]
) -> int:
    """Return the index of the first divergent block between two chains."""
    upper = min(len(chain_a), len(chain_b))
    for idx in range(upper):
        if chain_a[idx] != chain_b[idx]:
            return idx
    return upper


def resolve_partition_fork(
    chain_a: Sequence[ConsensusBlock], chain_b: Sequence[ConsensusBlock]
) -> tuple[ConsensusBlock, ...]:
    """
    Resolve a fork between two chains after a healed partition.

    Preference order:
    1. Larger proof-of-elapsed-rounds value
    2. Higher quorum weight at the divergent round
    3. VRF tiebreaker on the first block after the fork
    """
    validate_proof_of_wait(chain_a)
    validate_proof_of_wait(chain_b)

    elapsed_rounds_a = proof_of_elapsed_rounds(chain_a)
    elapsed_rounds_b = proof_of_elapsed_rounds(chain_b)

    if elapsed_rounds_a > elapsed_rounds_b:
        return tuple(chain_a)
    if elapsed_rounds_b > elapsed_rounds_a:
        return tuple(chain_b)
    if len(chain_a) > len(chain_b):
        return tuple(chain_a)
    if len(chain_b) > len(chain_a):
        return tuple(chain_b)
    if chain_a == chain_b:
        return tuple(chain_a)

    fork_round = find_first_divergent_round(chain_a, chain_b)
    if fork_round >= len(chain_a) or fork_round >= len(chain_b):
        # One chain is a strict prefix; length equality handled above.
        return tuple(chain_a)

    weight_a = chain_a[fork_round].quorum_weight
    weight_b = chain_b[fork_round].quorum_weight
    if weight_a != weight_b:
        return tuple(chain_a) if weight_a > weight_b else tuple(chain_b)

    vrf_index = fork_round + 1
    if vrf_index >= len(chain_a) or vrf_index >= len(chain_b):
        vrf_index = fork_round
    vrf_a = chain_a[vrf_index].vrf_hash
    vrf_b = chain_b[vrf_index].vrf_hash
    return tuple(chain_a) if vrf_a <= vrf_b else tuple(chain_b)


class PartitionDetector:
    """
    Detect quorum loss, freeze watermarks, and recover deterministically.

    The detector stores frozen chain snapshots when fewer than two-thirds of
    active nodes are reachable. Upon recovery it replays the frozen watermarks
    and applies ``resolve_partition_fork`` to select the winning chain.
    """

    def __init__(
        self,
        *,
        ping_nodes: Callable[[Iterable[str]], Collection[str]],
        get_current_state: Callable[[], ConsensusChainState],
    ) -> None:
        self._ping_nodes = ping_nodes
        self._get_current_state = get_current_state
        self.last_quorum_time: dict[int, str] = {}
        self.frozen_watermarks: dict[int, ConsensusChainState] = {}

    def check_network_health(self, round_num: int, current_nodes: Iterable[str]) -> bool:
        """
        Probe active nodes and freeze state if quorum is lost.

        Returns ``False`` and stores a frozen watermark when fewer than
        ceil(2/3 * active_nodes) respond.
        """
        nodes = tuple(current_nodes)
        if not nodes:
            raise ValueError("current_nodes cannot be empty")
        reachable = self._ping_nodes(nodes)
        required = ceil(2 * len(nodes) / 3)
        if len(reachable) < required:
            self.frozen_watermarks[round_num] = self._get_current_state()
            return False
        self.last_quorum_time[round_num] = current_timestamp()
        return True

    def recover_from_partition(self, healed_round: int) -> ConsensusChainState:
        """
        Recover from a partition by replaying frozen watermarks.

        Chooses the winning chain across all frozen states older than the
        healed round and the current chain snapshot.
        """
        candidates: list[ConsensusChainState] = [self._get_current_state()]
        processed_rounds: list[int] = []
        for round_num in sorted(self.frozen_watermarks):
            if round_num >= healed_round:
                continue
            candidates.append(self.frozen_watermarks[round_num])
            processed_rounds.append(round_num)

        winner = candidates[0]
        for challenger in candidates[1:]:
            chosen = resolve_partition_fork(winner.chain, challenger.chain)
            if chosen == challenger.chain:
                winner = challenger

        for round_num in processed_rounds:
            self.frozen_watermarks.pop(round_num, None)

        self.last_quorum_time[healed_round] = current_timestamp()
        return winner


def vrf_hash_from_seed(seed: str) -> str:
    """Derive a deterministic VRF-style hash from seed material."""
    return hash_bytes(seed.encode("utf-8")).hex()
