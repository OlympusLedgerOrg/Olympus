"""
Partition awareness and fork resolution utilities.

These helpers implement dynamic quorum detection with frozen watermarks and a
deterministic fork-choice rule that combines elapsed rounds, quorum weight, and
a VRF-style tie-breaker. Chains are validated for proof-of-elapsed-time using
consensus round progression (block height), not wall-clock ordering.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from math import ceil

from .hashes import hash_bytes
from .timestamps import current_timestamp


@dataclass(frozen=True)
class VotePublication:
    """Public gossip evidence proving that a federation vote was published."""

    vote_hash: str
    published_at: str
    witnesses: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.vote_hash, str) or not self.vote_hash:
            raise ValueError("vote_hash must be a non-empty hex string")
        try:
            vote_hash_bytes = bytes.fromhex(self.vote_hash)
        except ValueError as exc:
            raise ValueError("vote_hash must be hex-encoded") from exc
        if len(vote_hash_bytes) != 32:
            raise ValueError("vote_hash must decode to 32 bytes")
        try:
            datetime.fromisoformat(self.published_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("published_at must be ISO 8601 with optional Z suffix") from exc
        if not self.witnesses:
            raise ValueError("witnesses cannot be empty")
        if any(not isinstance(witness, str) or not witness for witness in self.witnesses):
            raise ValueError("witness identifiers must be non-empty strings")
        if len(set(self.witnesses)) != len(self.witnesses):
            raise ValueError("witness identifiers must be unique")


@dataclass(frozen=True)
class PublishedVote:
    """Signed chain vote that includes proof-of-publication metadata."""

    node_id: str
    shard_id: str
    round_number: int
    chain_id: str
    publication: VotePublication

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, str) or not self.node_id:
            raise ValueError("node_id must be a non-empty string")
        if not isinstance(self.shard_id, str) or not self.shard_id:
            raise ValueError("shard_id must be a non-empty string")
        if self.round_number < 0:
            raise ValueError("round_number must be non-negative")
        if not isinstance(self.chain_id, str) or not self.chain_id:
            raise ValueError("chain_id must be a non-empty string")


@dataclass(frozen=True)
class SlashingEvidence:
    """Slashable equivocation evidence for a node that signed conflicting forks."""

    node_id: str
    shard_id: str
    round_number: int
    conflicting_chain_ids: tuple[str, ...]
    publication_hashes: tuple[str, ...]


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


@dataclass(frozen=True)
class TransactionBroadcast:
    """Censorship-resistant broadcast receipt for a transaction proposal."""

    tx_id: str
    round_number: int
    broadcast_at: str
    witnesses: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.tx_id, str) or not self.tx_id:
            raise ValueError("tx_id must be a non-empty string")
        if self.round_number < 0:
            raise ValueError("round_number must be non-negative")
        try:
            datetime.fromisoformat(self.broadcast_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("broadcast_at must be ISO 8601 with optional Z suffix") from exc
        if not self.witnesses:
            raise ValueError("witnesses cannot be empty")
        if any(not isinstance(witness, str) or not witness for witness in self.witnesses):
            raise ValueError("witness identifiers must be non-empty strings")
        if len(set(self.witnesses)) != len(self.witnesses):
            raise ValueError("witness identifiers must be unique")


def detect_slashable_equivocations(votes: Sequence[PublishedVote]) -> tuple[SlashingEvidence, ...]:
    """Return deterministic slashing evidence for Nothing-at-Stake double-signing."""
    grouped_votes: dict[tuple[str, str, int], dict[str, str]] = {}
    for vote in votes:
        key = (vote.node_id, vote.shard_id, vote.round_number)
        bucket = grouped_votes.setdefault(key, {})
        existing_publication = bucket.get(vote.chain_id)
        if existing_publication is None:
            bucket[vote.chain_id] = vote.publication.vote_hash
            continue
        if existing_publication != vote.publication.vote_hash:
            bucket[vote.chain_id] = min(existing_publication, vote.publication.vote_hash)

    evidence: list[SlashingEvidence] = []
    for (node_id, shard_id, round_number), chain_votes in sorted(grouped_votes.items()):
        if len(chain_votes) < 2:
            continue
        ordered_chain_ids = tuple(sorted(chain_votes))
        publication_hashes = tuple(chain_votes[chain_id] for chain_id in ordered_chain_ids)
        evidence.append(
            SlashingEvidence(
                node_id=node_id,
                shard_id=shard_id,
                round_number=round_number,
                conflicting_chain_ids=ordered_chain_ids,
                publication_hashes=publication_hashes,
            )
        )
    return tuple(evidence)


def select_rotating_leader(
    round_number: int, leaders: Sequence[str], *, rotation_window: int = 1
) -> str:
    """Return the scheduled leader with deterministic frequent round-robin rotation."""
    if round_number < 0:
        raise ValueError("round_number must be non-negative")
    if rotation_window <= 0:
        raise ValueError("rotation_window must be positive")
    if not leaders:
        raise ValueError("leaders cannot be empty")
    if any(not isinstance(leader, str) or not leader for leader in leaders):
        raise ValueError("leader identifiers must be non-empty strings")

    leader_index = (round_number // rotation_window) % len(leaders)
    return leaders[leader_index]


def build_inclusion_list(
    broadcasts: Sequence[TransactionBroadcast], *, minimum_witnesses: int = 2
) -> tuple[str, ...]:
    """Build a deterministic inclusion list from censorship-proof tx broadcasts."""
    if minimum_witnesses <= 0:
        raise ValueError("minimum_witnesses must be positive")

    seen_order: dict[str, tuple[datetime, int]] = {}
    witness_sets: dict[str, set[str]] = {}
    for index, broadcast in enumerate(broadcasts):
        witness_sets.setdefault(broadcast.tx_id, set()).update(broadcast.witnesses)
        if broadcast.tx_id not in seen_order:
            seen_order[broadcast.tx_id] = (
                datetime.fromisoformat(broadcast.broadcast_at.replace("Z", "+00:00")),
                index,
            )

    eligible = [
        tx_id for tx_id, witnesses in witness_sets.items() if len(witnesses) >= minimum_witnesses
    ]
    eligible.sort(key=lambda tx_id: (seen_order[tx_id][0], seen_order[tx_id][1], tx_id))
    return tuple(eligible)


def missing_inclusion_entries(
    inclusion_list: Sequence[str], proposed_block_transactions: Sequence[str]
) -> tuple[str, ...]:
    """Return required inclusion-list transactions missing from a proposed block."""
    proposed = {tx_id for tx_id in proposed_block_transactions}
    missing = {tx_id for tx_id in inclusion_list if tx_id not in proposed}
    return tuple(sorted(missing))


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
        if previous_round != -1 and block.round_number != previous_round + 1:
            raise ValueError("round numbers must advance by exactly one per block")
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


def select_random_peers(nodes: Sequence[str], sample_size: int) -> tuple[str, ...]:
    """Return a cryptographically random subset of peers for health checks."""
    if sample_size <= 0:
        raise ValueError("sample_size must be positive")
    if sample_size > len(nodes):
        raise ValueError("sample_size cannot exceed number of available nodes")
    if sample_size == len(nodes):
        return tuple(nodes)
    return tuple(secrets.SystemRandom().sample(list(nodes), sample_size))


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
        sample_size: int | None = None,
        peer_groups: Mapping[str, str] | None = None,
        min_peer_group_diversity: int = 1,
        cross_network_verifier: Callable[[Collection[str]], bool] | None = None,
        peer_selector: Callable[[Sequence[str], int], tuple[str, ...]] = select_random_peers,
    ) -> None:
        self._ping_nodes = ping_nodes
        self._get_current_state = get_current_state
        self._sample_size = sample_size
        self._peer_groups = dict(peer_groups or {})
        self._min_peer_group_diversity = min_peer_group_diversity
        self._cross_network_verifier = cross_network_verifier
        self._peer_selector = peer_selector
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

        sample_size = len(nodes) if self._sample_size is None else self._sample_size
        if sample_size <= 0:
            raise ValueError("sample_size must be a positive integer")
        if sample_size > len(nodes):
            sample_size = len(nodes)
        sampled_nodes = self._peer_selector(nodes, sample_size)

        if self._peer_groups and self._min_peer_group_diversity > 1:
            sampled_groups = {
                self._peer_groups[node_id]
                for node_id in sampled_nodes
                if node_id in self._peer_groups
            }
            if len(sampled_groups) < self._min_peer_group_diversity:
                self.frozen_watermarks[round_num] = self._get_current_state()
                return False

        reachable = self._ping_nodes(sampled_nodes)
        required = ceil(2 * len(sampled_nodes) / 3)
        if len(reachable) < required:
            self.frozen_watermarks[round_num] = self._get_current_state()
            return False
        if self._cross_network_verifier is not None and not self._cross_network_verifier(reachable):
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
