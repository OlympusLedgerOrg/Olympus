"""Federation gossip, VRF selection, and fork resolution."""

from __future__ import annotations

from typing import Any

from protocol.hashes import (
    HASH_SEPARATOR,
    VRF_SELECTION_PREFIX,
    _VRF_COMMIT_REVEAL_PREFIX,
    blake3_hash,
    hash_bytes,
)
from protocol.ledger import Ledger, LedgerEntry

from .identity import (
    DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS,
    FederationRegistry,
    _median_numeric,
    _median_timestamp,
    _parse_timestamp,
    _to_int,
    is_replay_epoch,
)
from .quorum import (
    FederationBehaviorSample,
    NodeSignature,
    _federation_vote_event_id,
    build_quorum_certificate,
    verify_quorum_certificate,
)


def resolve_canonical_fork(
    candidates: list[tuple[dict[str, Any], dict[str, Any]]],
    registry: FederationRegistry,
    *,
    current_epoch: int | None = None,
    max_clock_skew_seconds: int = DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Return the deterministic canonical root candidate among competing forks.

    The resolver applies these deterministic rules:
    1. Only candidates with valid quorum certificates are eligible.
    2. Replay protection rejects candidates whose federation epoch is lower than
       ``current_epoch`` (default: ``registry.epoch``).
    3. Prefer the candidate with the highest number of valid signer approvals.
    4. Apply NTP hardening by rejecting certificate timestamps that are outliers
       relative to the median candidate timestamp.
    5. If signer counts tie, choose the lexicographically lowest header hash.
    """
    if not candidates:
        return None
    effective_epoch = registry.epoch if current_epoch is None else int(current_epoch)
    if effective_epoch < 0:
        raise ValueError("Current federation epoch must be an integer >= 0")
    if max_clock_skew_seconds < 0:
        raise ValueError("max_clock_skew_seconds must be >= 0")

    eligible: list[tuple[int, Any, str, dict[str, Any], dict[str, Any]]] = []
    slot: tuple[str, int, int] | None = None
    for header, certificate in candidates:
        cert_epoch = _to_int(certificate.get("federation_epoch"))
        if cert_epoch is None or is_replay_epoch(cert_epoch, effective_epoch):
            continue
        if not verify_quorum_certificate(certificate, header, registry):
            continue

        candidate_slot = (
            str(certificate["shard_id"]),
            int(certificate["height"]),
            int(certificate["round"]),
        )
        if slot is None:
            slot = candidate_slot
        elif candidate_slot != slot:
            raise ValueError("Fork candidates must reference the same shard_id, height, and round")

        signer_count = len(certificate["signatures"])
        try:
            certificate_timestamp = _parse_timestamp(str(certificate["timestamp"]))
        except ValueError:
            # Malformed timestamp: treat this candidate as ineligible for canonical fork resolution.
            continue
        header_hash = str(header["header_hash"])
        eligible.append((signer_count, certificate_timestamp, header_hash, header, certificate))

    if not eligible:
        return None

    median_timestamp = _median_timestamp([item[1] for item in eligible])
    skew_hardened = [
        item
        for item in eligible
        if abs((item[1] - median_timestamp).total_seconds()) <= max_clock_skew_seconds
    ]
    if not skew_hardened:
        skew_hardened = eligible

    selected_entry = min(skew_hardened, key=lambda item: (-item[0], item[2]))
    selected_header = selected_entry[3]
    selected_certificate = selected_entry[4]
    return selected_header, selected_certificate


def build_proactive_share_commitments(
    registry: FederationRegistry, *, epoch: int, refresh_nonce: str
) -> dict[str, str]:
    """Return deterministic proactive secret-share commitments for active nodes."""
    if epoch < 0:
        raise ValueError("Epoch must be non-negative")
    if not refresh_nonce:
        raise ValueError("refresh_nonce must be non-empty")
    commitments: dict[str, str] = {}
    for node in registry.active_nodes():
        payload = HASH_SEPARATOR.join(
            [
                node.node_id,
                node.pubkey.hex(),
                str(epoch),
                refresh_nonce,
            ]
        ).encode("utf-8")
        commitments[node.node_id] = hash_bytes(payload).hex()
    return commitments


def verify_proactive_share_commitments(
    registry: FederationRegistry,
    *,
    epoch: int,
    refresh_nonce: str,
    commitments: dict[str, str],
) -> bool:
    """Return whether proactive share commitments match deterministic expectations."""
    expected = build_proactive_share_commitments(
        registry,
        epoch=epoch,
        refresh_nonce=refresh_nonce,
    )
    return commitments == expected


def detect_compromise_signals(
    samples: list[FederationBehaviorSample],
    *,
    spike_multiplier: float = 2.0,
) -> dict[str, tuple[str, ...]]:
    """Return per-node behavioral compromise signals from observed vote samples."""
    if spike_multiplier < 1.0:
        raise ValueError("spike_multiplier must be >= 1.0")
    if not samples:
        return {}

    by_node: dict[str, list[FederationBehaviorSample]] = {}
    for sample in samples:
        by_node.setdefault(sample.node_id, []).append(sample)

    median_count = _median_numeric([len(node_samples) for node_samples in by_node.values()])
    results: dict[str, tuple[str, ...]] = {}
    for node_id, node_samples in by_node.items():
        signals: list[str] = []
        seen_round_hashes: dict[int, set[str]] = {}
        for sample in node_samples:
            seen_round_hashes.setdefault(sample.round_number, set()).add(sample.header_hash)
        if any(len(round_hashes) > 1 for round_hashes in seen_round_hashes.values()):
            signals.append("double_vote_detected")
        if median_count > 0 and len(node_samples) > median_count * spike_multiplier:
            signals.append("participation_spike_detected")
        if signals:
            results[node_id] = tuple(sorted(signals))
    return results


def vrf_selection_scores(
    *,
    shard_id: str,
    round_number: int,
    registry: FederationRegistry,
    epoch: int | None = None,
    round_entropy: str | None = None,
) -> list[tuple[str, int]]:
    """Return deterministic VRF-style selection scores for active federation nodes.

    Optional ``round_entropy`` lets callers bind commit-reveal randomness (and any
    associated non-interactive proof transcript hash) into the selection seed to
    mitigate VRF grinding by adaptive participants.
    """
    if round_number < 0:
        raise ValueError("Round number must be non-negative")
    effective_epoch = registry.epoch if epoch is None else int(epoch)
    if effective_epoch < 0:
        raise ValueError("Epoch must be non-negative")
    entropy_bytes = b""
    if round_entropy is not None:
        try:
            entropy_bytes = bytes.fromhex(round_entropy)
        except ValueError as exc:
            raise ValueError("Round entropy must be a valid hex string") from exc
    membership_hash = registry.membership_hash()
    selection_seed = blake3_hash(
        [
            VRF_SELECTION_PREFIX,
            HASH_SEPARATOR.encode("utf-8").join(
                [
                    str(shard_id).encode("utf-8"),
                    str(round_number).encode("utf-8"),
                    str(effective_epoch).encode("utf-8"),
                    membership_hash.encode("utf-8"),
                    entropy_bytes,
                ]
            ),
        ]
    )
    scores: list[tuple[str, int]] = []
    for node in registry.active_nodes():
        score_bytes = blake3_hash([selection_seed, node.node_id.encode("utf-8")])
        score = int.from_bytes(score_bytes[:8], byteorder="big", signed=False)
        scores.append((node.node_id, score))
    return sorted(scores, key=lambda item: (item[1], item[0]))


def select_vrf_committee(
    *,
    shard_id: str,
    round_number: int,
    registry: FederationRegistry,
    committee_size: int,
    epoch: int | None = None,
    round_entropy: str | None = None,
) -> list[str]:
    """Select a deterministic VRF-style committee from active federation nodes."""
    if committee_size <= 0:
        raise ValueError("Committee size must be positive")
    scores = vrf_selection_scores(
        shard_id=shard_id,
        round_number=round_number,
        registry=registry,
        epoch=epoch,
        round_entropy=round_entropy,
    )
    if committee_size > len(scores):
        raise ValueError("Committee size cannot exceed active federation members")
    return [node_id for node_id, _ in scores[:committee_size]]


def select_vrf_leader(
    *,
    shard_id: str,
    round_number: int,
    registry: FederationRegistry,
    epoch: int | None = None,
    round_entropy: str | None = None,
) -> str:
    """Select a deterministic VRF-style leader from active federation nodes."""
    committee = select_vrf_committee(
        shard_id=shard_id,
        round_number=round_number,
        registry=registry,
        committee_size=1,
        epoch=epoch,
        round_entropy=round_entropy,
    )
    return committee[0]


def build_vrf_reveal_commitment(*, node_id: str, reveal: str) -> str:
    """Build a deterministic commit-reveal binding for VRF anti-grinding rounds."""
    payload = HASH_SEPARATOR.encode("utf-8").join([node_id.encode("utf-8"), reveal.encode("utf-8")])
    return blake3_hash([_VRF_COMMIT_REVEAL_PREFIX, payload]).hex()


def derive_vrf_round_entropy(
    *,
    shard_id: str,
    round_number: int,
    epoch: int,
    commitments: dict[str, str],
    reveals: dict[str, str],
    proof_transcript_hashes: dict[str, str] | None = None,
) -> str:
    """Derive round entropy from commit-reveal data and optional ZK proof bindings.

    The optional ``proof_transcript_hashes`` map allows callers to bind each
    participant's non-interactive proof transcript hash into the final entropy.
    """
    if round_number < 0:
        raise ValueError("Round number must be non-negative")
    if epoch < 0:
        raise ValueError("Epoch must be non-negative")
    if not reveals:
        raise ValueError("At least one reveal is required")

    reveal_chunks: list[bytes] = []
    separator = HASH_SEPARATOR.encode("utf-8")
    for node_id, reveal in sorted(reveals.items()):
        commitment = commitments.get(node_id)
        if commitment is None:
            raise ValueError(f"Missing commitment for node_id: {node_id}")
        expected_commitment = build_vrf_reveal_commitment(node_id=node_id, reveal=reveal)
        normalized_commitment = commitment.lower()
        if normalized_commitment != expected_commitment.lower():
            raise ValueError(f"Reveal does not match commitment for node_id: {node_id}")

        proof_hash = ""
        if proof_transcript_hashes is not None:
            proof_hash = str(proof_transcript_hashes.get(node_id, ""))
            if not proof_hash:
                raise ValueError(f"Missing proof transcript hash for node_id: {node_id}")

        reveal_chunks.append(
            separator.join(
                [
                    node_id.encode("utf-8"),
                    reveal.encode("utf-8"),
                    proof_hash.encode("utf-8"),
                ]
            )
        )

    context = separator.join(
        [
            shard_id.encode("utf-8"),
            str(round_number).encode("utf-8"),
            str(epoch).encode("utf-8"),
        ]
    )
    return blake3_hash([_VRF_COMMIT_REVEAL_PREFIX, context, *reveal_chunks]).hex()


def append_quorum_certificate_to_ledger(
    *,
    ledger: Ledger,
    header: dict[str, Any],
    signatures: list[NodeSignature],
    registry: FederationRegistry,
    canonicalization: dict[str, Any],
) -> LedgerEntry:
    """Append a ledger entry that persistently commits a federation quorum certificate."""
    certificate = build_quorum_certificate(header, signatures, registry)
    return ledger.append(
        record_hash=str(header["header_hash"]),
        shard_id=str(header["shard_id"]),
        shard_root=str(header["root_hash"]),
        canonicalization=canonicalization,
        federation_quorum_certificate=certificate,
    )
