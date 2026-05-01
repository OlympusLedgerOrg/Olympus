# ruff: noqa: I001  -- DAG order enforced; gossip imports protocol.ledger so must go last
"""Federation identity, registry, and quorum-signing prototype.

This package re-exports every public name that was previously available from
the monolithic ``protocol.federation`` module so that all existing imports
continue to work unchanged.
"""

from protocol.federation.identity import (
    _CERTIFICATE_SIGNATURE_SCHEME_ED25519,
    _HEADER_EXCLUDED_FIELDS,
    DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS,
    FEDERATION_DOMAIN_TAG,
    FederationKeyHistoryEntry,
    FederationNode,
    FederationRegistry,
    _extract_round_and_height,
    _median_numeric,
    _median_timestamp,
    _parse_timestamp,
    _to_int,
    is_replay_epoch,
)
from protocol.federation.quorum import (
    FederationBehaviorSample,
    FederationVoteMessage,
    NodeSignature,
    QuorumNotReached,
    _build_federation_vote_message,
    _federation_vote_event_id,
    _header_hash_matches_commitment,
    build_federation_header_record,
    build_quorum_certificate,
    collect_quorum_signatures,
    count_verified_quorum_signers,
    has_federation_quorum,
    quorum_certificate_hash,
    serialize_vote_message,
    sign_federated_header,
    verify_federated_header_signatures,
    verify_quorum_certificate,
)
from protocol.federation.replication import (
    DataAvailabilityChallenge,
    FederationFinalityStatus,
    GossipedShardHeader,
    ReplicationProof,
    ShardHeaderForkEvidence,
    create_replication_proof,
    detect_shard_header_forks,
    registry_forest_commitment,
    verify_data_availability,
)
from protocol.federation.rotation import (
    EpochKeyRotationRecord,
    RecursiveChainProof,
    verify_epoch_key_rotation,
    verify_recursive_chain_proof,
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


__all__ = [
    # identity
    "FEDERATION_DOMAIN_TAG",
    "_HEADER_EXCLUDED_FIELDS",
    "_CERTIFICATE_SIGNATURE_SCHEME_ED25519",
    "DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS",
    "_to_int",
    "FederationKeyHistoryEntry",
    "FederationNode",
    "FederationRegistry",
    "_parse_timestamp",
    "_median_numeric",
    "_median_timestamp",
    "is_replay_epoch",
    "_extract_round_and_height",
    # quorum
    "NodeSignature",
    "FederationBehaviorSample",
    "FederationVoteMessage",
    "QuorumNotReached",
    "serialize_vote_message",
    "_build_federation_vote_message",
    "sign_federated_header",
    "_federation_vote_event_id",
    "_header_hash_matches_commitment",
    "verify_federated_header_signatures",
    "has_federation_quorum",
    "build_federation_header_record",
    "build_quorum_certificate",
    "collect_quorum_signatures",
    "quorum_certificate_hash",
    "verify_quorum_certificate",
    "count_verified_quorum_signers",
    # gossip
    "resolve_canonical_fork",
    "build_proactive_share_commitments",
    "verify_proactive_share_commitments",
    "detect_compromise_signals",
    "vrf_selection_scores",
    "select_vrf_committee",
    "select_vrf_leader",
    "build_vrf_reveal_commitment",
    "derive_vrf_round_entropy",
    "append_quorum_certificate_to_ledger",
    # replication
    "ShardHeaderForkEvidence",
    "GossipedShardHeader",
    "detect_shard_header_forks",
    "registry_forest_commitment",
    "DataAvailabilityChallenge",
    "ReplicationProof",
    "FederationFinalityStatus",
    "verify_data_availability",
    "create_replication_proof",
    # rotation
    "RecursiveChainProof",
    "EpochKeyRotationRecord",
    "verify_recursive_chain_proof",
    "verify_epoch_key_rotation",
]
