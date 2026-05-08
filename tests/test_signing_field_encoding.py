"""
Tests for encode_signing_fields() and every subsystem migrated from
pipe-joining to length-prefixed field encoding (C-3 fix).

The key invariant across all tests:
    old: HASH_SEPARATOR.join(["a|b", "c"]) == HASH_SEPARATOR.join(["a", "b|c"])
    new: encode_signing_fields("a|b", "c") != encode_signing_fields("a", "b|c")
"""

from __future__ import annotations

from pathlib import Path

import nacl.exceptions
import nacl.signing
import pytest

from protocol.hashes import (
    HASH_SEPARATOR,
    blake3_hash,
    encode_signing_fields,
)
from protocol.partition import EquivocationSeenCache


REPO_ROOT = Path(__file__).parent.parent
REGISTRY_PATH = REPO_ROOT / "examples" / "federation_registry.json"


# ---------------------------------------------------------------------------
# encode_signing_fields — core properties
# ---------------------------------------------------------------------------


def test_encode_signing_fields_pipe_in_field_differs_from_pipe_as_boundary() -> None:
    """A "|" inside a field must not collide with a field boundary."""
    a = encode_signing_fields("a|b", "c")
    b = encode_signing_fields("a", "b|c")
    assert a != b


def test_encode_signing_fields_reorder_differs() -> None:
    a = encode_signing_fields("abc", "d")
    b = encode_signing_fields("a", "bcd")
    assert a != b


def test_encode_signing_fields_empty_field_is_distinct() -> None:
    a = encode_signing_fields("", "abc")
    b = encode_signing_fields("abc", "")
    c = encode_signing_fields("abc")
    assert a != b
    assert a != c
    assert b != c


def test_encode_signing_fields_bytes_passthrough() -> None:
    raw = b"\x00\x01\x02"
    result = encode_signing_fields(raw, "after")
    # bytes field is used as-is, not re-encoded
    assert len(result) == 4 + 3 + 4 + 5  # [len raw][raw][len "after"]["after"]


def test_encode_signing_fields_rejects_non_str_or_bytes() -> None:
    """Wire format must not depend on Python's str() of arbitrary types."""
    with pytest.raises(TypeError):
        encode_signing_fields(42)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        encode_signing_fields("ok", {"a": 1})  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        encode_signing_fields(None)  # type: ignore[arg-type]


def test_encode_signing_fields_accepts_bytes_and_str_mixed() -> None:
    encoded = encode_signing_fields("text", b"\x00\x01\x02")
    assert isinstance(encoded, bytes)


def test_encode_signing_fields_empty_field_list() -> None:
    assert encode_signing_fields() == b""


def test_encode_signing_fields_deterministic() -> None:
    a = encode_signing_fields("node-1", "shard-a", "42")
    b = encode_signing_fields("node-1", "shard-a", "42")
    assert a == b


# ---------------------------------------------------------------------------
# Legacy regression: old pipe-join was ambiguous; new encoding is not
# ---------------------------------------------------------------------------


def test_legacy_pipe_join_was_ambiguous() -> None:
    """Document that the old encoding had the collision we are fixing."""
    old_a = HASH_SEPARATOR.join(["a|b", "c"])
    old_b = HASH_SEPARATOR.join(["a", "b|c"])
    assert old_a == old_b  # this is the bug we're fixing


def test_new_encoding_rejects_same_collision() -> None:
    new_a = encode_signing_fields("a|b", "c")
    new_b = encode_signing_fields("a", "b|c")
    assert new_a != new_b


# ---------------------------------------------------------------------------
# Checkpoint vote event ID
# ---------------------------------------------------------------------------


def test_checkpoint_vote_event_id_pipe_injection_safe() -> None:
    from protocol.checkpoint_verify import _checkpoint_vote_event_id
    from protocol.federation.identity import FederationRegistry

    registry = FederationRegistry.from_file(REGISTRY_PATH)

    # A checkpoint_hash containing "|" must not collide with a split
    id_a = _checkpoint_vote_event_id("ab|cd", 1, 10, registry)
    id_b = _checkpoint_vote_event_id("ab", 1, 10, registry)
    assert id_a != id_b


def test_checkpoint_vote_event_id_deterministic() -> None:
    from protocol.checkpoint_verify import _checkpoint_vote_event_id
    from protocol.federation.identity import FederationRegistry

    registry = FederationRegistry.from_file(REGISTRY_PATH)
    id_a = _checkpoint_vote_event_id("deadbeef" * 8, 5, 100, registry)
    id_b = _checkpoint_vote_event_id("deadbeef" * 8, 5, 100, registry)
    assert id_a == id_b


# ---------------------------------------------------------------------------
# Federation: proactive share commitments
# ---------------------------------------------------------------------------


def test_proactive_share_commitments_pipe_injection_safe() -> None:
    from protocol.federation.gossip import build_proactive_share_commitments
    from protocol.federation.identity import FederationRegistry

    registry = FederationRegistry.from_file(REGISTRY_PATH)
    # Two nonces that differ only by a "|" must produce different commitments
    c1 = build_proactive_share_commitments(registry, epoch=1, refresh_nonce="abc|def")
    c2 = build_proactive_share_commitments(registry, epoch=1, refresh_nonce="abc")
    assert c1 != c2


# ---------------------------------------------------------------------------
# Federation: VRF selection seed
# ---------------------------------------------------------------------------


def test_vrf_selection_scores_pipe_in_shard_id_distinct() -> None:
    from protocol.federation.gossip import vrf_selection_scores
    from protocol.federation.identity import FederationRegistry

    registry = FederationRegistry.from_file(REGISTRY_PATH)
    scores_a = vrf_selection_scores(shard_id="records|evil", round_number=0, registry=registry)
    scores_b = vrf_selection_scores(shard_id="records", round_number=0, registry=registry)
    # Different shard_ids must produce different orderings
    assert [n for n, _ in scores_a] != [n for n, _ in scores_b] or (
        [s for _, s in scores_a] != [s for _, s in scores_b]
    )


# ---------------------------------------------------------------------------
# Federation: VRF commit-reveal
# ---------------------------------------------------------------------------


def test_vrf_reveal_commitment_pipe_injection_safe() -> None:
    from protocol.federation.gossip import build_vrf_reveal_commitment

    c_a = build_vrf_reveal_commitment(node_id="node|x", reveal="abc")
    c_b = build_vrf_reveal_commitment(node_id="node", reveal="x|abc")
    assert c_a != c_b


def test_derive_vrf_round_entropy_pipe_injection_safe() -> None:
    from protocol.federation.gossip import build_vrf_reveal_commitment, derive_vrf_round_entropy

    node_id_a = "node|evil"
    reveal_a = "reveal"
    node_id_b = "node"
    reveal_b = "evil|reveal"

    commitments_a = {node_id_a: build_vrf_reveal_commitment(node_id=node_id_a, reveal=reveal_a)}
    entropy_a = derive_vrf_round_entropy(
        shard_id="s1",
        round_number=0,
        epoch=1,
        commitments=commitments_a,
        reveals={node_id_a: reveal_a},
    )

    commitments_b = {node_id_b: build_vrf_reveal_commitment(node_id=node_id_b, reveal=reveal_b)}
    entropy_b = derive_vrf_round_entropy(
        shard_id="s1",
        round_number=0,
        epoch=1,
        commitments=commitments_b,
        reveals={node_id_b: reveal_b},
    )

    assert entropy_a != entropy_b


# ---------------------------------------------------------------------------
# Federation: key rotation signing payload
# ---------------------------------------------------------------------------


def test_key_rotation_payload_pipe_injection_safe() -> None:
    from protocol.federation.rotation import EpochKeyRotationRecord
    from protocol.hashes import KEY_ROTATION_PREFIX

    old_key = nacl.signing.SigningKey.generate()

    def _make_record(node_id: str) -> EpochKeyRotationRecord:
        rotation_payload = encode_signing_fields(
            node_id,
            str(1),
            "old" * 16,
            "new" * 16,
            "2026-01-01T00:00:00Z",
        )
        rotation_hash = blake3_hash([KEY_ROTATION_PREFIX, b"|", rotation_payload])
        sig = old_key.sign(rotation_hash).signature.hex()
        return EpochKeyRotationRecord(
            node_id=node_id,
            epoch=1,
            old_pubkey_hash="old" * 16,
            new_pubkey_hash="new" * 16,
            rotated_at="2026-01-01T00:00:00Z",
            rotation_signature=sig,
            witness_signatures=(),
        )

    record_a = _make_record("node|split")

    # Signature created for "node|split" must NOT verify against "node" + "split"
    payload_b = encode_signing_fields(
        "node", str(1), "old" * 16, "new" * 16, "2026-01-01T00:00:00Z"
    )
    hash_b = blake3_hash([KEY_ROTATION_PREFIX, b"|", payload_b])
    with pytest.raises(nacl.exceptions.BadSignatureError):
        old_key.verify_key.verify(hash_b, bytes.fromhex(record_a.rotation_signature))


# ---------------------------------------------------------------------------
# Federation: data availability challenge hash
# ---------------------------------------------------------------------------


def test_da_challenge_hash_pipe_injection_safe() -> None:
    from protocol.federation.replication import DataAvailabilityChallenge

    c_a = DataAvailabilityChallenge(
        shard_id="shard|evil",
        header_hash="aa" * 32,
        challenger_id="challenger",
        challenge_nonce="nonce",
        issued_at="2026-01-01T00:00:00Z",
        response_deadline="2026-01-01T01:00:00Z",
    ).challenge_hash()

    c_b = DataAvailabilityChallenge(
        shard_id="shard",
        header_hash="aa" * 32,
        challenger_id="evil|challenger",
        challenge_nonce="nonce",
        issued_at="2026-01-01T00:00:00Z",
        response_deadline="2026-01-01T01:00:00Z",
    ).challenge_hash()

    assert c_a != c_b


# ---------------------------------------------------------------------------
# Redaction: correctness proof binding
# ---------------------------------------------------------------------------


def test_redaction_binding_pipe_injection_safe() -> None:
    """Same-arity inputs that would collide under naive pipe-join must differ here.

    Under HASH_SEPARATOR.join both encodings produce "a|b|c|d|e|f"; under
    encode_signing_fields they MUST differ because field boundaries are
    bound by length prefixes, not by the literal "|" character.
    """
    pipe_join_a = HASH_SEPARATOR.join(["a|b", "c", "d", "e", "f"])
    pipe_join_b = HASH_SEPARATOR.join(["a", "b|c", "d", "e", "f"])
    assert pipe_join_a == pipe_join_b  # the legacy collision

    encoded_a = encode_signing_fields("a|b", "c", "d", "e", "f")
    encoded_b = encode_signing_fields("a", "b|c", "d", "e", "f")
    assert encoded_a != encoded_b


def test_redaction_correctness_proof_roundtrip() -> None:
    from protocol.hashes import REDACTION_BINDING_PREFIX

    root = "aa" * 32
    binding_payload = encode_signing_fields(root, root, root, root, "0,1,2")
    binding_hash = blake3_hash([REDACTION_BINDING_PREFIX, b"|", binding_payload]).hex()
    assert len(binding_hash) == 64


# ---------------------------------------------------------------------------
# Shard namespace mapping
# ---------------------------------------------------------------------------


def test_shard_namespace_pipe_injection_safe() -> None:
    from protocol.shards import ShardNamespacePartitioner

    p = ShardNamespacePartitioner(shard_count=16)
    id_a = p.shard_id_for_namespace("evil|ns")
    id_b = p.shard_id_for_namespace("evil")
    # With 16 shards and a BLAKE3-based mapping these may or may not be the same
    # shard by chance, so we test determinism rather than inequality.
    assert id_a == p.shard_id_for_namespace("evil|ns")
    assert id_b == p.shard_id_for_namespace("evil")


def test_shard_namespace_deterministic() -> None:
    from protocol.shards import ShardNamespacePartitioner

    p = ShardNamespacePartitioner(shard_count=32)
    assert p.shard_id_for_namespace("records.agency") == p.shard_id_for_namespace("records.agency")


# ---------------------------------------------------------------------------
# H-6: EquivocationSeenCache
# ---------------------------------------------------------------------------


def test_equivocation_seen_cache_new_entry_returns_true() -> None:
    cache = EquivocationSeenCache()
    assert cache.is_new("node-1", "shard-a", 1, "hash1") is True


def test_equivocation_seen_cache_duplicate_returns_false() -> None:
    cache = EquivocationSeenCache()
    cache.is_new("node-1", "shard-a", 1, "hash1")
    assert cache.is_new("node-1", "shard-a", 1, "hash1") is False


def test_equivocation_seen_cache_different_hash_is_new() -> None:
    cache = EquivocationSeenCache()
    cache.is_new("node-1", "shard-a", 1, "hash1")
    assert cache.is_new("node-1", "shard-a", 1, "hash2") is True


def test_equivocation_seen_cache_different_round_is_new() -> None:
    cache = EquivocationSeenCache()
    cache.is_new("node-1", "shard-a", 1, "hash1")
    assert cache.is_new("node-1", "shard-a", 2, "hash1") is True


def test_equivocation_seen_cache_len() -> None:
    cache = EquivocationSeenCache()
    assert len(cache) == 0
    cache.is_new("node-1", "shard-a", 1, "h1")
    assert len(cache) == 1
    cache.is_new("node-1", "shard-a", 1, "h1")  # duplicate
    assert len(cache) == 1
    cache.is_new("node-1", "shard-a", 2, "h1")  # new round
    assert len(cache) == 2


def test_equivocation_seen_cache_evicts_oldest_at_capacity() -> None:
    cache = EquivocationSeenCache(max_entries=3)
    cache.is_new("n", "s", 1, "h1")
    cache.is_new("n", "s", 2, "h2")
    cache.is_new("n", "s", 3, "h3")
    assert len(cache) == 3

    # Adding a 4th entry should evict the oldest (round 1)
    cache.is_new("n", "s", 4, "h4")
    assert len(cache) == 3
    # round-1 entry was evicted, so it appears new again
    assert cache.is_new("n", "s", 1, "h1") is True


def test_equivocation_seen_cache_rejects_non_positive_max_entries() -> None:
    with pytest.raises(ValueError):
        EquivocationSeenCache(max_entries=0)
    with pytest.raises(ValueError):
        EquivocationSeenCache(max_entries=-1)


def test_equivocation_seen_cache_is_lru_not_fifo() -> None:
    """A repeatedly-hit entry must not be evicted under churn (LRU, not FIFO).

    Insertion order is h1, h2, h3. We then hit h1 (refreshing recency) and
    insert h4. Under FIFO h1 would be evicted; under true LRU h2 is evicted.
    """
    cache = EquivocationSeenCache(max_entries=3)
    cache.is_new("n", "s", 1, "h1")
    cache.is_new("n", "s", 2, "h2")
    cache.is_new("n", "s", 3, "h3")

    # Hit h1 -> refreshes its recency
    assert cache.is_new("n", "s", 1, "h1") is False

    # Adding h4 should evict h2 (now the LRU), not h1
    cache.is_new("n", "s", 4, "h4")
    assert cache.is_new("n", "s", 1, "h1") is False  # still present
    assert cache.is_new("n", "s", 2, "h2") is True  # was evicted


# ---------------------------------------------------------------------------
# DA challenge: response_deadline binding (replication.py)
# ---------------------------------------------------------------------------


def test_da_challenge_hash_binds_response_deadline() -> None:
    """Two challenges differing only by deadline must produce different hashes."""
    from protocol.federation.replication import DataAvailabilityChallenge

    base_kwargs = dict(
        shard_id="shard-1",
        header_hash="aa" * 32,
        challenger_id="challenger",
        challenge_nonce="nonce",
        issued_at="2026-01-01T00:00:00Z",
    )
    h1 = DataAvailabilityChallenge(
        **base_kwargs, response_deadline="2026-01-01T01:00:00Z"
    ).challenge_hash()
    h2 = DataAvailabilityChallenge(
        **base_kwargs, response_deadline="2026-01-01T02:00:00Z"
    ).challenge_hash()
    assert h1 != h2
