"""Golden-vector tests for protocol/hashes.py wire-format changes (PR #698).

These vectors are part of the wire-format contract. Any cross-language verifier
(Rust, Go, JS, ...) MUST reproduce the exact hex strings asserted here.
Changing any of these values is a breaking protocol change and requires a
coordinated update across all verifier implementations.

Covers:
- M-15 / M-14: ``create_dual_root_commitment`` / ``parse_dual_root_commitment``
  binding-hash format ``LEDGER_PREFIX || _SEP || len_b3 || blake3_root || _SEP
  || len_pos || poseidon_root``.
- M-16: ``federation_vote_hash`` payload no longer contains an inner
  ``"olympus.federation.v1"`` domain string.
- F-FED-6: ``protocol.federation.quorum._federation_vote_event_id`` uses
  length-prefixed field encoding (no ``|`` join).
- F-FED-7: ``protocol.federation.replication.ReplicationProof.proof_payload_hash``
  uses length-prefixed field encoding (no ``|`` join).
"""

from __future__ import annotations

import pytest

from protocol.federation.identity import FederationNode, FederationRegistry
from protocol.federation.quorum import _federation_vote_event_id
from protocol.federation.replication import ReplicationProof
from protocol.hashes import (
    _SEP,
    LEDGER_PREFIX,
    blake3_hash,
    create_dual_root_commitment,
    federation_vote_hash,
    parse_dual_root_commitment,
)


# ---------------------------------------------------------------------------
# M-15 + M-14: dual-root commitment golden vector
# ---------------------------------------------------------------------------


def test_create_dual_root_commitment_golden_vector() -> None:
    """Wire format: 2B len_b3 || 32B b3 || 2B len_pos || 32B pos || 32B binding."""
    blake3_root = bytes.fromhex("11" * 32)
    poseidon_root = bytes.fromhex("22" * 32)

    commitment = create_dual_root_commitment(blake3_root, poseidon_root)

    expected_hex = (
        # len(blake3_root) == 32
        "0020"
        # blake3_root
        + "11" * 32
        # len(poseidon_root) == 32
        + "0020"
        # poseidon_root
        + "22" * 32
        # binding_hash = blake3(LEDGER_PREFIX || _SEP || len_b3 ||
        #                       blake3_root || _SEP || len_pos || poseidon_root)
        + "f0593089d2a0ccd14f8b283321d0d8d7517b04123a4ae96f868ed000635cc30c"
    )
    assert commitment.hex() == expected_hex
    assert len(commitment) == 100


def test_create_dual_root_commitment_binding_hash_formula() -> None:
    """The binding hash MUST commit to LEDGER_PREFIX, both _SEPs, and both length fields.

    A verifier that reconstructs the binding hash from the wire format must use
    exactly ``LEDGER_PREFIX || _SEP || len_b3 || blake3_root || _SEP || len_pos
    || poseidon_root``. This test pins that formula.
    """
    blake3_root = bytes.fromhex("11" * 32)
    poseidon_root = bytes.fromhex("22" * 32)
    len_b3 = (32).to_bytes(2, "big")
    len_pos = (32).to_bytes(2, "big")

    expected_binding = blake3_hash(
        [LEDGER_PREFIX, _SEP, len_b3, blake3_root, _SEP, len_pos, poseidon_root]
    )
    commitment = create_dual_root_commitment(blake3_root, poseidon_root)
    assert commitment[-32:] == expected_binding


def test_create_dual_root_commitment_binding_hash_breaks_old_format() -> None:
    """The new binding hash must NOT match the legacy formula that omitted _SEP and length fields.

    Old formula (missing leading _SEP and length fields):
        ``blake3(LEDGER_PREFIX || blake3_root || _SEP || poseidon_root)``

    Any verifier still using the old formula MUST fail to reproduce the binding
    hash, signaling that it needs to update.
    """
    blake3_root = bytes.fromhex("11" * 32)
    poseidon_root = bytes.fromhex("22" * 32)
    legacy_binding = blake3_hash([LEDGER_PREFIX, blake3_root, _SEP, poseidon_root])

    commitment = create_dual_root_commitment(blake3_root, poseidon_root)
    assert commitment[-32:] != legacy_binding


def test_create_dual_root_commitment_binding_covers_length_fields() -> None:
    """Mutating a length byte without re-deriving the binding hash must be rejected.

    M-14 requires the length fields to be inside the binding hash so that a
    crafted payload claiming a different (shorter) length cannot pass parsing.
    """
    blake3_root = bytes.fromhex("11" * 32)
    poseidon_root = bytes.fromhex("22" * 32)
    commitment = bytearray(create_dual_root_commitment(blake3_root, poseidon_root))
    # Flip the low byte of len_pos (offset 2 + 32 = 34, low byte at offset 35).
    commitment[35] ^= 0x01
    with pytest.raises(ValueError):
        parse_dual_root_commitment(bytes(commitment))


def test_dual_root_commitment_round_trip_under_new_format() -> None:
    blake3_root = bytes.fromhex("33" * 32)
    poseidon_root = bytes.fromhex("44" * 32)
    commitment = create_dual_root_commitment(blake3_root, poseidon_root)
    parsed_b3, parsed_pos = parse_dual_root_commitment(commitment)
    assert parsed_b3 == blake3_root
    assert parsed_pos == poseidon_root


# ---------------------------------------------------------------------------
# M-16: federation_vote_hash golden vector (no inner domain)
# ---------------------------------------------------------------------------


def test_federation_vote_hash_golden_vector_no_inner_domain() -> None:
    """Vote hash payload is length-prefixed (node_id, shard_id, header_hash, timestamp, event_id).

    The inner ``"olympus.federation.v1"`` field has been removed; domain
    separation comes from ``FEDERATION_PREFIX`` only.
    """
    vote_hash = federation_vote_hash(
        node_id="node-A",
        shard_id="records.test",
        header_hash="a" * 64,
        timestamp="2026-03-09T00:00:00Z",
        event_id_hex="deadbeef",
    )
    assert vote_hash.hex() == ("dd5426a489f7c531d39d1989582ac21dfc6b3fa006cd41613a22af5f53c9bf81")


def test_federation_vote_hash_does_not_match_legacy_inner_domain_format() -> None:
    """Any verifier still prepending ``"olympus.federation.v1"`` will produce a different hash."""
    from protocol.hashes import FEDERATION_PREFIX

    def legacy_with_inner_domain(
        node_id: str,
        shard_id: str,
        header_hash: str,
        timestamp: str,
        event_id_hex: str,
    ) -> bytes:
        fields = [
            "olympus.federation.v1",
            node_id,
            shard_id,
            header_hash,
            timestamp,
            event_id_hex,
        ]
        encoded: list[bytes] = []
        for value in fields:
            field_bytes = value.encode("utf-8")
            encoded.append(len(field_bytes).to_bytes(4, byteorder="big"))
            encoded.append(field_bytes)
        return blake3_hash([FEDERATION_PREFIX, _SEP, b"".join(encoded)])

    legacy = legacy_with_inner_domain(
        "node-A", "records.test", "a" * 64, "2026-03-09T00:00:00Z", "deadbeef"
    )
    current = federation_vote_hash(
        "node-A", "records.test", "a" * 64, "2026-03-09T00:00:00Z", "deadbeef"
    )
    assert legacy != current


# ---------------------------------------------------------------------------
# F-FED-6: _federation_vote_event_id length-prefixed encoding
# ---------------------------------------------------------------------------


def _golden_registry() -> FederationRegistry:
    node1 = FederationNode(
        node_id="node-A",
        pubkey=bytes.fromhex("11" * 32),
        endpoint="https://a",
        operator="op-a",
        jurisdiction="us",
    )
    node2 = FederationNode(
        node_id="node-B",
        pubkey=bytes.fromhex("22" * 32),
        endpoint="https://b",
        operator="op-b",
        jurisdiction="us",
    )
    return FederationRegistry(nodes=(node1, node2), epoch=7)


def test_federation_vote_event_id_golden_vector() -> None:
    registry = _golden_registry()
    # Pin the membership hash so the event_id vector is fully reproducible.
    assert (
        registry.membership_hash()
        == "63b63393b190c6b5e965692644f94fbd6ecea90bc2b96d3fa0196ed7feed473d"
    )
    header = {
        "shard_id": "records.test",
        "header_hash": "a" * 64,
        "timestamp": "2026-03-09T00:00:00Z",
    }
    assert _federation_vote_event_id(header, registry) == (
        "22c075b2691ee4a9231d13de4008fca48e7cc25fbb557ba49ce9760717d46bdc"
    )


def test_federation_vote_event_id_prevents_pipe_injection() -> None:
    """``shard_id`` containing ``|`` must NOT collide with other field layouts.

    With the legacy ``HASH_SEPARATOR.join(...)`` encoding the two headers below
    would have produced identical event IDs. Length-prefixing eliminates that
    field-injection vector.
    """
    registry = _golden_registry()
    header_a = {
        "shard_id": "X|Y",
        "header_hash": "a" * 64,
        "timestamp": "2026-03-09T00:00:00Z",
    }
    header_b = {
        "shard_id": "X",
        "header_hash": "Y|" + "a" * 62,
        "timestamp": "2026-03-09T00:00:00Z",
    }
    assert _federation_vote_event_id(header_a, registry) != _federation_vote_event_id(
        header_b, registry
    )


# ---------------------------------------------------------------------------
# F-FED-7: ReplicationProof.proof_payload_hash length-prefixed encoding
# ---------------------------------------------------------------------------


def test_replication_proof_payload_hash_golden_vector() -> None:
    proof = ReplicationProof(
        challenge_hash="c" * 64,
        guardian_id="guardian-1",
        ledger_tail_hash="d" * 64,
        merkle_root_verified=True,
        proof_sample_indices=(0, 5, 17),
        proof_sample_hashes=("a" * 64, "b" * 64, "e" * 64),
        replicated_at="2026-03-09T00:00:00Z",
        guardian_signature="",
    )
    assert proof.proof_payload_hash() == (
        "e5af90fb7dd3050674989ad9f824b059b7a3e1b6f233ff987c36eefe4c6ed9dd"
    )


def test_replication_proof_payload_hash_prevents_pipe_injection() -> None:
    """A ``|`` inside ``guardian_id`` must NOT collide with a layout that moves
    the boundary into ``ledger_tail_hash``.
    """
    base_kwargs = dict(
        challenge_hash="c" * 64,
        merkle_root_verified=True,
        proof_sample_indices=(0,),
        proof_sample_hashes=("a" * 64,),
        replicated_at="2026-03-09T00:00:00Z",
        guardian_signature="",
    )
    proof_a = ReplicationProof(
        guardian_id="g|x",
        ledger_tail_hash="d" * 64,
        **base_kwargs,
    )
    proof_b = ReplicationProof(
        guardian_id="g",
        ledger_tail_hash="x|" + "d" * 62,
        **base_kwargs,
    )
    assert proof_a.proof_payload_hash() != proof_b.proof_payload_hash()


def test_replication_proof_payload_hash_prevents_comma_collision_in_hashes() -> None:
    """Different ``proof_sample_hashes`` tuples that would collide if comma-joined
    must produce distinct hashes. E.g., ["a,b", "c"] vs ["a", "b,c"].
    """
    base_kwargs = dict(
        challenge_hash="c" * 64,
        guardian_id="guardian-1",
        ledger_tail_hash="d" * 64,
        merkle_root_verified=True,
        proof_sample_indices=(0, 1),
        replicated_at="2026-03-09T00:00:00Z",
        guardian_signature="",
    )
    # These two would produce the same comma-joined string: "abc,def,ghi"
    proof_a = ReplicationProof(
        proof_sample_hashes=("abc,def", "ghi"),
        **base_kwargs,
    )
    proof_b = ReplicationProof(
        proof_sample_hashes=("abc", "def,ghi"),
        **base_kwargs,
    )
    # With per-element length-prefixing, these must be different
    assert proof_a.proof_payload_hash() != proof_b.proof_payload_hash()
