"""Tests for encode_signing_fields() and the field-injection collision fix (C-3).

Security invariant under test:

    # Old (broken) — injection ambiguity:
    assert HASH_SEPARATOR.join(["a|b", "c"]) == HASH_SEPARATOR.join(["a", "b|c"])

    # New (fixed) — unambiguous field boundaries:
    assert encode_signing_fields("a|b", "c") != encode_signing_fields("a", "b|c")
"""

from __future__ import annotations

from protocol.hashes import (
    CHAIN_PROOF_COMMIT_PREFIX,
    CHECKPOINT_PREFIX,
    DA_CHALLENGE_PREFIX,
    GOSSIP_SHARE_COMMIT_PREFIX,
    HASH_SEPARATOR,
    KEY_ROTATION_PREFIX,
    REDACTION_BIND_PREFIX,
    SHARD_NS_PREFIX,
    blake3_hash,
    encode_signing_fields,
)


# ---------------------------------------------------------------------------
# encode_signing_fields — unit tests
# ---------------------------------------------------------------------------


class TestEncodeSigningFields:
    def test_empty_fields_returns_empty_bytes(self):
        assert encode_signing_fields() == b""

    def test_single_empty_string(self):
        result = encode_signing_fields("")
        # 4-byte length prefix of 0, then nothing
        assert result == b"\x00\x00\x00\x00"

    def test_single_ascii_field(self):
        result = encode_signing_fields("abc")
        assert result == b"\x00\x00\x00\x03abc"

    def test_two_fields_concatenated(self):
        result = encode_signing_fields("ab", "cd")
        assert result == b"\x00\x00\x00\x02ab\x00\x00\x00\x02cd"

    def test_length_prefix_is_big_endian(self):
        # 256 bytes → length 256 → 0x00 0x00 0x01 0x00
        field = "x" * 256
        result = encode_signing_fields(field)
        assert result[:4] == b"\x00\x00\x01\x00"
        assert result[4:] == field.encode("utf-8")

    def test_multibyte_utf8_length(self):
        # "é" is 2 bytes in UTF-8
        result = encode_signing_fields("é")
        assert result[:4] == b"\x00\x00\x00\x02"

    def test_returns_bytes(self):
        assert isinstance(encode_signing_fields("x"), bytes)

    def test_three_fields(self):
        result = encode_signing_fields("a", "bb", "ccc")
        expected = b"\x00\x00\x00\x01a\x00\x00\x00\x02bb\x00\x00\x00\x03ccc"
        assert result == expected


# ---------------------------------------------------------------------------
# Canonical collision regression: the CORE security invariant
# ---------------------------------------------------------------------------


class TestFieldInjectionCollision:
    def test_old_join_is_ambiguous(self):
        """Prove that the OLD approach was broken — both produce the same bytes."""
        old_a = HASH_SEPARATOR.join(["a|b", "c"])
        old_b = HASH_SEPARATOR.join(["a", "b|c"])
        assert old_a == old_b, "Old HASH_SEPARATOR.join is ambiguous — this test must pass"

    def test_new_encoding_is_unambiguous(self):
        """Prove that the NEW approach fixes the injection: outputs differ."""
        new_a = encode_signing_fields("a|b", "c")
        new_b = encode_signing_fields("a", "b|c")
        assert new_a != new_b, "encode_signing_fields must disambiguate field boundaries"

    def test_pipe_in_first_field(self):
        assert encode_signing_fields("x|y", "z") != encode_signing_fields("x", "y|z")

    def test_pipe_in_last_field(self):
        assert encode_signing_fields("a", "b|c") != encode_signing_fields("a|b", "c")

    def test_empty_and_separator_fields(self):
        # "" | "a" vs "|a" (single field)
        assert encode_signing_fields("", "a") != encode_signing_fields("|a")

    def test_many_pipes(self):
        assert encode_signing_fields("a||b", "c") != encode_signing_fields("a", "|b", "c")

    def test_deterministic_same_input(self):
        a = encode_signing_fields("node-1", "shard-abc", "0001")
        b = encode_signing_fields("node-1", "shard-abc", "0001")
        assert a == b


# ---------------------------------------------------------------------------
# Domain-prefix constants — smoke tests that they are distinct bytes
# ---------------------------------------------------------------------------


class TestDomainPrefixConstants:
    def test_all_prefixes_are_bytes(self):
        prefixes = [
            CHECKPOINT_PREFIX,
            GOSSIP_SHARE_COMMIT_PREFIX,
            CHAIN_PROOF_COMMIT_PREFIX,
            DA_CHALLENGE_PREFIX,
            REDACTION_BIND_PREFIX,
            SHARD_NS_PREFIX,
            KEY_ROTATION_PREFIX,
        ]
        for p in prefixes:
            assert isinstance(p, bytes)

    def test_all_prefixes_are_distinct(self):
        prefixes = [
            CHECKPOINT_PREFIX,
            GOSSIP_SHARE_COMMIT_PREFIX,
            CHAIN_PROOF_COMMIT_PREFIX,
            DA_CHALLENGE_PREFIX,
            REDACTION_BIND_PREFIX,
            SHARD_NS_PREFIX,
            KEY_ROTATION_PREFIX,
        ]
        assert len(set(prefixes)) == len(prefixes), "Domain prefixes must all be distinct"

    def test_prefixes_start_with_oly(self):
        for prefix in [
            GOSSIP_SHARE_COMMIT_PREFIX,
            CHAIN_PROOF_COMMIT_PREFIX,
            DA_CHALLENGE_PREFIX,
            REDACTION_BIND_PREFIX,
            SHARD_NS_PREFIX,
        ]:
            assert prefix.startswith(b"OLY:"), f"{prefix!r} must start with b'OLY:'"


# ---------------------------------------------------------------------------
# Cross-callsite: same fields + different prefix → different hash
# ---------------------------------------------------------------------------


class TestCrossPrefixIsolation:
    _FIELDS = ("node-1", "shard-test", "42")

    def _h(self, prefix: bytes) -> str:
        return blake3_hash([prefix, encode_signing_fields(*self._FIELDS)]).hex()

    def test_checkpoint_vs_gossip(self):
        assert self._h(CHECKPOINT_PREFIX) != self._h(GOSSIP_SHARE_COMMIT_PREFIX)

    def test_da_challenge_vs_rotation(self):
        assert self._h(DA_CHALLENGE_PREFIX) != self._h(KEY_ROTATION_PREFIX)

    def test_chain_proof_vs_redaction(self):
        assert self._h(CHAIN_PROOF_COMMIT_PREFIX) != self._h(REDACTION_BIND_PREFIX)

    def test_shard_ns_vs_da_challenge(self):
        assert self._h(SHARD_NS_PREFIX) != self._h(DA_CHALLENGE_PREFIX)


# ---------------------------------------------------------------------------
# Callsite smoke tests: verify each migrated function produces a hex string
# ---------------------------------------------------------------------------


class TestCallsiteSmoke:
    def test_checkpoint_vote_event_id(self):
        from protocol.checkpoint_verify import _checkpoint_vote_event_id
        from protocol.federation.identity import FederationNode, FederationRegistry

        node = FederationNode(
            node_id="n1",
            pubkey=b"\x01" * 32,
            endpoint="http://localhost",
            operator="op",
            jurisdiction="US",
        )
        reg = FederationRegistry(nodes=(node,), epoch=0)
        result = _checkpoint_vote_event_id("aabbcc", 1, 100, reg)
        assert isinstance(result, str) and len(result) == 64

    def test_gossip_share_commitments(self):
        from protocol.federation.gossip import build_proactive_share_commitments
        from protocol.federation.identity import FederationNode, FederationRegistry

        node = FederationNode(
            node_id="n1",
            pubkey=b"\x02" * 32,
            endpoint="http://localhost",
            operator="op",
            jurisdiction="US",
        )
        reg = FederationRegistry(nodes=(node,), epoch=1)
        result = build_proactive_share_commitments(reg, epoch=1, refresh_nonce="nonce123")
        assert "n1" in result
        assert len(result["n1"]) == 64

    def test_da_challenge_hash(self):
        from protocol.federation.replication import DataAvailabilityChallenge

        c = DataAvailabilityChallenge(
            shard_id="shard-1",
            header_hash="aabb",
            challenger_id="node-1",
            challenge_nonce="nonce",
            issued_at="2025-01-01T00:00:00Z",
            response_deadline="2025-01-01T01:00:00Z",
        )
        h = c.challenge_hash()
        assert isinstance(h, str) and len(h) == 64

    def test_shard_ns_mapping(self):
        from protocol.shards import ShardNamespacePartitioner

        mapper = ShardNamespacePartitioner(prefix="test", shard_count=8)
        result = mapper.shard_id_for_namespace("gov.watauga")
        assert result.startswith("test-")
        assert result in {f"test-{i}" for i in range(8)}

    def test_chain_proof_commitment(self):
        from protocol.federation.rotation import RecursiveChainProof

        proof = RecursiveChainProof(
            proof_type="groth16",
            previous_root="aabb",
            current_root="ccdd",
            epoch_start=0,
            epoch_end=1,
            transition_count=1,
            proof_data="deadbeef",
            public_inputs=("aabb", "ccdd"),
            verification_key_hash="vkhash",
            created_at="2025-01-01T00:00:00Z",
        )
        h = proof.proof_commitment_hash()
        assert isinstance(h, str) and len(h) == 64
