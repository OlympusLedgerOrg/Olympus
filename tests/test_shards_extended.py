"""Extended tests for protocol/shards.py targeting uncovered lines."""

import pytest
import nacl.signing

from protocol.shards import (
    ShardNamespacePartitioner,
    _hkdf_derive,
    canonical_header,
    create_shard_header,
    sign_header,
    verify_header,
    create_key_revocation_record,
    verify_key_revocation_record,
    create_superseding_signature,
    verify_superseding_signature,
    verify_header_with_rotation,
    rotation_record_to_event,
    get_signing_key_from_seed,
    derive_scoped_signing_key,
    get_verify_key_from_signing_key,
    _HKDF_SALT,
)
from protocol.hlc import HLCTimestamp
from protocol.timestamps import current_timestamp


# ── ShardNamespacePartitioner (lines 68-71, 74-79) ──


class TestShardNamespacePartitioner:
    def test_zero_shard_count(self):
        with pytest.raises(ValueError, match="positive"):
            ShardNamespacePartitioner(shard_count=0)

    def test_empty_prefix(self):
        with pytest.raises(ValueError, match="non-empty"):
            ShardNamespacePartitioner(shard_count=1, prefix="")

    def test_empty_namespace(self):
        p = ShardNamespacePartitioner(shard_count=4)
        with pytest.raises(ValueError, match="non-empty"):
            p.shard_id_for_namespace("")

    def test_deterministic_mapping(self):
        p = ShardNamespacePartitioner(shard_count=4)
        result = p.shard_id_for_namespace("test-ns")
        assert result.startswith("shard-")
        assert p.shard_id_for_namespace("test-ns") == result


# ── _HKDF_SALT length (line 48) ──


class TestHKDFSalt:
    def test_salt_is_32_bytes(self):
        assert len(_HKDF_SALT) == 32


# ── create_shard_header edge cases (lines 168-169, 171, 174, 188-189) ──


class TestCreateShardHeader:
    def test_non_integer_height(self):
        with pytest.raises(ValueError, match="integers"):
            create_shard_header("s1", b"\x00" * 32, "2025-01-01T00:00:00Z", height="abc")

    def test_negative_height(self):
        with pytest.raises(ValueError, match="non-negative"):
            create_shard_header("s1", b"\x00" * 32, "2025-01-01T00:00:00Z", height=-1)

    def test_negative_tree_size(self):
        with pytest.raises(ValueError, match="non-negative"):
            create_shard_header("s1", b"\x00" * 32, "2025-01-01T00:00:00Z", tree_size=-1)

    def test_wrong_root_hash_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            create_shard_header("s1", b"\x00" * 16, "2025-01-01T00:00:00Z")

    def test_with_timestamp_token_dict(self):
        header = create_shard_header(
            "s1", b"\x00" * 32, "2025-01-01T00:00:00Z",
            timestamp_token={"token": "value"},
        )
        assert header["timestamp_token"] == {"token": "value"}


# ── verify_header edge cases (lines 272-273) ──


class TestVerifyHeader:
    def _make_signed_header(self):
        sk = nacl.signing.SigningKey.generate()
        vk = sk.verify_key
        header = create_shard_header("s1", b"\x00" * 32, "2025-01-01T00:00:00Z")
        sig = sign_header(header, sk)
        return header, sig, vk, sk

    def test_bad_signature_returns_false(self):
        header, sig, vk, _ = self._make_signed_header()
        assert verify_header(header, "00" * 64, vk) is False

    def test_replay_detection(self):
        header, sig, vk, _ = self._make_signed_header()
        header["sequence_number"] = 5
        # Re-create header hash since we changed fields
        # Actually just test with the original header
        header2 = create_shard_header("s1", b"\x00" * 32, "2025-01-01T00:00:00Z")
        header2["sequence_number"] = 5
        from protocol.shards import shard_header_hash, _HEADER_EXCLUDED_FIELDS
        header2["header_hash"] = shard_header_hash(
            {k: v for k, v in header2.items() if k not in _HEADER_EXCLUDED_FIELDS}
        ).hex()
        sk2 = nacl.signing.SigningKey.generate()
        sig2 = sign_header(header2, sk2)
        # prev_sequence >= seq → replay
        assert verify_header(header2, sig2, sk2.verify_key, prev_sequence=10) is False

    def test_timestamp_hlc_bad_format(self):
        header, sig, vk, sk = self._make_signed_header()
        header["timestamp_hlc"] = "not-hex"
        # Need to recompute hash
        from protocol.shards import shard_header_hash, _HEADER_EXCLUDED_FIELDS
        header["header_hash"] = shard_header_hash(
            {k: v for k, v in header.items() if k not in _HEADER_EXCLUDED_FIELDS}
        ).hex()
        sig = sign_header(header, sk)
        now_hlc = HLCTimestamp(wall_ms=1000, counter=0)
        assert verify_header(header, sig, vk, now_hlc=now_hlc) is False


# ── verify_key_revocation_record edge cases (lines 392, 394, 399-401, 407, 416-417) ──


class TestVerifyKeyRevocationRecord:
    def test_missing_fields(self):
        assert verify_key_revocation_record({}) is False

    def test_wrong_event_type(self):
        record = {
            "event_type": "wrong",
            "old_pubkey": "aa" * 32,
            "new_pubkey": "bb" * 32,
            "compromise_timestamp": "2025-01-01T00:00:00Z",
            "last_good_sequence": 0,
            "reason": "test",
            "signature": "cc" * 64,
        }
        assert verify_key_revocation_record(record) is False

    def test_negative_last_good_sequence(self):
        sk = nacl.signing.SigningKey.generate()
        old_sk = nacl.signing.SigningKey.generate()
        record = create_key_revocation_record(
            old_verify_key=old_sk.verify_key,
            new_signing_key=sk,
            compromise_timestamp="2025-01-01T00:00:00Z",
            last_good_sequence=0,
        )
        record["last_good_sequence"] = -1
        assert verify_key_revocation_record(record) is False

    def test_valid_dual_signed(self):
        old_sk = nacl.signing.SigningKey.generate()
        new_sk = nacl.signing.SigningKey.generate()
        record = create_key_revocation_record(
            old_verify_key=old_sk.verify_key,
            new_signing_key=new_sk,
            compromise_timestamp="2025-01-01T00:00:00Z",
            last_good_sequence=5,
            old_signing_key=old_sk,
        )
        assert record["dual_signed"] is True
        assert verify_key_revocation_record(record) is True

    def test_single_signed_warns(self):
        old_sk = nacl.signing.SigningKey.generate()
        new_sk = nacl.signing.SigningKey.generate()
        record = create_key_revocation_record(
            old_verify_key=old_sk.verify_key,
            new_signing_key=new_sk,
            compromise_timestamp="2025-01-01T00:00:00Z",
            last_good_sequence=5,
        )
        assert record["dual_signed"] is False
        assert verify_key_revocation_record(record) is True

    def test_dual_signed_missing_old_sig(self):
        old_sk = nacl.signing.SigningKey.generate()
        new_sk = nacl.signing.SigningKey.generate()
        record = create_key_revocation_record(
            old_verify_key=old_sk.verify_key,
            new_signing_key=new_sk,
            compromise_timestamp="2025-01-01T00:00:00Z",
            last_good_sequence=5,
            old_signing_key=old_sk,
        )
        del record["old_key_signature"]
        assert verify_key_revocation_record(record) is False


# ── verify_superseding_signature (lines 491, 493, 495, 497, 499, 501, 505, 508-509) ──


class TestVerifySupersedingSignature:
    def _setup(self):
        old_sk = nacl.signing.SigningKey.generate()
        new_sk = nacl.signing.SigningKey.generate()
        revocation = create_key_revocation_record(
            old_verify_key=old_sk.verify_key,
            new_signing_key=new_sk,
            compromise_timestamp="2025-01-01T00:00:00Z",
            last_good_sequence=5,
            old_signing_key=old_sk,
        )
        header_hash = "dd" * 32
        superseding = create_superseding_signature(
            header_hash=header_hash,
            old_verify_key=old_sk.verify_key,
            new_signing_key=new_sk,
            supersedes_from="2025-01-01T00:00:00Z",
        )
        return old_sk, new_sk, revocation, header_hash, superseding

    def test_valid_superseding(self):
        _, _, revocation, header_hash, superseding = self._setup()
        assert verify_superseding_signature(superseding, header_hash=header_hash, revocation_record=revocation)

    def test_missing_fields(self):
        assert verify_superseding_signature({}, header_hash="aa", revocation_record={}) is False

    def test_wrong_event_type(self):
        _, _, revocation, header_hash, superseding = self._setup()
        superseding["event_type"] = "wrong"
        assert verify_superseding_signature(superseding, header_hash=header_hash, revocation_record=revocation) is False

    def test_wrong_header_hash(self):
        _, _, revocation, _, superseding = self._setup()
        assert verify_superseding_signature(superseding, header_hash="ee" * 32, revocation_record=revocation) is False

    def test_wrong_old_pubkey(self):
        _, _, revocation, header_hash, superseding = self._setup()
        revocation["old_pubkey"] = "ff" * 32
        assert verify_superseding_signature(superseding, header_hash=header_hash, revocation_record=revocation) is False


# ── rotation_record_to_event (lines 539, 543, 551, 594-605) ──


class TestRotationRecordToEvent:
    def test_invalid_revocation_record(self):
        with pytest.raises(ValueError, match="Invalid key revocation"):
            rotation_record_to_event({"event_type": "key_revocation"})

    def test_unsupported_event_type(self):
        with pytest.raises(ValueError, match="Unsupported"):
            rotation_record_to_event({"event_type": "unknown"})

    def test_superseding_without_revocation(self):
        with pytest.raises(ValueError, match="require revocation_record"):
            rotation_record_to_event({"event_type": "superseding_signature"})

    def test_valid_revocation_event(self):
        old_sk = nacl.signing.SigningKey.generate()
        new_sk = nacl.signing.SigningKey.generate()
        record = create_key_revocation_record(
            old_verify_key=old_sk.verify_key,
            new_signing_key=new_sk,
            compromise_timestamp="2025-01-01T00:00:00Z",
            last_good_sequence=5,
            old_signing_key=old_sk,
        )
        event = rotation_record_to_event(record)
        assert event.schema_version == "olympus.key-rotation.v1"


# ── verify_header_with_rotation edge cases (lines 556->560, 561) ──


class TestVerifyHeaderWithRotation:
    def test_no_revocation(self):
        sk = nacl.signing.SigningKey.generate()
        header = create_shard_header("s1", b"\x00" * 32, "2025-01-01T00:00:00Z")
        sig = sign_header(header, sk)
        assert verify_header_with_rotation(header, sig, sk.verify_key) is True

    def test_header_signed_by_new_key_after_revocation(self):
        old_sk = nacl.signing.SigningKey.generate()
        new_sk = nacl.signing.SigningKey.generate()
        revocation = create_key_revocation_record(
            old_verify_key=old_sk.verify_key,
            new_signing_key=new_sk,
            compromise_timestamp="2025-01-01T00:00:00Z",
            last_good_sequence=5,
            old_signing_key=old_sk,
        )
        header = create_shard_header("s1", b"\x00" * 32, "2025-06-01T00:00:00Z")
        sig = sign_header(header, new_sk)
        assert verify_header_with_rotation(header, sig, new_sk.verify_key, revocation_record=revocation) is True


# ── get_signing_key_from_seed (line 669, 671) ──


class TestGetSigningKeyFromSeed:
    def test_wrong_seed_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            get_signing_key_from_seed(b"\x00" * 16)

    def test_valid_seed(self):
        key = get_signing_key_from_seed(b"\x01" * 32)
        assert isinstance(key, nacl.signing.SigningKey)

    def test_deterministic(self):
        k1 = get_signing_key_from_seed(b"\x02" * 32)
        k2 = get_signing_key_from_seed(b"\x02" * 32)
        assert k1.encode() == k2.encode()


# ── derive_scoped_signing_key (lines 668-698) ──


class TestDeriveScopedSigningKey:
    def test_empty_master_seed(self):
        with pytest.raises(ValueError, match="non-empty"):
            derive_scoped_signing_key(b"", "shard1")

    def test_empty_shard_id(self):
        with pytest.raises(ValueError, match="non-empty"):
            derive_scoped_signing_key(b"\x01" * 32, "")

    def test_empty_node_id(self):
        with pytest.raises(ValueError, match="non-empty"):
            derive_scoped_signing_key(b"\x01" * 32, "shard1", node_id="")

    def test_with_node_id(self):
        key = derive_scoped_signing_key(b"\x01" * 32, "shard1", node_id="node1")
        assert isinstance(key, nacl.signing.SigningKey)

    def test_without_node_id(self):
        key = derive_scoped_signing_key(b"\x01" * 32, "shard1")
        assert isinstance(key, nacl.signing.SigningKey)

    def test_different_node_ids_differ(self):
        k1 = derive_scoped_signing_key(b"\x01" * 32, "shard1", node_id="node1")
        k2 = derive_scoped_signing_key(b"\x01" * 32, "shard1", node_id="node2")
        assert k1.encode() != k2.encode()
