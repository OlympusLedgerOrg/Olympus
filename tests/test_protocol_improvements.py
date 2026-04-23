"""Tests for new protocol improvements (Items 1-10).

These tests validate the new functionality without requiring PostgreSQL.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import nacl.signing
import pytest
from psycopg.pq import TransactionStatus

from storage import postgres as postgres_module
from storage.postgres import StorageLayer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakePool:
    """Minimal pool stub for unit tests that don't touch the database."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.connection = MagicMock()
        self.connection.closed = False
        self.connection.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)

    def getconn(self) -> MagicMock:
        return self.connection

    def putconn(self, _conn: object) -> None:
        pass

    def close(self) -> None:
        pass


@pytest.fixture()
def _fake_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(postgres_module, "ConnectionPool", _FakePool)


# ---------------------------------------------------------------------------
# 🔥 Item 3: Packed path encoding
# ---------------------------------------------------------------------------


class TestPathEncoding:
    """Verify _encode_path packs bits into bytes (MSB first)."""

    def test_empty_path(self) -> None:
        assert StorageLayer._encode_path(()) == b""

    def test_single_zero(self) -> None:
        assert StorageLayer._encode_path((0,)) == b"\x00"

    def test_single_one(self) -> None:
        # 1 bit set in MSB of first byte
        assert StorageLayer._encode_path((1,)) == b"\x80"

    def test_full_byte_all_ones(self) -> None:
        assert StorageLayer._encode_path((1, 1, 1, 1, 1, 1, 1, 1)) == b"\xff"

    def test_full_byte_alternating(self) -> None:
        assert StorageLayer._encode_path((1, 0, 1, 0, 1, 0, 1, 0)) == bytes([0b10101010])

    def test_256_bit_all_ones(self) -> None:
        path = tuple([1] * 256)
        packed = StorageLayer._encode_path(path)
        assert len(packed) == 32
        assert packed == b"\xff" * 32

    def test_256_bit_all_zeros(self) -> None:
        path = tuple([0] * 256)
        packed = StorageLayer._encode_path(path)
        assert len(packed) == 32
        assert packed == b"\x00" * 32

    def test_partial_byte(self) -> None:
        # 5 bits: (1,0,1,1,0) → 10110_000 → 0xB0
        assert StorageLayer._encode_path((1, 0, 1, 1, 0)) == bytes([0xB0])

    def test_deterministic(self) -> None:
        """Encoding is deterministic for the same input."""
        path = tuple([1, 0, 0, 1, 1, 0, 1, 0, 0, 1])
        assert StorageLayer._encode_path(path) == StorageLayer._encode_path(path)

    def test_protocol_state_encode_matches(self) -> None:
        """protocol_state.encode_path matches StorageLayer._encode_path."""
        from storage.protocol_state import encode_path

        paths = [(), (0,), (1,), (1, 0, 1, 0), tuple([1] * 256)]
        for p in paths:
            assert encode_path(p) == StorageLayer._encode_path(p)


# ---------------------------------------------------------------------------
# 🔥 Item 4: Merkle node cache
# ---------------------------------------------------------------------------


class TestNodeCache:
    """Verify the LRU node cache behavior."""

    @pytest.mark.usefixtures("_fake_pool")
    def test_cache_miss_returns_none(self) -> None:
        sl = StorageLayer("postgresql://unused", node_cache_size=10)
        assert sl._cache_get("s", 0, b"\x00") is None

    @pytest.mark.usefixtures("_fake_pool")
    def test_cache_put_and_get(self) -> None:
        sl = StorageLayer("postgresql://unused", node_cache_size=10)
        sl._cache_put("s", 0, b"\x00", b"\xab" * 32)
        assert sl._cache_get("s", 0, b"\x00") == b"\xab" * 32

    @pytest.mark.usefixtures("_fake_pool")
    def test_cache_eviction(self) -> None:
        sl = StorageLayer("postgresql://unused", node_cache_size=2)
        sl._cache_put("s", 0, b"\x01", b"\x01" * 32)
        sl._cache_put("s", 0, b"\x02", b"\x02" * 32)
        # Evicts the first entry
        sl._cache_put("s", 0, b"\x03", b"\x03" * 32)
        assert sl._cache_get("s", 0, b"\x01") is None
        assert sl._cache_get("s", 0, b"\x02") == b"\x02" * 32

    @pytest.mark.usefixtures("_fake_pool")
    def test_cache_lru_promotion(self) -> None:
        sl = StorageLayer("postgresql://unused", node_cache_size=2)
        sl._cache_put("s", 0, b"\x01", b"\x01" * 32)
        sl._cache_put("s", 0, b"\x02", b"\x02" * 32)
        # Access first entry to promote it
        sl._cache_get("s", 0, b"\x01")
        # Now evict — should evict b"\x02" (least recently used)
        sl._cache_put("s", 0, b"\x03", b"\x03" * 32)
        assert sl._cache_get("s", 0, b"\x01") == b"\x01" * 32
        assert sl._cache_get("s", 0, b"\x02") is None

    @pytest.mark.usefixtures("_fake_pool")
    def test_cache_disabled(self) -> None:
        sl = StorageLayer("postgresql://unused", node_cache_size=0)
        sl._cache_put("s", 0, b"\x01", b"\x01" * 32)
        assert sl._cache_get("s", 0, b"\x01") is None

    @pytest.mark.usefixtures("_fake_pool")
    def test_cache_clear(self) -> None:
        sl = StorageLayer("postgresql://unused", node_cache_size=10)
        sl._cache_put("s", 0, b"\x01", b"\x01" * 32)
        sl._cache_clear()
        assert sl._cache_get("s", 0, b"\x01") is None


# ---------------------------------------------------------------------------
# 🔥 Item 1: Module separation
# ---------------------------------------------------------------------------


class TestModuleSeparation:
    """Verify protocol_state and operational_state modules import correctly."""

    def test_protocol_state_imports(self) -> None:
        from storage.protocol_state import (
            assert_root_matches_state,
            encode_path,
            get_header_by_seq,
            load_tree_state,
            persist_tree_nodes,
        )

        assert callable(encode_path)
        assert callable(load_tree_state)
        assert callable(persist_tree_nodes)
        assert callable(get_header_by_seq)
        assert callable(assert_root_matches_state)

    def test_operational_state_imports(self) -> None:
        from storage.operational_state import (
            clear_rate_limits,
            consume_rate_limit,
            get_ingestion_proof,
            get_timestamp_tokens,
            store_ingestion_batch,
            store_timestamp_token,
        )

        assert callable(consume_rate_limit)
        assert callable(clear_rate_limits)
        assert callable(store_ingestion_batch)
        assert callable(get_ingestion_proof)
        assert callable(store_timestamp_token)
        assert callable(get_timestamp_tokens)

    def test_init_exports_submodules(self) -> None:
        import storage

        assert hasattr(storage, "protocol_state")
        assert hasattr(storage, "operational_state")


# ---------------------------------------------------------------------------
# 🔥 Item 5: Consistency checker
# ---------------------------------------------------------------------------


class TestConsistencyChecker:
    """Verify SMTConsistencyChecker behavior."""

    def test_run_once_consistent(self) -> None:
        from storage.consistency_checker import SMTConsistencyChecker

        mock_storage = MagicMock()
        mock_storage.verify_persisted_root.return_value = True
        checker = SMTConsistencyChecker(mock_storage)
        result = checker.run_once("shard-1")
        assert result.consistent is True
        assert result.shard_id == "shard-1"

    def test_run_once_divergent(self) -> None:
        from storage.consistency_checker import SMTConsistencyChecker

        mock_storage = MagicMock()
        mock_storage.verify_persisted_root.return_value = False
        checker = SMTConsistencyChecker(mock_storage)
        result = checker.run_once("shard-1")
        assert result.consistent is False

    def test_run_once_exception(self) -> None:
        from storage.consistency_checker import SMTConsistencyChecker

        mock_storage = MagicMock()
        mock_storage.verify_persisted_root.side_effect = RuntimeError("db down")
        checker = SMTConsistencyChecker(mock_storage)
        result = checker.run_once("shard-1")
        assert result.consistent is False
        assert "db down" in result.error

    def test_run_all(self) -> None:
        from storage.consistency_checker import SMTConsistencyChecker

        mock_storage = MagicMock()
        mock_storage.get_all_shard_ids.return_value = ["a", "b"]
        mock_storage.verify_persisted_root.return_value = True
        checker = SMTConsistencyChecker(mock_storage)
        report = checker.run_all()
        assert report.all_consistent is True
        assert len(report.results) == 2

    def test_run_all_halt_on_divergence(self) -> None:
        from storage.consistency_checker import SMTConsistencyChecker

        mock_storage = MagicMock()
        mock_storage.get_all_shard_ids.return_value = ["a", "b", "c"]
        mock_storage.verify_persisted_root.return_value = False
        checker = SMTConsistencyChecker(mock_storage, halt_on_divergence=True)
        report = checker.run_all()
        # Should halt after first divergent shard
        assert len(report.results) == 1
        assert report.divergent_shards == ["a"]

    def test_start_stop(self) -> None:
        from storage.consistency_checker import SMTConsistencyChecker

        mock_storage = MagicMock()
        mock_storage.get_all_shard_ids.return_value = []
        checker = SMTConsistencyChecker(mock_storage)
        checker.start(interval_seconds=0.05)
        time.sleep(0.15)
        checker.stop(timeout=2.0)
        assert mock_storage.get_all_shard_ids.called


# ---------------------------------------------------------------------------
# 🔥 Item 6: Strengthened timestamp semantics
# ---------------------------------------------------------------------------


class TestTimestampSemantics:
    """Verify strengthened timestamp token functions."""

    def test_extract_tsa_certificate_invalid_bytes(self) -> None:
        from protocol.rfc3161 import extract_tsa_certificate

        assert extract_tsa_certificate(b"not a token") is None

    def test_check_expiry_invalid_bytes(self) -> None:
        from protocol.rfc3161 import check_tsa_certificate_expiry

        result = check_tsa_certificate_expiry(b"invalid")
        assert result["valid"] is False
        assert result["warning"] is True

    def test_validate_chain_invalid_bytes(self) -> None:
        from protocol.rfc3161 import validate_tsa_certificate_chain

        result = validate_tsa_certificate_chain(b"invalid")
        assert result["valid"] is False
        assert result["fingerprint"] is None


# ---------------------------------------------------------------------------
# 🔥 Item 9: Verification bundle
# ---------------------------------------------------------------------------


class TestVerificationBundle:
    """Verify the verification bundle generator imports and constants."""

    def test_bundle_version(self) -> None:
        from protocol.verification_bundle import BUNDLE_VERSION

        assert BUNDLE_VERSION == "1.0.0"

    def test_create_bundle_missing_record(self) -> None:
        from protocol.verification_bundle import create_verification_bundle

        mock_storage = MagicMock()
        mock_storage.get_proof.return_value = None
        with pytest.raises(ValueError, match="Record not found"):
            create_verification_bundle(
                mock_storage,
                shard_id="shard-1",
                record_type="document",
                record_id="doc-1",
                version=1,
            )

    def test_create_bundle_missing_header(self) -> None:
        from protocol.verification_bundle import create_verification_bundle

        mock_storage = MagicMock()
        mock_proof = MagicMock()
        mock_storage.get_proof.return_value = mock_proof
        mock_storage.get_latest_header.return_value = None
        with pytest.raises(ValueError, match="No shard header found"):
            create_verification_bundle(
                mock_storage,
                shard_id="shard-1",
                record_type="document",
                record_id="doc-1",
                version=1,
            )

    def test_create_bundle_success(self) -> None:
        from protocol.verification_bundle import create_verification_bundle

        mock_proof = MagicMock()
        mock_proof.to_dict.return_value = {"exists": True, "key": "abc"}

        mock_entry = MagicMock()
        mock_entry.canonicalization = {"format": "json"}

        mock_storage = MagicMock()
        mock_storage.get_proof.return_value = mock_proof
        mock_storage.get_latest_header.return_value = {
            "header": {
                "shard_id": "s",
                "root_hash": "a" * 64,
                "timestamp": "2025-01-01T00:00:00Z",
                "previous_header_hash": "",
                "header_hash": "b" * 64,
            },
            "signature": "c" * 128,
            "pubkey": "d" * 64,
        }
        mock_storage.get_ledger_tail.return_value = [mock_entry]
        mock_storage.get_timestamp_token.return_value = None

        bundle = create_verification_bundle(
            mock_storage,
            shard_id="s",
            record_type="document",
            record_id="doc-1",
            version=1,
        )
        assert bundle["bundle_version"] == "1.0.0"
        assert "shard_header" in bundle
        assert "smt_proof" in bundle
        assert bundle["canonicalization"] == {"format": "json"}

    def test_create_bundle_includes_signed_tree_head(self) -> None:
        from protocol.epochs import SignedTreeHead
        from protocol.verification_bundle import create_verification_bundle

        signing_key = nacl.signing.SigningKey.generate()
        signed_tree_head = SignedTreeHead.create(
            epoch_id=7,
            tree_size=1,
            merkle_root=b"\xaa" * 32,
            signing_key=signing_key,
            timestamp="2025-01-01T00:00:00Z",
        )

        mock_proof = MagicMock()
        mock_proof.to_dict.return_value = {"exists": True, "key": "abc"}

        mock_entry = MagicMock()
        mock_entry.canonicalization = {"format": "json"}

        mock_storage = MagicMock()
        mock_storage.get_proof.return_value = mock_proof
        mock_storage.get_latest_header.return_value = {
            "header": {
                "shard_id": "s",
                "root_hash": "a" * 64,
                "timestamp": "2025-01-01T00:00:00Z",
                "previous_header_hash": "",
                "header_hash": "b" * 64,
            },
            "signature": "c" * 128,
            "pubkey": "d" * 64,
        }
        mock_storage.get_ledger_tail.return_value = [mock_entry]
        mock_storage.get_timestamp_token.return_value = None

        bundle = create_verification_bundle(
            mock_storage,
            shard_id="s",
            record_type="document",
            record_id="doc-1",
            version=1,
            signed_tree_head=signed_tree_head,
        )

        assert bundle["signed_tree_head"] == signed_tree_head.to_dict()


# ---------------------------------------------------------------------------
# 🔥 Item 10: SMT specification
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 🔥 Item 8: Schema generation
# ---------------------------------------------------------------------------


class TestSchemaGeneration:
    """Verify schema generation tool imports and runs."""

    def test_generate_json_schema(self) -> None:
        from pydantic import BaseModel, Field

        from tools.generate_schemas import generate_json_schema

        class SampleModel(BaseModel):
            name: str = Field(..., description="A name")
            count: int = Field(0, ge=0)

        schema = generate_json_schema(SampleModel)
        assert schema["type"] == "object"
        assert "name" in schema["properties"]
        assert "count" in schema["properties"]
