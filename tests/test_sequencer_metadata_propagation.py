"""Tests for ADR-0003 parser metadata propagation through the sequencer path.

Verifies that parser_id and canonical_parser_version are forwarded correctly
from Python → Go → Rust on the /v1/queue-leaf-hash endpoint.  The tests
exercise the client and storage_layer adapters in isolation using mocks so
that no live Go or Rust service is required.
"""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock

import pytest

from api.services.sequencer_client import (
    GoSequencerClient,
    SequencerAppendResult,
)
from protocol.hashes import leaf_hash


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_append_result(
    new_root: str | None = None,
    leaf_value_hash: str | None = None,
) -> SequencerAppendResult:
    return SequencerAppendResult(
        new_root=new_root or "a" * 64,
        global_key="b" * 64,
        leaf_value_hash=leaf_value_hash or "c" * 64,
        tree_size=1,
    )


# ---------------------------------------------------------------------------
# GoSequencerClient.append_record_hash — payload correctness
# ---------------------------------------------------------------------------


class TestAppendRecordHashPayload:
    """Unit tests for GoSequencerClient.append_record_hash()."""

    @pytest.mark.asyncio
    async def test_forwards_parser_metadata_in_payload(self):
        """parser_id and canonical_parser_version appear in the POST payload."""
        value_hash = bytes(range(32))
        captured_payload: dict = {}

        async def fake_post(url, *, json, headers):
            captured_payload.update(json)
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "new_root": "a" * 64,
                "global_key": "b" * 64,
                "leaf_value_hash": "c" * 64,
                "tree_size": 1,
            }
            return mock_resp

        client = GoSequencerClient(base_url="http://localhost:9999", token="test-token")
        mock_http = AsyncMock()
        mock_http.post = fake_post
        client._client = mock_http

        await client.append_record_hash(
            shard_id="test:shard",
            record_type="artifact",
            record_id="doc-001",
            value_hash=value_hash,
            parser_id="docling@2.3.1",
            canonical_parser_version="v1",
        )

        assert captured_payload["parser_id"] == "docling@2.3.1"
        assert captured_payload["canonical_parser_version"] == "v1"
        assert captured_payload["shard_id"] == "test:shard"
        # value_hash is base64-encoded in the wire payload
        assert captured_payload["value_hash"] == base64.b64encode(value_hash).decode("ascii")

    @pytest.mark.asyncio
    async def test_hits_queue_leaf_hash_endpoint(self):
        """append_record_hash() targets /v1/queue-leaf-hash, not /v1/queue-leaf."""
        captured_url: list[str] = []

        async def fake_post(url, *, json, headers):
            captured_url.append(url)
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "new_root": "a" * 64,
                "global_key": "b" * 64,
                "leaf_value_hash": "c" * 64,
                "tree_size": 1,
            }
            return mock_resp

        client = GoSequencerClient(base_url="http://localhost:9999", token="test-token")
        mock_http = AsyncMock()
        mock_http.post = fake_post
        client._client = mock_http

        await client.append_record_hash(
            shard_id="test:shard",
            record_type="artifact",
            record_id="doc-001",
            value_hash=b"\x00" * 32,
            parser_id="fallback@1.0.0",
            canonical_parser_version="v1",
        )

        assert len(captured_url) == 1
        assert captured_url[0].endswith("/v1/queue-leaf-hash")

    @pytest.mark.asyncio
    async def test_raises_value_error_for_wrong_hash_length(self):
        """append_record_hash raises ValueError when value_hash is not 32 bytes."""
        client = GoSequencerClient(base_url="http://localhost:9999", token="test-token")
        with pytest.raises(ValueError, match="32 bytes"):
            await client.append_record_hash(
                shard_id="test:shard",
                record_type="artifact",
                record_id="doc-001",
                value_hash=b"\x00" * 16,  # wrong length
                parser_id="fallback@1.0.0",
                canonical_parser_version="v1",
            )


# ---------------------------------------------------------------------------
# api.ingest direct queue-leaf helpers — payload correctness
# ---------------------------------------------------------------------------


class TestIngestQueueLeafPayload:
    """Unit tests for the direct ingest.py sequencer payload builders."""

    @pytest.mark.asyncio
    async def test_single_queue_leaf_includes_parser_metadata(self, monkeypatch):
        """_call_sequencer_queue_leaf sends ADR-0003 metadata and Rust content_type."""
        from api import ingest as ingest_api

        captured_payload: dict = {}

        class FakeClient:
            async def post(self, url, *, json, headers):
                captured_payload.update(json)
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {
                    "new_root": "a" * 64,
                    "global_key": "b" * 64,
                    "leaf_value_hash": "c" * 64,
                    "tree_size": 1,
                }
                return mock_resp

        monkeypatch.setenv("INGEST_PARSER_CANONICAL_VERSION", "v9")
        monkeypatch.setattr(ingest_api, "_get_sequencer_client", lambda: FakeClient())

        await ingest_api._call_sequencer_queue_leaf(
            shard_id="shard-1",
            record_type="doc",
            record_id="doc-001",
            version="1",
            canonical_content=b'{"k":"v"}',
        )

        assert captured_payload["content_type"] == "json"
        assert captured_payload["parser_id"] == "fallback@1.0.0"
        assert captured_payload["canonical_parser_version"] == "v9"

    @pytest.mark.asyncio
    async def test_batch_queue_leaves_includes_parser_metadata(self, monkeypatch):
        """_call_sequencer_queue_leaves_batch sends metadata for every record."""
        from api import ingest as ingest_api

        captured_payload: dict = {}

        class FakeClient:
            async def post(self, url, *, json, headers):
                captured_payload.update(json)
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {
                    "results": [
                        {
                            "new_root": "a" * 64,
                            "global_key": "b" * 64,
                            "leaf_value_hash": "c" * 64,
                            "tree_size": 1,
                        }
                    ]
                }
                return mock_resp

        monkeypatch.setenv("INGEST_PARSER_CANONICAL_VERSION", "v7")
        monkeypatch.setattr(ingest_api, "_get_sequencer_client", lambda: FakeClient())

        await ingest_api._call_sequencer_queue_leaves_batch(
            [
                {
                    "shard_id": "shard-1",
                    "record_type": "doc",
                    "record_id": "doc-001",
                    "version": "1",
                    "canonical_content": b'{"k":"v"}',
                }
            ]
        )

        record = captured_payload["records"][0]
        assert record["content_type"] == "json"
        assert record["parser_id"] == "fallback@1.0.0"
        assert record["canonical_parser_version"] == "v7"


class TestSequencerProofSummaryVerification:
    """Sequencer batch proof summaries should verify without Merkle leaf-index crashes."""

    def test_empty_sibling_sequencer_summary_verifies_by_adr_leaf_hash(self):
        from api.services.proof_utils import evaluate_proof_bundle

        content_hash = "11" * 32
        smt_key = "22" * 32
        parser_id = "fallback@1.0.0"
        canonical_parser_version = "v1"
        root_hash = "33" * 32
        proof = {
            "leaf_hash": leaf_hash(
                bytes.fromhex(smt_key),
                bytes.fromhex(content_hash),
                parser_id,
                canonical_parser_version,
            ).hex(),
            "leaf_index": str(int(smt_key, 16)),
            "siblings": [],
            "root_hash": root_hash,
            "tree_size": "1",
            "smt_key": smt_key,
            "parser_id": parser_id,
            "canonical_parser_version": canonical_parser_version,
        }

        normalized_hash, normalized_root, hash_matches, proof_valid = evaluate_proof_bundle(
            content_hash,
            root_hash,
            proof,
        )

        assert normalized_hash == content_hash
        assert normalized_root == root_hash
        assert hash_matches is True
        assert proof_valid is True

    def test_empty_sibling_value_hash_summary_requires_content_hash_binding(self):
        from api.services.proof_utils import evaluate_proof_bundle

        content_hash = "11" * 32
        root_hash = "33" * 32
        proof = {
            "leaf_hash": "44" * 32,
            "leaf_index": str(int("22" * 32, 16)),
            "siblings": [],
            "root_hash": root_hash,
            "content_hash": content_hash,
            "tree_size": "1",
            "smt_key": "22" * 32,
            "parser_id": "fallback@1.0.0",
            "canonical_parser_version": "v1",
        }

        _, _, hash_matches, proof_valid = evaluate_proof_bundle(
            content_hash,
            root_hash,
            proof,
        )

        assert hash_matches is True
        assert proof_valid is True

    def test_empty_sibling_value_hash_summary_rejects_unbound_content_hash(self):
        from api.services.proof_utils import evaluate_proof_bundle

        content_hash = "11" * 32
        root_hash = "33" * 32
        proof = {
            "leaf_hash": "44" * 32,
            "leaf_index": str(int("22" * 32, 16)),
            "siblings": [],
            "root_hash": root_hash,
            "tree_size": "1",
            "smt_key": "22" * 32,
            "parser_id": "fallback@1.0.0",
            "canonical_parser_version": "v1",
        }

        _, _, hash_matches, proof_valid = evaluate_proof_bundle(
            content_hash,
            root_hash,
            proof,
        )

        assert hash_matches is False
        assert proof_valid is False


# ---------------------------------------------------------------------------
# append_via_backend — H-3 fix (uses queue-leaf-hash, not queue-leaf)
# ---------------------------------------------------------------------------


class TestAppendViaBackendSequencerPath:
    """Tests that storage_layer.append_via_backend() uses append_record_hash."""

    @pytest.mark.asyncio
    async def test_calls_append_record_hash_not_append_record(self):
        """The sequencer path must call append_record_hash(), not append_record()."""

        from api.services.storage_layer import append_via_backend

        mock_backend = AsyncMock(spec=GoSequencerClient)
        mock_backend.append_record_hash = AsyncMock(return_value=_make_append_result())
        mock_backend.append_record = AsyncMock(
            side_effect=AssertionError("append_record must not be called on pre-hashed path")
        )
        mock_backend.get_inclusion_proof = AsyncMock(return_value=None)

        value_hash = bytes(range(32))
        result = await append_via_backend(
            shard_id="test:shard",
            record_type="artifact",
            record_id="doc-001",
            version=1,
            value_hash=value_hash,
            parser_id="docling@2.3.1",
            canonical_parser_version="v1",
            want_proof=False,
            backend=mock_backend,
        )

        mock_backend.append_record_hash.assert_called_once()
        call_kwargs = mock_backend.append_record_hash.call_args.kwargs
        assert call_kwargs["parser_id"] == "docling@2.3.1"
        assert call_kwargs["canonical_parser_version"] == "v1"
        assert call_kwargs["value_hash"] == value_hash
        assert result.backend == "sequencer"

    @pytest.mark.asyncio
    async def test_parser_metadata_forwarded_to_append_record_hash(self):
        """parser_id and canonical_parser_version reach append_record_hash()."""
        from api.services.storage_layer import append_via_backend

        mock_backend = AsyncMock(spec=GoSequencerClient)
        mock_backend.append_record_hash = AsyncMock(return_value=_make_append_result())
        mock_backend.get_inclusion_proof = AsyncMock(return_value=None)

        await append_via_backend(
            shard_id="watauga:2025:budget",
            record_type="document",
            record_id="foia-001",
            version=2,
            value_hash=b"\xde\xad\xbe\xef" * 8,
            parser_id="pdfminer@6.0.0",
            canonical_parser_version="v2",
            want_proof=False,
            backend=mock_backend,
        )

        kwargs = mock_backend.append_record_hash.call_args.kwargs
        assert kwargs["parser_id"] == "pdfminer@6.0.0"
        assert kwargs["canonical_parser_version"] == "v2"
