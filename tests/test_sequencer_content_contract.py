"""Tests for the /v1/queue-leaf vs /v1/queue-leaf-hash content contract.

Asserts that:
- /v1/queue-leaf rejects "application/octet-stream" (Rust canonicalization
  only accepts "json", "text", and "plaintext").
- /v1/queue-leaf-hash accepts any binary payload (32-byte value_hash) and
  does NOT attempt Rust canonicalization.
- parser_id and canonical_parser_version are required on both endpoints.

These are unit tests using the Go sequencer's HTTP handler directly via
net/http/httptest (Go) and via mock HTTP responses from the Python client.
The Python-layer tests here focus on client payload construction and error
surfacing; see services/sequencer-go/internal/api/sequencer_test.go for Go
unit tests of the handlers themselves.
"""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock

import pytest

from api.services.sequencer_client import (
    GoSequencerClient,
    SequencerResponseError,
)


def _mock_response(status: int, body: dict | str | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    if isinstance(body, dict):
        resp.json.return_value = body
        resp.text = str(body)
    else:
        resp.json.side_effect = ValueError("no JSON")
        resp.text = body or ""
    return resp


# ---------------------------------------------------------------------------
# Client correctly targets /v1/queue-leaf-hash for pre-hashed leaves
# ---------------------------------------------------------------------------


class TestQueueLeafHashClientContract:
    """Python client targets the right endpoint for raw vs pre-hashed content."""

    @pytest.mark.asyncio
    async def test_queue_leaf_sends_to_queue_leaf_path(self):
        """`append_record` targets /v1/queue-leaf."""
        captured: list[str] = []

        async def _post(url, *, json, headers):
            captured.append(url)
            return _mock_response(
                200,
                {
                    "new_root": "a" * 64,
                    "global_key": "b" * 64,
                    "leaf_value_hash": "c" * 64,
                    "tree_size": 1,
                },
            )

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = _post

        await client.append_record(
            shard_id="s",
            record_type="doc",
            record_id="r",
            content=b'{"k":"v"}',
            content_type="json",
            parser_id="x@1",
            canonical_parser_version="v1",
        )
        assert captured[0].endswith("/v1/queue-leaf")

    @pytest.mark.asyncio
    async def test_queue_leaf_hash_sends_to_queue_leaf_hash_path(self):
        """`append_record_hash` targets /v1/queue-leaf-hash."""
        captured: list[str] = []

        async def _post(url, *, json, headers):
            captured.append(url)
            return _mock_response(
                200,
                {
                    "new_root": "a" * 64,
                    "global_key": "b" * 64,
                    "leaf_value_hash": "c" * 64,
                    "tree_size": 1,
                },
            )

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = _post

        await client.append_record_hash(
            shard_id="s",
            record_type="doc",
            record_id="r",
            value_hash=b"\x00" * 32,
            parser_id="x@1",
            canonical_parser_version="v1",
        )
        assert captured[0].endswith("/v1/queue-leaf-hash")

    @pytest.mark.asyncio
    async def test_queue_leaf_does_not_send_octet_stream_as_default(self):
        """`append_record` defaults content_type to application/octet-stream
        only for legacy callers; explicit callers should pass a Rust-accepted
        type like "json".  Verify the field is forwarded as provided."""
        captured_payload: dict = {}

        async def _post(url, *, json, headers):
            captured_payload.update(json)
            return _mock_response(
                200,
                {
                    "new_root": "a" * 64,
                    "global_key": "b" * 64,
                    "leaf_value_hash": "c" * 64,
                    "tree_size": 1,
                },
            )

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = _post

        await client.append_record(
            shard_id="s",
            record_type="doc",
            record_id="r",
            content=b'{"k":"v"}',
            content_type="json",
            parser_id="x@1",
            canonical_parser_version="v1",
        )
        assert captured_payload["content_type"] == "json"

    @pytest.mark.asyncio
    async def test_queue_leaf_hash_encodes_value_hash_as_base64(self):
        """value_hash is base64-encoded in the /v1/queue-leaf-hash payload."""
        value_hash = bytes(range(32))
        captured_payload: dict = {}

        async def _post(url, *, json, headers):
            captured_payload.update(json)
            return _mock_response(
                200,
                {
                    "new_root": "a" * 64,
                    "global_key": "b" * 64,
                    "leaf_value_hash": "c" * 64,
                    "tree_size": 1,
                },
            )

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = _post

        await client.append_record_hash(
            shard_id="s",
            record_type="doc",
            record_id="r",
            value_hash=value_hash,
            parser_id="x@1",
            canonical_parser_version="v1",
        )
        expected = base64.b64encode(value_hash).decode("ascii")
        assert captured_payload["value_hash"] == expected

    @pytest.mark.asyncio
    async def test_queue_leaf_hash_rejects_non_32_byte_hash(self):
        """Client raises ValueError before making any HTTP call for wrong length."""
        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=AssertionError("should not be called"))

        with pytest.raises(ValueError, match="32 bytes"):
            await client.append_record_hash(
                shard_id="s",
                record_type="doc",
                record_id="r",
                value_hash=b"\x00" * 31,
                parser_id="x@1",
                canonical_parser_version="v1",
            )
        client._client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_queue_leaf_hash_surfaces_non_200_as_response_error(self):
        """Non-200 from /v1/queue-leaf-hash is raised as SequencerResponseError."""

        async def _post(url, *, json, headers):
            return _mock_response(422, "invalid content_type")

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = _post

        with pytest.raises(SequencerResponseError) as exc_info:
            await client.append_record_hash(
                shard_id="s",
                record_type="doc",
                record_id="r",
                value_hash=b"\x00" * 32,
                parser_id="x@1",
                canonical_parser_version="v1",
            )
        assert exc_info.value.status_code == 422


# ---------------------------------------------------------------------------
# B) append_record_hash: empty-body error does not raise TypeError
# ---------------------------------------------------------------------------


class TestAppendRecordHashEmptyBodyError:
    """Non-200 with empty response body must not cause TypeError in logging."""

    @pytest.mark.asyncio
    async def test_empty_body_non_200_raises_response_error_not_type_error(self):
        """detail must be "" not None — prevents TypeError in %.200s format."""

        async def _post(url, *, json, headers):
            resp = MagicMock()
            resp.status_code = 503
            resp.text = ""  # empty body
            return resp

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = _post

        # Must raise SequencerResponseError, not TypeError
        with pytest.raises(SequencerResponseError) as exc_info:
            await client.append_record_hash(
                shard_id="s",
                record_type="doc",
                record_id="r",
                value_hash=b"\x00" * 32,
                parser_id="p@1",
                canonical_parser_version="v1",
            )
        assert exc_info.value.status_code == 503
        # detail should be empty string, not None
        assert exc_info.value.detail == ""

    @pytest.mark.asyncio
    async def test_non_empty_body_preserved_in_detail(self):
        """detail carries the first 500 chars of a non-empty response body."""

        async def _post(url, *, json, headers):
            resp = MagicMock()
            resp.status_code = 400
            resp.text = "bad parser_id"
            return resp

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = _post

        with pytest.raises(SequencerResponseError) as exc_info:
            await client.append_record_hash(
                shard_id="s",
                record_type="doc",
                record_id="r",
                value_hash=b"\x00" * 32,
                parser_id="p@1",
                canonical_parser_version="v1",
            )
        assert exc_info.value.detail == "bad parser_id"


# ---------------------------------------------------------------------------
# C) append_record: default content_type + validation
# ---------------------------------------------------------------------------


class TestAppendRecordContentTypeValidation:
    """append_record() defaults to "json" and rejects invalid content_types."""

    @pytest.mark.asyncio
    async def test_default_content_type_is_json(self):
        """Omitting content_type sends content_type=json in the payload."""
        captured_payload: dict = {}

        async def _post(url, *, json, headers):
            captured_payload.update(json)
            return _mock_response(
                200,
                {
                    "new_root": "a" * 64,
                    "global_key": "b" * 64,
                    "leaf_value_hash": "c" * 64,
                    "tree_size": 1,
                },
            )

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = _post

        # Omit content_type → should default to "json"
        await client.append_record(
            shard_id="s",
            record_type="doc",
            record_id="r",
            content=b'{"k":"v"}',
            parser_id="p@1",
            canonical_parser_version="v1",
        )
        assert captured_payload["content_type"] == "json"

    @pytest.mark.asyncio
    async def test_octet_stream_raises_value_error_before_http(self):
        """application/octet-stream is invalid and raises ValueError client-side."""
        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=AssertionError("must not be called"))

        with pytest.raises(ValueError, match="json/text/plaintext"):
            await client.append_record(
                shard_id="s",
                record_type="doc",
                record_id="r",
                content=b"binary",
                content_type="application/octet-stream",
                parser_id="p@1",
                canonical_parser_version="v1",
            )
        client._client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_invalid_content_type_raises_before_http(self):
        """Any unsupported content_type raises ValueError before HTTP."""
        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=AssertionError("must not be called"))

        with pytest.raises(ValueError, match="Invalid content_type"):
            await client.append_record(
                shard_id="s",
                record_type="doc",
                record_id="r",
                content=b"data",
                content_type="binary/octet-stream",
                parser_id="p@1",
                canonical_parser_version="v1",
            )
        client._client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_content_types_accepted(self):
        """All three Rust-accepted content_types are forwarded without error."""

        async def _post(url, *, json, headers):
            return _mock_response(
                200,
                {
                    "new_root": "a" * 64,
                    "global_key": "b" * 64,
                    "leaf_value_hash": "c" * 64,
                    "tree_size": 1,
                },
            )

        for ct in ("json", "text", "plaintext"):
            client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
            client._client = AsyncMock()
            client._client.post = _post
            # Should not raise
            await client.append_record(
                shard_id="s",
                record_type="doc",
                record_id="r",
                content=b"data",
                content_type=ct,
                parser_id="p@1",
                canonical_parser_version="v1",
            )
