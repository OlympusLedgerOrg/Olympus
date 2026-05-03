"""Tests for append_records_batch() ADR-0003 pre-HTTP validation.

Verifies that:
- Batch records missing parser_id, canonical_parser_version, or valid
  content_type raise ValueError with per-record index + record_id context
  *before* any HTTP call is made.
- Valid batch records still reach the HTTP endpoint.
- Each error message identifies the specific failing record by index and id.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from api.services.sequencer_client import GoSequencerClient, SequencerAppendResult


def _ok_response() -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "results": [
            {
                "new_root": "a" * 64,
                "global_key": "b" * 64,
                "leaf_value_hash": "c" * 64,
                "tree_size": 1,
            }
        ]
    }
    return resp


def _valid_record(record_id: str = "r-001") -> dict:
    return {
        "shard_id": "test:shard",
        "record_type": "doc",
        "record_id": record_id,
        "content": b'{"k":"v"}',
        "content_type": "json",
        "parser_id": "docling@2.3.1",
        "canonical_parser_version": "v1",
    }


class TestAppendRecordsBatchValidation:
    """append_records_batch() must validate ADR-0003 fields before HTTP."""

    @pytest.mark.asyncio
    async def test_valid_batch_sends_http_request(self):
        """A well-formed batch reaches the HTTP endpoint."""
        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=_ok_response())

        results = await client.append_records_batch([_valid_record()])

        client._client.post.assert_called_once()
        assert len(results) == 1
        assert isinstance(results[0], SequencerAppendResult)

    @pytest.mark.asyncio
    async def test_empty_parser_id_raises_before_http(self):
        """Empty parser_id raises ValueError without HTTP call."""
        bad = _valid_record()
        bad["parser_id"] = ""

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=AssertionError("must not be called"))

        with pytest.raises(ValueError) as exc_info:
            await client.append_records_batch([bad])
        client._client.post.assert_not_called()
        assert "parser_id" in str(exc_info.value)
        assert "record 0" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_missing_parser_id_raises_before_http(self):
        """Missing parser_id key raises ValueError without HTTP call."""
        bad = _valid_record()
        del bad["parser_id"]

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=AssertionError("must not be called"))

        with pytest.raises(ValueError, match="parser_id"):
            await client.append_records_batch([bad])
        client._client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_canonical_parser_version_raises_before_http(self):
        """Empty canonical_parser_version raises ValueError without HTTP call."""
        bad = _valid_record()
        bad["canonical_parser_version"] = ""

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=AssertionError("must not be called"))

        with pytest.raises(ValueError) as exc_info:
            await client.append_records_batch([bad])
        client._client.post.assert_not_called()
        assert "canonical_parser_version" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_invalid_content_type_raises_before_http(self):
        """Invalid content_type raises ValueError without HTTP call."""
        bad = _valid_record()
        bad["content_type"] = "application/octet-stream"

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=AssertionError("must not be called"))

        with pytest.raises(ValueError, match="json/text/plaintext"):
            await client.append_records_batch([bad])
        client._client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_bytes_content_raises_before_http(self):
        """content that is not bytes raises ValueError without HTTP call."""
        bad = _valid_record()
        bad["content"] = '{"k":"v"}'  # string, not bytes

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=AssertionError("must not be called"))

        with pytest.raises(ValueError, match="content must be bytes"):
            await client.append_records_batch([bad])
        client._client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_error_identifies_failing_record_by_index_and_id(self):
        """Error message includes record index and record_id for context."""
        records = [
            _valid_record("r-001"),
            _valid_record("r-002"),
            {
                **_valid_record("r-003"),
                "parser_id": "",  # third record is bad
            },
        ]

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=AssertionError("must not be called"))

        with pytest.raises(ValueError) as exc_info:
            await client.append_records_batch(records)

        msg = str(exc_info.value)
        assert "record 2" in msg, f"Expected 'record 2' in error, got: {msg}"
        assert "r-003" in msg, f"Expected record_id in error, got: {msg}"
        client._client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_first_invalid_record_stops_validation(self):
        """Validation stops at the first bad record (fail-fast)."""
        records = [
            {**_valid_record("r-001"), "parser_id": ""},  # fails first
            {**_valid_record("r-002"), "canonical_parser_version": ""},  # would also fail
        ]

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=AssertionError("must not be called"))

        with pytest.raises(ValueError) as exc_info:
            await client.append_records_batch(records)

        msg = str(exc_info.value)
        # Only the first failure should appear
        assert "record 0" in msg
        assert "parser_id" in msg
        client._client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_batch_default_content_type_json(self):
        """Batch records without content_type default to 'json'."""
        record = _valid_record()
        del record["content_type"]  # omit content_type

        captured_payload: dict = {}

        async def _post(url, *, json, headers):
            captured_payload.update(json)
            return _ok_response()

        client = GoSequencerClient(base_url="http://localhost:9999", token="tok")
        client._client = AsyncMock()
        client._client.post = _post

        await client.append_records_batch([record])

        assert captured_payload["records"][0]["content_type"] == "json"
