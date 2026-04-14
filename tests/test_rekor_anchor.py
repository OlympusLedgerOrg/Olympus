"""Tests for Sigstore Rekor transparency log integration.

These tests verify the RekorAnchor class and fire_and_forget_anchor function
using respx to mock the Rekor API. Tests cover:
- Successful anchoring
- Rekor timeout (ingest still succeeds)
- Rekor 4xx error (ingest still succeeds, status set to 'failed')
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from integrations.rekor import (
    DEFAULT_REKOR_URL,
    RekorAnchor,
    RekorAnchorResult,
    _rekor_enabled,
    fire_and_forget_anchor,
)


@pytest.fixture
def mock_http_client():
    """Create a mock async HTTP client."""
    return httpx.AsyncClient()


@pytest.fixture
def sample_hashes():
    """Sample header and root hashes for testing."""
    return {
        "header_hash": bytes.fromhex("aa" * 32),
        "root_hash": bytes.fromhex("bb" * 32),
        "shard_id": "test.shard",
        "seq": 42,
    }


class TestRekorEnabled:
    """Tests for the _rekor_enabled helper function."""

    def test_rekor_disabled_by_default(self):
        """Rekor should be disabled when env var is not set."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("OLYMPUS_REKOR_ENABLED", None)
            assert _rekor_enabled() is False

    def test_rekor_enabled_with_true(self):
        """Rekor should be enabled when set to 'true'."""
        with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "true"}):
            assert _rekor_enabled() is True

    def test_rekor_enabled_with_1(self):
        """Rekor should be enabled when set to '1'."""
        with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "1"}):
            assert _rekor_enabled() is True

    def test_rekor_enabled_with_yes(self):
        """Rekor should be enabled when set to 'yes'."""
        with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "yes"}):
            assert _rekor_enabled() is True

    def test_rekor_disabled_with_false(self):
        """Rekor should be disabled when set to 'false'."""
        with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "false"}):
            assert _rekor_enabled() is False


class TestRekorAnchorResult:
    """Tests for the RekorAnchorResult dataclass."""

    def test_successful_result(self):
        """Test creating a successful result."""
        result = RekorAnchorResult(
            success=True,
            rekor_uuid="abc123",
            rekor_index=12345,
            verification_url="https://rekor.sigstore.dev/api/v1/log/entries?logIndex=12345",
        )
        assert result.success is True
        assert result.rekor_uuid == "abc123"
        assert result.rekor_index == 12345
        assert result.error_message is None

    def test_failed_result(self):
        """Test creating a failed result."""
        result = RekorAnchorResult(
            success=False,
            error_message="Connection timeout",
        )
        assert result.success is False
        assert result.rekor_uuid is None
        assert result.error_message == "Connection timeout"


class TestRekorAnchorCommitment:
    """Tests for the RekorAnchor.anchor_commitment method."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_successful_anchor(self, mock_http_client, sample_hashes):
        """Test successful anchoring to Rekor."""
        rekor_uuid = "24296fb24b8ad77a66c63bc03e1e2e6b"
        log_index = 98765

        # Mock successful Rekor response
        respx.post(f"{DEFAULT_REKOR_URL}/api/v1/log/entries").mock(
            return_value=httpx.Response(
                201,
                json={
                    rekor_uuid: {
                        "logIndex": log_index,
                        "body": "base64body",
                    }
                },
            )
        )

        with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "true"}):
            anchor = RekorAnchor(mock_http_client)
            result = await anchor.anchor_commitment(
                shard_id=sample_hashes["shard_id"],
                seq=sample_hashes["seq"],
                header_hash=sample_hashes["header_hash"],
                root_hash=sample_hashes["root_hash"],
            )

        assert result.success is True
        assert result.rekor_uuid == rekor_uuid
        assert result.rekor_index == log_index
        assert result.verification_url == (
            f"{DEFAULT_REKOR_URL}/api/v1/log/entries?logIndex={log_index}"
        )

    @pytest.mark.asyncio
    async def test_anchor_disabled(self, mock_http_client, sample_hashes):
        """Test anchoring when Rekor is disabled."""
        with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "false"}):
            anchor = RekorAnchor(mock_http_client)
            result = await anchor.anchor_commitment(
                shard_id=sample_hashes["shard_id"],
                seq=sample_hashes["seq"],
                header_hash=sample_hashes["header_hash"],
                root_hash=sample_hashes["root_hash"],
            )

        assert result.success is False
        assert result.error_message == "Rekor anchoring is disabled"

    @pytest.mark.asyncio
    @respx.mock
    async def test_anchor_timeout(self, mock_http_client, sample_hashes):
        """Test that Rekor timeout does not block ingest."""
        # Mock timeout
        respx.post(f"{DEFAULT_REKOR_URL}/api/v1/log/entries").mock(
            side_effect=httpx.TimeoutException("Connection timeout")
        )

        with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "true"}):
            anchor = RekorAnchor(mock_http_client, timeout_seconds=0.1)
            result = await anchor.anchor_commitment(
                shard_id=sample_hashes["shard_id"],
                seq=sample_hashes["seq"],
                header_hash=sample_hashes["header_hash"],
                root_hash=sample_hashes["root_hash"],
            )

        assert result.success is False
        assert "timed out" in result.error_message

    @pytest.mark.asyncio
    @respx.mock
    async def test_anchor_4xx_error(self, mock_http_client, sample_hashes):
        """Test that Rekor 4xx error does not block ingest."""
        # Mock 400 Bad Request
        respx.post(f"{DEFAULT_REKOR_URL}/api/v1/log/entries").mock(
            return_value=httpx.Response(400, json={"error": "Bad request"})
        )

        with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "true"}):
            anchor = RekorAnchor(mock_http_client)
            result = await anchor.anchor_commitment(
                shard_id=sample_hashes["shard_id"],
                seq=sample_hashes["seq"],
                header_hash=sample_hashes["header_hash"],
                root_hash=sample_hashes["root_hash"],
            )

        assert result.success is False
        assert "HTTP 400" in result.error_message

    @pytest.mark.asyncio
    @respx.mock
    async def test_anchor_5xx_error(self, mock_http_client, sample_hashes):
        """Test that Rekor 5xx error does not block ingest."""
        # Mock 500 Internal Server Error
        respx.post(f"{DEFAULT_REKOR_URL}/api/v1/log/entries").mock(
            return_value=httpx.Response(500, json={"error": "Server error"})
        )

        with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "true"}):
            anchor = RekorAnchor(mock_http_client)
            result = await anchor.anchor_commitment(
                shard_id=sample_hashes["shard_id"],
                seq=sample_hashes["seq"],
                header_hash=sample_hashes["header_hash"],
                root_hash=sample_hashes["root_hash"],
            )

        assert result.success is False
        assert "HTTP 500" in result.error_message

    @pytest.mark.asyncio
    @respx.mock
    async def test_anchor_connection_error(self, mock_http_client, sample_hashes):
        """Test that connection errors do not block ingest."""
        # Mock connection error
        respx.post(f"{DEFAULT_REKOR_URL}/api/v1/log/entries").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "true"}):
            anchor = RekorAnchor(mock_http_client)
            result = await anchor.anchor_commitment(
                shard_id=sample_hashes["shard_id"],
                seq=sample_hashes["seq"],
                header_hash=sample_hashes["header_hash"],
                root_hash=sample_hashes["root_hash"],
            )

        assert result.success is False
        assert "request failed" in result.error_message


class TestRekorAnchorShardHeader:
    """Tests for the RekorAnchor.anchor_shard_header method."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_anchor_shard_header_success(self, mock_http_client, sample_hashes):
        """Test successful shard header anchoring with storage persistence."""
        rekor_uuid = "24296fb24b8ad77a66c63bc03e1e2e6b"
        log_index = 98765

        # Mock successful Rekor response
        respx.post(f"{DEFAULT_REKOR_URL}/api/v1/log/entries").mock(
            return_value=httpx.Response(
                201,
                json={
                    rekor_uuid: {
                        "logIndex": log_index,
                        "body": "base64body",
                    }
                },
            )
        )

        # Mock storage layer
        mock_storage = MagicMock()
        mock_storage.create_rekor_anchor.return_value = 1
        mock_storage.update_rekor_anchor.return_value = None

        with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "true"}):
            anchor = RekorAnchor(mock_http_client)
            result = await anchor.anchor_shard_header(
                storage=mock_storage,
                shard_id=sample_hashes["shard_id"],
                seq=sample_hashes["seq"],
                header_hash=sample_hashes["header_hash"],
                root_hash=sample_hashes["root_hash"],
            )

        assert result.success is True
        assert result.rekor_uuid == rekor_uuid

        # Verify storage calls
        mock_storage.create_rekor_anchor.assert_called_once_with(
            shard_id=sample_hashes["shard_id"],
            shard_seq=sample_hashes["seq"],
            root_hash=sample_hashes["root_hash"],
        )
        mock_storage.update_rekor_anchor.assert_called_once_with(
            anchor_id=1,
            status="anchored",
            rekor_uuid=rekor_uuid,
            rekor_index=log_index,
        )

    @pytest.mark.asyncio
    @respx.mock
    async def test_anchor_shard_header_failure(self, mock_http_client, sample_hashes):
        """Test failed shard header anchoring updates storage with failed status."""
        # Mock 4xx error
        respx.post(f"{DEFAULT_REKOR_URL}/api/v1/log/entries").mock(
            return_value=httpx.Response(400, json={"error": "Bad request"})
        )

        # Mock storage layer
        mock_storage = MagicMock()
        mock_storage.create_rekor_anchor.return_value = 1

        with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "true"}):
            anchor = RekorAnchor(mock_http_client)
            result = await anchor.anchor_shard_header(
                storage=mock_storage,
                shard_id=sample_hashes["shard_id"],
                seq=sample_hashes["seq"],
                header_hash=sample_hashes["header_hash"],
                root_hash=sample_hashes["root_hash"],
            )

        assert result.success is False

        # Verify storage updated with failed status
        mock_storage.update_rekor_anchor.assert_called_once_with(
            anchor_id=1,
            status="failed",
        )


class TestFireAndForgetAnchor:
    """Tests for the fire_and_forget_anchor function."""

    @pytest.mark.asyncio
    async def test_fire_and_forget_disabled(self, sample_hashes):
        """Test that fire_and_forget does nothing when disabled."""
        mock_http_client = MagicMock()
        mock_storage = MagicMock()

        with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "false"}):
            fire_and_forget_anchor(
                http_client=mock_http_client,
                storage=mock_storage,
                shard_id=sample_hashes["shard_id"],
                seq=sample_hashes["seq"],
                header_hash=sample_hashes["header_hash"],
                root_hash=sample_hashes["root_hash"],
            )

        # Should not create any anchor records when disabled
        mock_storage.create_rekor_anchor.assert_not_called()

    @pytest.mark.asyncio
    @respx.mock
    async def test_fire_and_forget_creates_task(self, sample_hashes):
        """Test that fire_and_forget creates an async task when enabled."""
        rekor_uuid = "24296fb24b8ad77a66c63bc03e1e2e6b"

        # Mock successful Rekor response
        respx.post(f"{DEFAULT_REKOR_URL}/api/v1/log/entries").mock(
            return_value=httpx.Response(
                201,
                json={
                    rekor_uuid: {
                        "logIndex": 12345,
                        "body": "base64body",
                    }
                },
            )
        )

        mock_storage = MagicMock()
        mock_storage.create_rekor_anchor.return_value = 1

        async with httpx.AsyncClient() as http_client:
            with patch.dict(os.environ, {"OLYMPUS_REKOR_ENABLED": "true"}):
                fire_and_forget_anchor(
                    http_client=http_client,
                    storage=mock_storage,
                    shard_id=sample_hashes["shard_id"],
                    seq=sample_hashes["seq"],
                    header_hash=sample_hashes["header_hash"],
                    root_hash=sample_hashes["root_hash"],
                )

                # Allow the async task to complete
                await asyncio.sleep(0.1)

        # Verify storage was called
        mock_storage.create_rekor_anchor.assert_called_once()


class TestHashedrekordPayload:
    """Tests for the hashedrekord payload construction."""

    def test_build_hashedrekord_payload(self, mock_http_client, sample_hashes):
        """Test that the hashedrekord payload is correctly constructed."""
        anchor = RekorAnchor(mock_http_client)
        payload = anchor._build_hashedrekord_payload(
            shard_id=sample_hashes["shard_id"],
            seq=sample_hashes["seq"],
            header_hash=sample_hashes["header_hash"],
            root_hash=sample_hashes["root_hash"],
        )

        assert payload["apiVersion"] == "0.0.1"
        assert payload["kind"] == "hashedrekord"
        assert "spec" in payload
        assert "data" in payload["spec"]
        assert "hash" in payload["spec"]["data"]
        assert payload["spec"]["data"]["hash"]["algorithm"] == "sha256"
