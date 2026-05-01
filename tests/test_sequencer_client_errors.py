"""Tests for api.services.sequencer_client error paths and helper functions.

Uses httpx's mock transport (via respx) to exercise all error branches without
needing a live Go sequencer.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import httpx
import pytest
import respx


# ---------------------------------------------------------------------------
# Exception types
# ---------------------------------------------------------------------------


class TestExceptionTypes:
    def test_sequencer_unavailable_error_attrs(self) -> None:
        from api.services.sequencer_client import SequencerUnavailableError

        cause = ConnectionRefusedError("refused")
        exc = SequencerUnavailableError("down", cause=cause)
        assert "down" in str(exc)
        assert exc.cause is cause

    def test_sequencer_unavailable_error_no_cause(self) -> None:
        from api.services.sequencer_client import SequencerUnavailableError

        exc = SequencerUnavailableError("down")
        assert exc.cause is None

    def test_sequencer_response_error_attrs(self) -> None:
        from api.services.sequencer_client import SequencerResponseError

        exc = SequencerResponseError("bad", status_code=503, detail="service down")
        assert exc.status_code == 503
        assert exc.detail == "service down"
        assert "bad" in str(exc)

    def test_sequencer_response_error_no_detail(self) -> None:
        from api.services.sequencer_client import SequencerResponseError

        exc = SequencerResponseError("bad", status_code=400)
        assert exc.status_code == 400
        assert exc.detail is None


# ---------------------------------------------------------------------------
# use_go_sequencer flag
# ---------------------------------------------------------------------------


class TestUseGoSequencer:
    def test_disabled_by_default(self) -> None:
        from api.services.sequencer_client import use_go_sequencer

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("OLYMPUS_USE_GO_SEQUENCER", None)
            assert use_go_sequencer() is False

    @pytest.mark.parametrize("val", ["1", "true", "yes", "on", "TRUE", "YES"])
    def test_enabled_for_truthy_values(self, val: str) -> None:
        from api.services.sequencer_client import use_go_sequencer

        with patch.dict(os.environ, {"OLYMPUS_USE_GO_SEQUENCER": val}):
            assert use_go_sequencer() is True

    @pytest.mark.parametrize("val", ["false", "0", "no", "off", ""])
    def test_disabled_for_falsy_values(self, val: str) -> None:
        from api.services.sequencer_client import use_go_sequencer

        with patch.dict(os.environ, {"OLYMPUS_USE_GO_SEQUENCER": val}):
            assert use_go_sequencer() is False


# ---------------------------------------------------------------------------
# GoSequencerClient init
# ---------------------------------------------------------------------------


class TestGoSequencerClientInit:
    def test_default_url(self) -> None:
        from api.services.sequencer_client import GoSequencerClient

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("OLYMPUS_SEQUENCER_URL", None)
            os.environ.pop("OLYMPUS_SEQUENCER_TOKEN", None)
            os.environ.pop("OLYMPUS_SEQUENCER_TIMEOUT_SECONDS", None)
            client = GoSequencerClient()
            assert client._base_url == "http://localhost:8081"

    def test_custom_url_from_env(self) -> None:
        from api.services.sequencer_client import GoSequencerClient

        with patch.dict(
            os.environ,
            {"OLYMPUS_SEQUENCER_URL": "http://custom:9090/", "OLYMPUS_SEQUENCER_TOKEN": "t"},
        ):
            client = GoSequencerClient()
            # Trailing slash must be stripped
            assert client._base_url == "http://custom:9090"

    def test_timeout_from_env(self) -> None:
        from api.services.sequencer_client import GoSequencerClient

        with patch.dict(os.environ, {"OLYMPUS_SEQUENCER_TIMEOUT_SECONDS": "15"}):
            client = GoSequencerClient(base_url="http://localhost:8081", token="t")
            assert client._timeout == 15.0

    def test_invalid_timeout_env_uses_default(self) -> None:
        from api.services.sequencer_client import GoSequencerClient

        with patch.dict(
            os.environ,
            {"OLYMPUS_SEQUENCER_TIMEOUT_SECONDS": "not-a-number", "OLYMPUS_SEQUENCER_TOKEN": "t"},
        ):
            client = GoSequencerClient()
            assert client._timeout == 30.0

    def test_missing_token_logs_error(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        from api.services.sequencer_client import GoSequencerClient

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("OLYMPUS_SEQUENCER_TOKEN", None)
            with caplog.at_level(logging.ERROR, logger="api.services.sequencer_client"):
                GoSequencerClient()
        assert any("OLYMPUS_SEQUENCER_TOKEN" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# close / lazy client
# ---------------------------------------------------------------------------


class TestClientLifecycle:
    @pytest.mark.asyncio
    async def test_close_without_open_is_noop(self) -> None:
        from api.services.sequencer_client import GoSequencerClient

        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        # Should not raise
        await client.close()
        assert client._client is None

    @pytest.mark.asyncio
    async def test_close_clears_client(self) -> None:
        from api.services.sequencer_client import GoSequencerClient

        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        _ = client._get_client()  # initialise
        assert client._client is not None
        await client.close()
        assert client._client is None


# ---------------------------------------------------------------------------
# append_record — error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAppendRecordErrors:
    @respx.mock
    async def test_raises_unavailable_on_request_error(self) -> None:
        from api.services.sequencer_client import GoSequencerClient, SequencerUnavailableError

        respx.post("http://localhost:8081/v1/queue-leaf").mock(
            side_effect=httpx.ConnectError("refused")
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        with pytest.raises(SequencerUnavailableError):
            await client.append_record(
                shard_id="s", record_type="doc", record_id="id1", content=b"data"
            )
        await client.close()

    @respx.mock
    async def test_raises_response_error_on_non_200(self) -> None:
        from api.services.sequencer_client import GoSequencerClient, SequencerResponseError

        respx.post("http://localhost:8081/v1/queue-leaf").mock(
            return_value=httpx.Response(503, text="service unavailable")
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        with pytest.raises(SequencerResponseError) as exc_info:
            await client.append_record(
                shard_id="s", record_type="doc", record_id="id1", content=b"data"
            )
        assert exc_info.value.status_code == 503
        assert exc_info.value.detail is not None
        await client.close()

    @respx.mock
    async def test_response_error_detail_truncated(self) -> None:
        from api.services.sequencer_client import GoSequencerClient, SequencerResponseError

        long_body = "x" * 600
        respx.post("http://localhost:8081/v1/queue-leaf").mock(
            return_value=httpx.Response(400, text=long_body)
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        with pytest.raises(SequencerResponseError) as exc_info:
            await client.append_record(
                shard_id="s", record_type="doc", record_id="id1", content=b"data"
            )
        assert exc_info.value.detail is not None
        assert len(exc_info.value.detail) <= 500
        await client.close()

    @respx.mock
    async def test_success_returns_result(self) -> None:
        from api.services.sequencer_client import GoSequencerClient, SequencerAppendResult

        respx.post("http://localhost:8081/v1/queue-leaf").mock(
            return_value=httpx.Response(
                200,
                json={
                    "new_root": "aa" * 32,
                    "global_key": "bb" * 32,
                    "leaf_value_hash": "cc" * 32,
                    "tree_size": 5,
                },
            )
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        result = await client.append_record(
            shard_id="shard", record_type="doc", record_id="id1", content=b"hello"
        )
        assert isinstance(result, SequencerAppendResult)
        assert result.tree_size == 5
        assert result.new_root == "aa" * 32
        await client.close()


# ---------------------------------------------------------------------------
# append_records_batch — error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAppendRecordsBatchErrors:
    @respx.mock
    async def test_raises_unavailable_on_request_error(self) -> None:
        from api.services.sequencer_client import GoSequencerClient, SequencerUnavailableError

        respx.post("http://localhost:8081/v1/queue-leaves").mock(
            side_effect=httpx.TimeoutException("timeout")
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        with pytest.raises(SequencerUnavailableError):
            await client.append_records_batch(
                [{"shard_id": "s", "record_type": "doc", "record_id": "r1", "content": b"x"}]
            )
        await client.close()

    @respx.mock
    async def test_raises_response_error_on_non_200(self) -> None:
        from api.services.sequencer_client import GoSequencerClient, SequencerResponseError

        respx.post("http://localhost:8081/v1/queue-leaves").mock(
            return_value=httpx.Response(500, text="internal error")
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        with pytest.raises(SequencerResponseError) as exc_info:
            await client.append_records_batch(
                [{"shard_id": "s", "record_type": "doc", "record_id": "r1", "content": b"x"}]
            )
        assert exc_info.value.status_code == 500
        await client.close()


# ---------------------------------------------------------------------------
# get_inclusion_proof — error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetInclusionProofErrors:
    @respx.mock
    async def test_raises_unavailable_on_request_error(self) -> None:
        from api.services.sequencer_client import GoSequencerClient, SequencerUnavailableError

        respx.get("http://localhost:8081/v1/get-inclusion-proof").mock(
            side_effect=httpx.ConnectError("refused")
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        with pytest.raises(SequencerUnavailableError):
            await client.get_inclusion_proof(shard_id="s", record_type="doc", record_id="id1")
        await client.close()

    @respx.mock
    async def test_raises_response_error_on_404(self) -> None:
        from api.services.sequencer_client import GoSequencerClient, SequencerResponseError

        respx.get("http://localhost:8081/v1/get-inclusion-proof").mock(
            return_value=httpx.Response(404, text="not found")
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        with pytest.raises(SequencerResponseError) as exc_info:
            await client.get_inclusion_proof(shard_id="s", record_type="doc", record_id="id1")
        assert exc_info.value.status_code == 404
        await client.close()


# ---------------------------------------------------------------------------
# get_latest_root — error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetLatestRootErrors:
    @respx.mock
    async def test_raises_unavailable_on_request_error(self) -> None:
        from api.services.sequencer_client import GoSequencerClient, SequencerUnavailableError

        respx.get("http://localhost:8081/v1/get-latest-root").mock(
            side_effect=httpx.ConnectError("refused")
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        with pytest.raises(SequencerUnavailableError):
            await client.get_latest_root()
        await client.close()

    @respx.mock
    async def test_raises_response_error_on_500(self) -> None:
        from api.services.sequencer_client import GoSequencerClient, SequencerResponseError

        respx.get("http://localhost:8081/v1/get-latest-root").mock(
            return_value=httpx.Response(500, text="error")
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        with pytest.raises(SequencerResponseError):
            await client.get_latest_root()
        await client.close()

    @respx.mock
    async def test_success_with_shard_id_param(self) -> None:
        from api.services.sequencer_client import GoSequencerClient

        route = respx.get("http://localhost:8081/v1/get-latest-root").mock(
            return_value=httpx.Response(200, json={"root": "aa" * 32, "tree_size": 10})
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        result = await client.get_latest_root(shard_id="my-shard")
        assert result.tree_size == 10
        # shard_id value must appear in the query string
        assert "shard_id=my-shard" in str(route.calls.last.request.url)
        await client.close()


# ---------------------------------------------------------------------------
# health_check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestHealthCheck:
    @respx.mock
    async def test_returns_true_when_healthy(self) -> None:
        from api.services.sequencer_client import GoSequencerClient

        respx.get("http://localhost:8081/v1/get-latest-root").mock(
            return_value=httpx.Response(200, json={"root": "aa" * 32, "tree_size": 0})
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        assert await client.health_check() is True
        await client.close()

    @respx.mock
    async def test_returns_false_when_unavailable(self) -> None:
        from api.services.sequencer_client import GoSequencerClient

        respx.get("http://localhost:8081/v1/get-latest-root").mock(
            side_effect=httpx.ConnectError("refused")
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        assert await client.health_check() is False
        await client.close()

    @respx.mock
    async def test_returns_false_on_error_response(self) -> None:
        from api.services.sequencer_client import GoSequencerClient

        respx.get("http://localhost:8081/v1/get-latest-root").mock(
            return_value=httpx.Response(503, text="down")
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        assert await client.health_check() is False
        await client.close()


# ---------------------------------------------------------------------------
# get_signed_root_pair — validation and error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetSignedRootPair:
    async def test_raises_value_error_when_new_lt_old(self) -> None:
        from api.services.sequencer_client import GoSequencerClient

        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        with pytest.raises(ValueError, match="new_tree_size"):
            await client.get_signed_root_pair(old_tree_size=10, new_tree_size=5)
        await client.close()

    async def test_raises_value_error_on_negative_size(self) -> None:
        from api.services.sequencer_client import GoSequencerClient

        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        with pytest.raises(ValueError, match="non-negative"):
            await client.get_signed_root_pair(old_tree_size=-1, new_tree_size=5)
        await client.close()

    @respx.mock
    async def test_raises_unavailable_on_request_error(self) -> None:
        from api.services.sequencer_client import GoSequencerClient, SequencerUnavailableError

        respx.get("http://localhost:8081/v1/get-signed-root-pair").mock(
            side_effect=httpx.ConnectError("refused")
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        with pytest.raises(SequencerUnavailableError):
            await client.get_signed_root_pair(old_tree_size=0, new_tree_size=5)
        await client.close()

    @respx.mock
    async def test_raises_response_error_on_non_200(self) -> None:
        from api.services.sequencer_client import GoSequencerClient, SequencerResponseError

        respx.get("http://localhost:8081/v1/get-signed-root-pair").mock(
            return_value=httpx.Response(410, text="Gone")
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        with pytest.raises(SequencerResponseError) as exc_info:
            await client.get_signed_root_pair(old_tree_size=0, new_tree_size=5)
        assert exc_info.value.status_code == 410
        await client.close()

    @respx.mock
    async def test_success_returns_pair(self) -> None:
        from api.services.sequencer_client import GoSequencerClient, SequencerSignedRootPair

        respx.get("http://localhost:8081/v1/get-signed-root-pair").mock(
            return_value=httpx.Response(
                200,
                json={
                    "old_tree_size": 3,
                    "new_tree_size": 7,
                    "old_root": "aa" * 32,
                    "old_signature": "bb" * 64,
                    "new_root": "cc" * 32,
                    "new_signature": "dd" * 64,
                },
            )
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        pair = await client.get_signed_root_pair(old_tree_size=3, new_tree_size=7)
        assert isinstance(pair, SequencerSignedRootPair)
        assert pair.old_tree_size == 3
        assert pair.new_tree_size == 7
        await client.close()

    @respx.mock
    async def test_equal_tree_sizes_allowed(self) -> None:
        """old_tree_size == new_tree_size is valid (snapshot at same point)."""
        from api.services.sequencer_client import GoSequencerClient

        respx.get("http://localhost:8081/v1/get-signed-root-pair").mock(
            return_value=httpx.Response(
                200,
                json={
                    "old_tree_size": 5,
                    "new_tree_size": 5,
                    "old_root": "aa" * 32,
                    "old_signature": "bb" * 64,
                    "new_root": "aa" * 32,
                    "new_signature": "cc" * 64,
                },
            )
        )
        client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        pair = await client.get_signed_root_pair(old_tree_size=5, new_tree_size=5)
        assert pair.old_tree_size == pair.new_tree_size == 5
        await client.close()


# ---------------------------------------------------------------------------
# get_sequencer_health_status module-level helper
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetSequencerHealthStatus:
    async def test_returns_disabled_when_sequencer_off(self) -> None:
        from api.services.sequencer_client import get_sequencer_health_status

        with patch.dict(os.environ, {"OLYMPUS_USE_GO_SEQUENCER": "false"}):
            status, healthy = await get_sequencer_health_status()
        assert status == "disabled"
        assert healthy is True

    @respx.mock
    async def test_returns_ok_when_healthy(self) -> None:
        from api.services import sequencer_client as sc_mod

        respx.get("http://localhost:8081/v1/get-latest-root").mock(
            return_value=httpx.Response(200, json={"root": "aa" * 32, "tree_size": 0})
        )
        with patch.dict(
            os.environ, {"OLYMPUS_USE_GO_SEQUENCER": "true", "OLYMPUS_SEQUENCER_TOKEN": "t"}
        ):
            # Reset module singleton so it picks up env changes
            sc_mod._sequencer_client = None
            status, healthy = await sc_mod.get_sequencer_health_status()
            await sc_mod.close_sequencer_client()
        assert status == "ok"
        assert healthy is True

    @respx.mock
    async def test_returns_unavailable_on_connect_error(self) -> None:
        from api.services import sequencer_client as sc_mod

        respx.get("http://localhost:8081/v1/get-latest-root").mock(
            side_effect=httpx.ConnectError("refused")
        )
        with patch.dict(
            os.environ, {"OLYMPUS_USE_GO_SEQUENCER": "true", "OLYMPUS_SEQUENCER_TOKEN": "t"}
        ):
            sc_mod._sequencer_client = None
            status, healthy = await sc_mod.get_sequencer_health_status()
            await sc_mod.close_sequencer_client()
        assert status == "unavailable"
        assert healthy is False

    @respx.mock
    async def test_returns_degraded_on_response_error(self) -> None:
        from api.services import sequencer_client as sc_mod

        respx.get("http://localhost:8081/v1/get-latest-root").mock(
            return_value=httpx.Response(503, text="down")
        )
        with patch.dict(
            os.environ, {"OLYMPUS_USE_GO_SEQUENCER": "true", "OLYMPUS_SEQUENCER_TOKEN": "t"}
        ):
            sc_mod._sequencer_client = None
            status, healthy = await sc_mod.get_sequencer_health_status()
            await sc_mod.close_sequencer_client()
        assert status == "degraded"
        assert healthy is False


# ---------------------------------------------------------------------------
# close_sequencer_client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCloseSequencerClient:
    async def test_close_when_none_is_noop(self) -> None:
        from api.services import sequencer_client as sc_mod

        sc_mod._sequencer_client = None
        await sc_mod.close_sequencer_client()  # must not raise
        assert sc_mod._sequencer_client is None

    async def test_close_clears_singleton(self) -> None:
        from api.services import sequencer_client as sc_mod
        from api.services.sequencer_client import GoSequencerClient

        sc_mod._sequencer_client = GoSequencerClient(base_url="http://localhost:8081", token="t")
        await sc_mod.close_sequencer_client()
        assert sc_mod._sequencer_client is None
