"""Unit tests for ``append_via_backend`` and ``GoSequencerClient.get_signed_root_pair``.

These tests exercise the unified write-backend adapter introduced when the
Python API was rewired to honour ``OLYMPUS_USE_GO_SEQUENCER``. They cover:

* The flag-off path: ``StorageLayer.append_record`` is invoked (in a thread)
  and the returned tuple is normalised into ``AppendRecordResult``.
* The flag-on path: ``GoSequencerClient.append_record`` and
  ``get_inclusion_proof`` are awaited and the response is normalised.
* Error mapping: ``SequencerUnavailableError`` → ``HTTPException(503)`` and
  ``SequencerResponseError`` → ``HTTPException(502)``.
* The new ``GoSequencerClient.get_signed_root_pair`` happy path, unreachable
  transport error, and non-2xx response error, driven through an
  ``httpx.MockTransport`` so the tests do not require a running sequencer.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import HTTPException

import api.services.storage_layer as storage_layer_mod
from api.services.sequencer_client import (
    GoSequencerClient,
    SequencerAppendResult,
    SequencerInclusionProof,
    SequencerResponseError,
    SequencerSignedRootPair,
    SequencerUnavailableError,
)


# Re-bind through the module to avoid the CodeQL "imported with both 'import'
# and 'import from'" warning while still keeping the short call sites.
AppendRecordResult = storage_layer_mod.AppendRecordResult
append_via_backend = storage_layer_mod.append_via_backend


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


HEX32_A = "11" * 32
HEX32_B = "22" * 32
HEX32_C = "33" * 32
HEX32_D = "44" * 32

VALUE_HASH = bytes.fromhex(HEX32_A)


@pytest.fixture(autouse=True)
def _reset_storage_layer_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure each test sees a clean storage_layer module state."""
    monkeypatch.setattr(storage_layer_mod, "_storage", None, raising=False)
    monkeypatch.setattr(storage_layer_mod, "_db_error", None, raising=False)
    monkeypatch.delenv("OLYMPUS_USE_GO_SEQUENCER", raising=False)


def _make_existence_proof() -> Any:
    """Build a minimal ExistenceProof-shaped object for the storage path."""
    proof = MagicMock()
    proof.key = bytes.fromhex(HEX32_B)
    proof.root_hash = bytes.fromhex(HEX32_C)
    proof.siblings = [bytes.fromhex(HEX32_D) for _ in range(256)]
    proof.parser_id = "fallback@1.0.0"
    proof.canonical_parser_version = "v1"
    return proof


def _make_ledger_entry(
    *, entry_hash: str = "ledger-entry-hash", ts: str = "2026-04-25T19:00:00Z"
) -> Any:
    entry = MagicMock()
    entry.entry_hash = entry_hash
    entry.ts = ts
    entry.poseidon_root = "12345678901234567890"
    return entry


# ---------------------------------------------------------------------------
# Flag-off path: StorageLayer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_append_via_backend_uses_storage_when_flag_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the flag off, the adapter calls StorageLayer.append_record."""
    proof = _make_existence_proof()
    ledger_entry = _make_ledger_entry()
    fake_storage = MagicMock()
    fake_storage.append_record.return_value = (
        bytes.fromhex(HEX32_C),  # root_hash
        proof,
        {"shard": "header"},  # header
        "signature-hex",
        ledger_entry,
    )

    # Bypass _get_storage() entirely by replacing the write backend selector.
    monkeypatch.setattr(storage_layer_mod, "_get_write_backend", lambda: fake_storage)

    signing_key = MagicMock()
    result = await append_via_backend(
        shard_id="watauga:2025:budget",
        record_type="artifact",
        record_id="art-001",
        version=1,
        value_hash=VALUE_HASH,
        signing_key=signing_key,
        canonicalization={"version": "v2"},
    )

    assert isinstance(result, AppendRecordResult)
    assert result.backend == "storage"
    assert result.persisted is True
    assert result.root_hash == bytes.fromhex(HEX32_C)
    assert result.ledger_entry_hash == "ledger-entry-hash"
    assert result.ts == "2026-04-25T19:00:00Z"
    assert result.poseidon_root == "12345678901234567890"
    assert result.storage_proof is proof
    assert result.sequencer_proof is None

    fake_storage.append_record.assert_called_once()
    call_kwargs = fake_storage.append_record.call_args.kwargs
    assert call_kwargs["shard_id"] == "watauga:2025:budget"
    assert call_kwargs["record_id"] == "art-001"
    assert call_kwargs["value_hash"] == VALUE_HASH
    assert call_kwargs["signing_key"] is signing_key


@pytest.mark.asyncio
async def test_append_via_backend_storage_path_requires_signing_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Storage-layer writes must surface a 500 if no signing key is supplied."""
    fake_storage = MagicMock()
    monkeypatch.setattr(storage_layer_mod, "_get_write_backend", lambda: fake_storage)

    with pytest.raises(HTTPException) as excinfo:
        await append_via_backend(
            shard_id="s",
            record_type="t",
            record_id="r",
            version=1,
            value_hash=VALUE_HASH,
            signing_key=None,
        )
    assert excinfo.value.status_code == 500
    fake_storage.append_record.assert_not_called()


# ---------------------------------------------------------------------------
# Flag-on path: GoSequencerClient
# ---------------------------------------------------------------------------


class _StubSequencerClient:
    """In-process stub of GoSequencerClient that records calls."""

    def __init__(
        self,
        *,
        append_result: SequencerAppendResult | None = None,
        proof_result: SequencerInclusionProof | None = None,
        append_exc: BaseException | None = None,
        proof_exc: BaseException | None = None,
    ) -> None:
        self._append_result = append_result
        self._proof_result = proof_result
        self._append_exc = append_exc
        self._proof_exc = proof_exc
        self.append_calls: list[dict[str, Any]] = []
        self.append_hash_calls: list[dict[str, Any]] = []
        self.proof_calls: list[dict[str, Any]] = []

    async def append_record(self, **kwargs: Any) -> SequencerAppendResult:
        self.append_calls.append(kwargs)
        if self._append_exc is not None:
            raise self._append_exc
        assert self._append_result is not None
        return self._append_result

    async def append_record_hash(self, **kwargs: Any) -> SequencerAppendResult:
        self.append_hash_calls.append(kwargs)
        if self._append_exc is not None:
            raise self._append_exc
        assert self._append_result is not None
        return self._append_result

    async def get_inclusion_proof(self, **kwargs: Any) -> SequencerInclusionProof:
        self.proof_calls.append(kwargs)
        if self._proof_exc is not None:
            raise self._proof_exc
        assert self._proof_result is not None
        return self._proof_result


def _patch_isinstance_for_stub(monkeypatch: pytest.MonkeyPatch, stub: _StubSequencerClient) -> None:
    """Make append_via_backend treat the stub as a GoSequencerClient instance."""
    monkeypatch.setattr(storage_layer_mod, "_get_write_backend", lambda: stub)
    real_isinstance = isinstance

    def fake_isinstance(obj: Any, cls: Any) -> bool:
        if cls is GoSequencerClient and obj is stub:
            return True
        return real_isinstance(obj, cls)

    monkeypatch.setattr("api.services.storage_layer.isinstance", fake_isinstance, raising=False)


@pytest.mark.asyncio
async def test_append_via_backend_uses_sequencer_when_flag_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the flag on, the adapter awaits the sequencer client and proof."""
    append = SequencerAppendResult(
        new_root=HEX32_C,
        global_key=HEX32_B,
        leaf_value_hash=HEX32_A,
        tree_size=42,
    )
    proof = SequencerInclusionProof(
        global_key=HEX32_B,
        value_hash=HEX32_A,
        siblings=[HEX32_D] * 256,
        root=HEX32_C,
    )
    stub = _StubSequencerClient(append_result=append, proof_result=proof)
    _patch_isinstance_for_stub(monkeypatch, stub)

    result = await append_via_backend(
        shard_id="watauga:2025:budget",
        record_type="artifact",
        record_id="art-001",
        version=1,
        value_hash=VALUE_HASH,
        signing_key=None,  # not required for sequencer path
    )

    assert isinstance(result, AppendRecordResult)
    assert result.backend == "sequencer"
    assert result.persisted is False
    assert result.root_hash == bytes.fromhex(HEX32_C)
    # leaf_value_hash is used as the per-leaf commitment identifier
    assert result.ledger_entry_hash == HEX32_A
    assert result.poseidon_root is None
    assert result.storage_proof is None
    assert result.sequencer_proof is proof

    # append_via_backend uses append_record_hash (pre-hashed path) for all
    # sequencer writes since it already holds a canonical content hash.
    assert len(stub.append_hash_calls) == 1
    assert stub.append_calls == []
    assert stub.append_hash_calls[0]["shard_id"] == "watauga:2025:budget"
    assert stub.append_hash_calls[0]["value_hash"] == VALUE_HASH
    assert stub.append_hash_calls[0]["version"] == "1"

    assert len(stub.proof_calls) == 1
    assert stub.proof_calls[0]["root"] == bytes.fromhex(HEX32_C)


@pytest.mark.asyncio
async def test_append_via_backend_skips_proof_when_not_requested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    append = SequencerAppendResult(
        new_root=HEX32_C,
        global_key=HEX32_B,
        leaf_value_hash=HEX32_A,
        tree_size=1,
    )
    stub = _StubSequencerClient(append_result=append)
    _patch_isinstance_for_stub(monkeypatch, stub)

    result = await append_via_backend(
        shard_id="s",
        record_type="t",
        record_id="r",
        version=1,
        value_hash=VALUE_HASH,
        want_proof=False,
    )

    assert result.sequencer_proof is None
    assert stub.proof_calls == []


@pytest.mark.asyncio
async def test_append_via_backend_maps_unavailable_to_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = _StubSequencerClient(
        append_exc=SequencerUnavailableError("boom"),
    )
    _patch_isinstance_for_stub(monkeypatch, stub)

    with pytest.raises(HTTPException) as excinfo:
        await append_via_backend(
            shard_id="s",
            record_type="t",
            record_id="r",
            version=1,
            value_hash=VALUE_HASH,
        )
    assert excinfo.value.status_code == 503


@pytest.mark.asyncio
async def test_append_via_backend_maps_response_error_to_502(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = _StubSequencerClient(
        append_exc=SequencerResponseError("nope", status_code=500, detail="x"),
    )
    _patch_isinstance_for_stub(monkeypatch, stub)

    with pytest.raises(HTTPException) as excinfo:
        await append_via_backend(
            shard_id="s",
            record_type="t",
            record_id="r",
            version=1,
            value_hash=VALUE_HASH,
        )
    assert excinfo.value.status_code == 502


@pytest.mark.asyncio
async def test_append_via_backend_proof_unavailable_maps_to_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    append = SequencerAppendResult(
        new_root=HEX32_C,
        global_key=HEX32_B,
        leaf_value_hash=HEX32_A,
        tree_size=1,
    )
    stub = _StubSequencerClient(
        append_result=append,
        proof_exc=SequencerUnavailableError("net down"),
    )
    _patch_isinstance_for_stub(monkeypatch, stub)

    with pytest.raises(HTTPException) as excinfo:
        await append_via_backend(
            shard_id="s",
            record_type="t",
            record_id="r",
            version=1,
            value_hash=VALUE_HASH,
        )
    assert excinfo.value.status_code == 503


# ---------------------------------------------------------------------------
# GoSequencerClient.get_signed_root_pair
# ---------------------------------------------------------------------------


def _make_client_with_transport(transport: httpx.MockTransport) -> GoSequencerClient:
    client = GoSequencerClient(base_url="http://sequencer.test", token="test-token")
    # Inject the mock-transport-backed httpx client directly.
    client._client = httpx.AsyncClient(transport=transport)
    return client


@pytest.mark.asyncio
async def test_get_signed_root_pair_happy_path() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        return httpx.Response(
            200,
            json={
                "old_tree_size": 100,
                "new_tree_size": 200,
                "old_root": HEX32_A,
                "old_signature": "aa" * 32,
                "new_root": HEX32_C,
                "new_signature": "bb" * 32,
            },
        )

    client = _make_client_with_transport(httpx.MockTransport(handler))
    try:
        result = await client.get_signed_root_pair(100, 200)
    finally:
        await client.close()

    assert isinstance(result, SequencerSignedRootPair)
    assert result.old_tree_size == 100
    assert result.new_tree_size == 200
    assert result.old_root == HEX32_A
    assert result.new_root == HEX32_C
    assert result.old_signature == "aa" * 32
    assert result.new_signature == "bb" * 32

    assert "/v1/get-signed-root-pair" in captured["url"]
    assert "old_tree_size=100" in captured["url"]
    assert "new_tree_size=200" in captured["url"]
    assert captured["headers"].get("x-sequencer-token") == "test-token"


@pytest.mark.asyncio
async def test_get_signed_root_pair_rejects_inverted_sizes() -> None:
    client = GoSequencerClient(base_url="http://sequencer.test", token="t")
    try:
        with pytest.raises(ValueError):
            await client.get_signed_root_pair(200, 100)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_get_signed_root_pair_rejects_negative_sizes() -> None:
    client = GoSequencerClient(base_url="http://sequencer.test", token="t")
    try:
        with pytest.raises(ValueError):
            await client.get_signed_root_pair(-1, 5)
        with pytest.raises(ValueError):
            await client.get_signed_root_pair(0, -1)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_get_signed_root_pair_unreachable_raises_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = _make_client_with_transport(httpx.MockTransport(handler))
    try:
        with pytest.raises(SequencerUnavailableError):
            await client.get_signed_root_pair(0, 1)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_get_signed_root_pair_non_2xx_raises_response_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            content=json.dumps({"error": "root_not_found"}).encode(),
            headers={"content-type": "application/json"},
        )

    client = _make_client_with_transport(httpx.MockTransport(handler))
    try:
        with pytest.raises(SequencerResponseError) as excinfo:
            await client.get_signed_root_pair(99, 100)
        assert excinfo.value.status_code == 404
        assert excinfo.value.detail is not None
        assert "root_not_found" in excinfo.value.detail
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# httpx.MockTransport-backed integration smoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_append_via_backend_integration_with_mock_sequencer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: a real GoSequencerClient with MockTransport flows through
    the adapter and yields a normalised AppendRecordResult.
    """
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        seen.append(path)
        if path == "/v1/queue-leaf-hash":
            return httpx.Response(
                200,
                json={
                    "new_root": HEX32_C,
                    "global_key": HEX32_B,
                    "leaf_value_hash": HEX32_A,
                    "tree_size": 7,
                },
            )
        if path == "/v1/get-inclusion-proof":
            return httpx.Response(
                200,
                json={
                    "global_key": HEX32_B,
                    "value_hash": HEX32_A,
                    "siblings": [HEX32_D] * 256,
                    "root": HEX32_C,
                },
            )
        return httpx.Response(404)

    client = _make_client_with_transport(httpx.MockTransport(handler))
    monkeypatch.setattr(storage_layer_mod, "_get_write_backend", lambda: client)

    try:
        result = await append_via_backend(
            shard_id="watauga:2025:budget",
            record_type="artifact",
            record_id="art-007",
            version=1,
            value_hash=VALUE_HASH,
        )
    finally:
        await client.close()

    assert result.backend == "sequencer"
    assert result.root_hash == bytes.fromhex(HEX32_C)
    assert result.sequencer_proof is not None
    assert len(result.sequencer_proof.siblings) == 256
    assert seen == ["/v1/queue-leaf-hash", "/v1/get-inclusion-proof"]
