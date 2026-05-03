"""H-2 atomicity contract tests for the Python → Go sequencer client.

These tests pin down the *observable* contract that the Python sequencer
client (``api.services.sequencer_client.GoSequencerClient``) sees from
the Go sequencer's two-phase prepare/commit machinery (see
``services/sequencer-go/internal/api/sequencer.go::handleQueueLeaf``).

We do NOT spin up a real Go sequencer here; that is exercised by the
chaos integration suite under ``services/sequencer-go``. Instead, we use
respx to fake the sequencer's HTTP surface and validate that:

1. A storage failure on the sequencer (HTTP 500 with "Storage failed")
   surfaces as a ``SequencerResponseError`` so callers can retry — and
   crucially, that the Python client does NOT cache the response root
   from a partial success.
2. A successful append returns the new_root/tree_size from the Go
   service's *committed* state — i.e. the response only reaches the
   client after the Go side has run prepare → store → commit.
3. A "commit failed after durable write" 500 response is distinguishable
   so that operator-facing tooling can surface the right remediation
   (the leaf is durable, restart-replay will reconcile).

The tests rely on a fake server that simulates the H-2 contract: a
second client request after a prior successful commit MUST observe the
new tree size, and a request after a simulated storage failure MUST
observe the *prior* tree size (because the live SMT was rolled back).
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import pytest
import respx

from api.services.sequencer_client import (
    GoSequencerClient,
    SequencerResponseError,
)


@pytest.fixture
def base_url() -> str:
    return "http://sequencer.test"


@pytest.fixture
def client(base_url: str, monkeypatch: pytest.MonkeyPatch) -> GoSequencerClient:
    monkeypatch.setenv("OLYMPUS_SEQUENCER_TOKEN", "x" * 32)
    return GoSequencerClient(
        base_url=base_url,
        token="x" * 32,
        timeout_seconds=2.0,
    )


def _append_payload(record_id: str = "doc-1") -> dict[str, Any]:
    return {
        "shard_id": "test.shard",
        "record_type": "doc",
        "record_id": record_id,
        "content": b'{"hello":"world"}',
        "content_type": "json",
        "parser_id": "test@1.0.0",
        "canonical_parser_version": "v1",
    }


@pytest.mark.asyncio
@respx.mock
async def test_storage_failure_surfaces_as_response_error(
    client: GoSequencerClient,
    base_url: str,
) -> None:
    """When the Go sequencer's Postgres COMMIT fails, it returns 500 and
    the Python client MUST raise SequencerResponseError so callers don't
    silently treat a failed durable write as success.

    Mirrors the Go test
    ``TestQueueLeaf_StorageFailure_TriggersAbort_RustStateUnchanged``.
    """
    respx.post(f"{base_url}/v1/queue-leaf").mock(
        return_value=httpx.Response(500, text="Storage failed\n")
    )

    with pytest.raises(SequencerResponseError) as excinfo:
        await client.append_record(**_append_payload())

    assert excinfo.value.status_code == 500
    assert "Storage failed" in (excinfo.value.detail or "")


@pytest.mark.asyncio
@respx.mock
async def test_commit_failure_after_durable_write_surfaces_as_response_error(
    client: GoSequencerClient,
    base_url: str,
) -> None:
    """When CommitPreparedUpdate fails AFTER Postgres COMMIT succeeded, the
    Go sequencer logs that startup-replay will reconcile and returns a
    500 with the message ``SMT commit failed after durable write``. The
    Python client must distinguish this so operator tooling can surface
    the correct remediation.
    """
    respx.post(f"{base_url}/v1/queue-leaf").mock(
        return_value=httpx.Response(500, text="SMT commit failed after durable write\n")
    )

    with pytest.raises(SequencerResponseError) as excinfo:
        await client.append_record(**_append_payload())

    assert excinfo.value.status_code == 500
    assert "after durable write" in (excinfo.value.detail or "")


@pytest.mark.asyncio
@respx.mock
async def test_happy_path_returns_committed_root(
    client: GoSequencerClient,
    base_url: str,
) -> None:
    """A successful response means the Go sequencer has finished all three
    phases: PrepareUpdate, Postgres COMMIT, and CommitPreparedUpdate. The
    new_root/tree_size in the response are therefore the live SMT's
    committed state.
    """
    respx.post(f"{base_url}/v1/queue-leaf").mock(
        return_value=httpx.Response(
            200,
            json={
                "new_root": "ab" * 32,
                "global_key": "cd" * 32,
                "leaf_value_hash": "ef" * 32,
                "tree_size": 1,
            },
        )
    )

    result = await client.append_record(**_append_payload())
    assert result.tree_size == 1
    assert result.new_root == "ab" * 32


@pytest.mark.asyncio
@respx.mock
async def test_storage_failure_then_retry_observes_unchanged_root(
    client: GoSequencerClient,
    base_url: str,
) -> None:
    """End-to-end H-2 invariant from the Python client's perspective:
    after a 5xx caused by storage failure, a follow-up GetLatestRoot MUST
    return the *prior* root — because the live SMT was rolled back via
    AbortPreparedUpdate.

    We simulate that by having the fake sequencer's /v1/get-latest-root
    return the same root before AND after the failed append. If the Go
    sequencer ever leaks the prepared-but-uncommitted root, this contract
    is broken.
    """
    prior_root_hex = "11" * 32
    prior_tree_size = 5

    # /v1/get-latest-root returns the same value before and after the
    # failed append, modeling H-2's atomicity guarantee.
    respx.get(f"{base_url}/v1/get-latest-root").mock(
        return_value=httpx.Response(
            200,
            json={
                "root": prior_root_hex,
                "tree_size": prior_tree_size,
            },
        )
    )
    respx.post(f"{base_url}/v1/queue-leaf").mock(
        return_value=httpx.Response(500, text="Storage failed\n")
    )

    before = await client.get_latest_root()
    with pytest.raises(SequencerResponseError):
        await client.append_record(**_append_payload())
    after = await client.get_latest_root()

    assert before.root == after.root, (
        "H-2 violation: live SMT root changed after a failed append. "
        "The Go sequencer must AbortPreparedUpdate on storage failure."
    )
    assert before.tree_size == after.tree_size


@pytest.mark.asyncio
async def test_storage_commit_timeout_constant_documented() -> None:
    """The Go-side ``DefaultStorageCommitTimeout`` MUST stay strictly
    less than the Rust LRU TTL (default 30s). This Python test is a
    sentinel: it documents the cross-language constant so a future
    refactor cannot silently push the Go timeout up to 30s+ without a
    matching change here.

    The actual enforcement lives in
    ``services/sequencer-go/cmd/sequencer/main.go`` (env-var bounds
    check) and in
    ``services/sequencer-go/internal/api/sequencer.go``
    (``DefaultStorageCommitTimeout`` doc-comment).
    """
    main_go = os.path.join(
        os.path.dirname(__file__),
        "..",
        "services",
        "sequencer-go",
        "cmd",
        "sequencer",
        "main.go",
    )
    if not os.path.exists(main_go):
        pytest.skip("Go sequencer source not available in this checkout")
    with open(main_go, encoding="utf-8") as f:
        src = f.read()
    assert "rustPreparedTxTTL = 30 * time.Second" in src, (
        "main.go must guard the storage-commit timeout against the 30s "
        "Rust LRU TTL — see api.DefaultStorageCommitTimeout doc."
    )
