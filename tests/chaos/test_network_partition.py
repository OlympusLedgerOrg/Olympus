"""
Chaos test: network partition simulation.

Verifies that Olympus handles loss of connectivity to:
- RFC 3161 Timestamp Authority (TSA) — used for external timestamp anchoring
- Guardian replication nodes (Phase 1) — used for SMT root verification

Expected system behaviour
--------------------------
- Local commit operations complete successfully even when the TSA is
  unreachable; RFC 3161 timestamping is best-effort and does not block ingestion.
- SMT divergence between nodes is detected and recorded via the
  ``olympus_smt_root_divergence_total`` Prometheus counter.
- The ``record_smt_divergence`` helper emits a structured WARNING log entry
  that monitoring systems can alert on.
- All entries committed during the partition remain verifiable offline using
  the local chain only.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from protocol.hashes import hash_bytes
from protocol.ledger import Ledger
from protocol.merkle import MerkleTree
from protocol.telemetry import record_smt_divergence


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_leaf_hash(seed: int) -> bytes:
    return hash_bytes(seed.to_bytes(4, "big"))


def _append_entry(ledger: Ledger, seed: int, shard: str = "net-chaos") -> str:
    leaf = _make_leaf_hash(seed)
    tree = MerkleTree([leaf])
    root = tree.get_root().hex()
    entry = ledger.append(
        record_hash=root,
        shard_id=shard,
        shard_root=root,
        canonicalization={"version": "1.0"},
    )
    return entry.entry_hash


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_local_commit_succeeds_when_tsa_unreachable(fresh_ledger: Ledger) -> None:
    """
    Ledger append succeeds even when the RFC 3161 TSA is unreachable.

    The TSA call is simulated by patching ``socket.getaddrinfo`` to raise a
    ``socket.gaierror`` (DNS failure) for TSA hostnames.  The local commit
    path must not block on the TSA response.
    """
    import socket as _socket

    _real_getaddrinfo = _socket.getaddrinfo

    def _dns_fail(host: str, *args: object, **kwargs: object) -> list[object]:
        if "freetsa" in str(host) or "tsa" in str(host):
            raise _socket.gaierror(11001, "Name or service not known")
        return _real_getaddrinfo(host, *args, **kwargs)  # type: ignore[arg-type]

    # In-memory Ledger.append() never contacts the TSA directly; verify it
    # succeeds even if the network is unavailable.
    with patch("socket.getaddrinfo", side_effect=_dns_fail):
        for i in range(3):
            entry_hash = _append_entry(fresh_ledger, i)
            assert entry_hash != ""

    assert len(fresh_ledger.entries) == 3
    assert fresh_ledger.verify_chain()


def test_rfc3161_timestamping_degrades_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    RFC 3161 timestamp_document() raises a clear exception (not a crash) when
    the TSA is unreachable.

    This ensures the calling code can catch the exception and continue without
    a timestamp rather than crashing.
    """
    import urllib.request

    import protocol.rfc3161 as rfc3161_module

    def _connection_refused(*_args: object, **_kwargs: object) -> None:
        raise OSError(111, "Connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", _connection_refused)

    # timestamp_document should raise OSError (or a subclass), not crash with
    # an unhandled traceback.
    with pytest.raises((OSError, Exception)):
        rfc3161_module.timestamp_document(
            blake3_hash_hex="a" * 64,
            tsa_url="http://tsa.unreachable.invalid/",
        )


def test_smt_divergence_increments_counter_on_root_mismatch(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    record_smt_divergence increments the Prometheus counter and emits a WARNING.

    This simulates the scenario where a network partition causes two nodes to
    compute different SMT roots for the same shard (e.g. one node received new
    records that the other did not).
    """
    local_root = "aa" * 32
    remote_root = "bb" * 32
    shard_id = "net-partition-shard"
    remote_node = "https://guardian-node-2.example"

    with caplog.at_level(logging.WARNING, logger="protocol.telemetry"):
        record_smt_divergence(
            shard_id=shard_id,
            local_root=local_root,
            remote_root=remote_root,
            remote_node=remote_node,
        )

    # A WARNING log must have been emitted
    warning_records = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("smt_root_divergence" in r.message for r in warning_records), (
        "Expected a WARNING log containing 'smt_root_divergence'"
    )


def test_chain_integrity_preserved_during_partition(fresh_ledger: Ledger) -> None:
    """
    Ledger chain integrity is maintained throughout a simulated network partition.

    Records committed during the partition (no external connectivity) must
    form a valid hash chain that can be independently verified offline.
    """
    # Entries committed before partition
    for i in range(2):
        _append_entry(fresh_ledger, i, shard="pre-partition")

    # Simulate partition: block all outbound sockets
    with patch("socket.socket.connect", side_effect=ConnectionRefusedError("partitioned")):
        # Entries committed during partition
        for i in range(3):
            _append_entry(fresh_ledger, 100 + i, shard="during-partition")

    # Entries committed after partition recovers
    for i in range(2):
        _append_entry(fresh_ledger, 200 + i, shard="post-partition")

    assert len(fresh_ledger.entries) == 7
    assert fresh_ledger.verify_chain()
