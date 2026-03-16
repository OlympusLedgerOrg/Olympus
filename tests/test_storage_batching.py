"""Unit tests for chunked Postgres flush helpers."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime

from protocol.hashes import hash_bytes, record_key
from protocol.ssmf import SparseMerkleTree
from storage.postgres import StorageLayer


class _FakeCursor:
    def __init__(self) -> None:
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []
        self.executemany_calls: list[tuple[str, list[tuple[object, ...]]]] = []

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def execute(self, sql: str, params: tuple[object, ...]) -> None:
        self.execute_calls.append((sql, params))

    def executemany(self, sql: str, rows: list[tuple[object, ...]]) -> None:
        self.executemany_calls.append((sql, list(rows)))


class _FakeConnection:
    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor
        self.commits = 0

    def cursor(self, *, row_factory: object | None = None) -> _FakeCursor:
        return self._cursor

    def commit(self) -> None:
        self.commits += 1


@contextmanager
def _fake_connection_scope(connection: _FakeConnection):
    yield connection


def _make_storage_for_unit_tests() -> StorageLayer:
    storage = object.__new__(StorageLayer)
    storage.DEFAULT_FLUSH_BATCH_SIZE = 2
    storage._node_cache_max = 0
    return storage


def test_iter_batches_splits_input_at_flush_boundary() -> None:
    batches = list(StorageLayer._iter_batches(range(5), 2))
    assert batches == [[0, 1], [2, 3], [4]]


def test_iter_batches_rejects_non_positive_batch_size() -> None:
    try:
        list(StorageLayer._iter_batches([1], 0))
    except ValueError as exc:
        assert "batch_size" in str(exc)
    else:
        raise AssertionError("Expected ValueError for batch_size=0")


def test_persist_tree_nodes_flushes_in_chunks() -> None:
    storage = _make_storage_for_unit_tests()
    cursor = _FakeCursor()
    cached_nodes: list[tuple[str, int, bytes, bytes]] = []
    storage._cache_put = lambda shard_id, level, path_bytes, hash_value: cached_nodes.append(  # type: ignore[method-assign]
        (shard_id, level, path_bytes, hash_value)
    )

    tree = SparseMerkleTree()
    for idx in range(3):
        tree.update(record_key("document", f"doc-{idx}", 1), hash_bytes(f"value-{idx}".encode()))

    storage._persist_tree_nodes(cursor, "shard-batch", tree)

    flushed_rows = sum(len(rows) for _, rows in cursor.executemany_calls)
    expected_batches = (len(tree.nodes) + storage.DEFAULT_FLUSH_BATCH_SIZE - 1) // (
        storage.DEFAULT_FLUSH_BATCH_SIZE
    )
    assert len(cursor.executemany_calls) == expected_batches
    assert flushed_rows == len(tree.nodes)
    assert len(cached_nodes) == len(tree.nodes)


def test_store_ingestion_batch_flushes_proofs_in_chunks() -> None:
    storage = _make_storage_for_unit_tests()
    cursor = _FakeCursor()
    connection = _FakeConnection(cursor)
    storage._get_connection = lambda: _fake_connection_scope(connection)  # type: ignore[method-assign]

    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    records = [
        {
            "proof_id": f"proof-{idx}",
            "record_id": f"record-{idx}",
            "record_type": "document",
            "version": 1,
            "shard_id": "shard-batch",
            "content_hash": hash_bytes(f"content-{idx}".encode()).hex(),
            "merkle_root": hash_bytes(f"root-{idx}".encode()).hex(),
            "merkle_proof": {"siblings": []},
            "ledger_entry_hash": hash_bytes(f"ledger-{idx}".encode()).hex(),
            "timestamp": timestamp,
            "canonicalization": {"type": "unit-test"},
            "persisted": True,
        }
        for idx in range(3)
    ]

    storage.store_ingestion_batch("batch-1", records)

    assert len(cursor.execute_calls) == 1
    assert len(cursor.executemany_calls) == 2
    assert sum(len(rows) for _, rows in cursor.executemany_calls) == len(records)
    assert connection.commits == 1
