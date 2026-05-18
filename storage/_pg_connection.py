"""
Connection pool, circuit breaker, node cache, and batch iteration mixin.

Internal to the storage package (_pg_* convention).
"""

from __future__ import annotations

import json
import logging
import time
from collections import OrderedDict
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime
from threading import Lock
from typing import Any

import psycopg
from psycopg import OperationalError
from psycopg.pq import TransactionStatus
from psycopg_pool import ConnectionPool, PoolTimeout

from storage._pg_utils import _encode_path


logger = logging.getLogger(__name__)


class _ConnectionMixin:
    """Connection pool, circuit breaker, LRU node cache, and batch helpers."""

    # Declared for type-checking; initialized by StorageLayer.__init__
    connection_string: str
    _pool: ConnectionPool[psycopg.Connection[dict[str, Any]]]
    _pool_closed: bool
    _connection_retries: int
    _retry_base_delay_seconds: float
    _retry_max_delay_seconds: float
    _circuit_breaker_threshold: int
    _circuit_breaker_timeout_seconds: float
    _circuit_open_until: float
    _consecutive_connection_failures: int
    _circuit_lock: Lock
    _node_cache_max: int
    _node_cache: OrderedDict[tuple[str, int, bytes], bytes]
    _node_cache_lock: Lock

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    @contextmanager
    def _get_connection(self) -> Iterator[psycopg.Connection[dict[str, Any]]]:
        """Acquire a pooled connection with retry and circuit-breaker protection.

        Yields a connection in transaction mode with dict row factory.
        Any uncommitted transaction is rolled back before returning to the pool.
        """
        connection = self._acquire_connection_with_retry()
        try:
            yield connection
        finally:
            try:
                if (
                    not connection.closed
                    and connection.info.transaction_status != TransactionStatus.IDLE
                ):
                    connection.rollback()
            except Exception:
                logger.warning(
                    "rollback() raised during connection cleanup; returning to pool anyway",
                    exc_info=True,
                )
            self._pool.putconn(connection)

    def _acquire_connection_with_retry(self) -> psycopg.Connection[dict[str, Any]]:
        """Acquire a pooled connection with retry and circuit-breaker protection."""
        last_transient_error: Exception | None = None
        for attempt in range(self._connection_retries + 1):
            if self._is_circuit_breaker_open():
                raise RuntimeError("Database circuit breaker is open; retry later")

            try:
                connection: psycopg.Connection[dict[str, Any]] = self._pool.getconn()
            except Exception as exc:
                if not self._is_transient_connection_error(exc):
                    raise
                last_transient_error = exc
                self._record_connection_failure()
                if attempt == self._connection_retries:
                    break
                delay = min(
                    self._retry_base_delay_seconds * (2**attempt),
                    self._retry_max_delay_seconds,
                )
                time.sleep(delay)
                continue

            self._reset_connection_failures()
            return connection

        if last_transient_error is not None:
            raise RuntimeError(
                "Failed to acquire PostgreSQL connection after retries"
            ) from last_transient_error
        raise RuntimeError("Failed to acquire PostgreSQL connection after retries")

    def _is_transient_connection_error(self, exc: Exception) -> bool:
        """Return True when an exception is likely transient and safe to retry."""
        return isinstance(exc, (OperationalError, PoolTimeout))

    def _record_connection_failure(self) -> None:
        """Update circuit-breaker state after a transient connection failure."""
        with self._circuit_lock:
            self._consecutive_connection_failures += 1
            if self._consecutive_connection_failures >= self._circuit_breaker_threshold:
                self._circuit_open_until = time.monotonic() + self._circuit_breaker_timeout_seconds

    def _reset_connection_failures(self) -> None:
        """Reset circuit-breaker counters after successful connection acquisition."""
        with self._circuit_lock:
            self._consecutive_connection_failures = 0
            self._circuit_open_until = 0.0

    def _is_circuit_breaker_open(self) -> bool:
        """Return True when the connection circuit breaker is currently open."""
        with self._circuit_lock:
            return time.monotonic() < self._circuit_open_until

    # ------------------------------------------------------------------
    # Merkle node cache helpers
    # ------------------------------------------------------------------

    def _cache_get(self, shard_id: str, level: int, path_bytes: bytes) -> bytes | None:
        """Return cached node hash or ``None`` on miss."""
        if self._node_cache_max <= 0:
            return None
        key = (shard_id, level, path_bytes)
        with self._node_cache_lock:
            value = self._node_cache.get(key)
            if value is not None:
                self._node_cache.move_to_end(key)
            return value

    def _cache_put(self, shard_id: str, level: int, path_bytes: bytes, hash_value: bytes) -> None:
        """Insert a node into the cache, evicting the oldest entry if full."""
        if self._node_cache_max <= 0:
            return
        key = (shard_id, level, path_bytes)
        with self._node_cache_lock:
            if key in self._node_cache:
                # Update the cached value too — leaving the stale hash here
                # would return wrong roots after an SMT update for the same
                # (shard, level, path).
                self._node_cache.move_to_end(key)
                self._node_cache[key] = hash_value
            else:
                if len(self._node_cache) >= self._node_cache_max:
                    self._node_cache.popitem(last=False)
                self._node_cache[key] = hash_value

    def _cache_clear(self) -> None:
        """Clear the entire Merkle node cache."""
        with self._node_cache_lock:
            self._node_cache.clear()

    # ------------------------------------------------------------------
    # Batch iteration helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _iter_batches(items: Iterable[Any], batch_size: int) -> Iterator[list[Any]]:
        """Yield items in fixed-size batches."""
        if batch_size <= 0:
            raise ValueError("batch_size must be a positive integer")
        batch: list[Any] = []
        for item in items:
            batch.append(item)
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch

    @staticmethod
    def _iter_ingestion_proof_rows(
        batch_id: str, records: list[dict[str, Any]]
    ) -> Iterator[tuple[Any, ...]]:
        """Yield ingestion proof rows ready for append-only persistence."""
        for idx, record in enumerate(records):
            yield (
                record["proof_id"],
                batch_id,
                record.get("batch_index", idx),
                record["shard_id"],
                record.get("record_type", "document"),
                record["record_id"],
                record.get("version", 1),
                bytes.fromhex(record["content_hash"]),
                bytes.fromhex(record["merkle_root"]),
                json.dumps(record["merkle_proof"]),
                bytes.fromhex(record["ledger_entry_hash"]),
                record["timestamp"],
                json.dumps(record.get("canonicalization")),
                record.get("persisted", True),
            )

    def _iter_tree_node_rows(
        self,
        shard_id: str,
        tree: Any,  # RustSparseMerkleTree — typed as Any to handle optional import
        ts: datetime,
    ) -> Iterator[tuple[str, int, bytes, bytes, datetime]]:
        """Yield sparse Merkle node rows ready for append-only persistence."""
        for path, hash_value in tree.nodes.items():
            path_bytes = _encode_path(path)
            yield (shard_id, len(path), path_bytes, hash_value, ts)
