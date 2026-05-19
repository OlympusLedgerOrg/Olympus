"""
Storage layer for Olympus protocol.

DATABASE BACKEND: PostgreSQL 16+ (PRODUCTION ONLY)
===================================================

This module provides the AUTHORITATIVE production storage layer for Olympus.

PostgreSQL is the ONLY supported production database. This implementation provides:
- ACID transaction guarantees across all tables
- Atomic append operations (no UPDATE or DELETE)
- Concurrent access safety
- Cryptographic hash integrity (32-byte BYTEA constraints)

TABLES (all append-only):
- smt_leaves: Sparse Merkle Tree leaf nodes (key-value pairs)
- smt_nodes: Sparse Merkle Tree internal nodes (path-to-hash mappings)
- shard_headers: Signed shard root commitments with chain linkage
- ledger_entries: Append-only ledger chain linking records to shard roots

TRANSACTION BOUNDARIES:
- append_record(): Single atomic transaction across all four tables
- get_*(): Read-only operations, automatic rollback on exit

Environment Variables:
- OLYMPUS_CB_THRESHOLD: Circuit breaker failure threshold (default: 5)
- OLYMPUS_CB_TIMEOUT_SECONDS: Circuit breaker timeout in seconds (default: 30.0)

See docs/08_database_strategy.md for complete database strategy documentation.

Implementation note
-------------------
The ``StorageLayer`` class is assembled from focused mixin modules (``_pg_*.py``).
Each mixin owns one domain; this file is the public facade.  All callers should
continue to import ``StorageLayer`` from this module — the internal split is an
implementation detail.
"""

from __future__ import annotations

import logging
import os
import time  # noqa: F401 — re-exported so tests can monkeypatch storage.postgres.time.sleep
from collections import OrderedDict
from datetime import datetime  # noqa: F401 — compatibility for tests monkeypatching facade
from threading import Lock
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


# Enforce OLYMPUS_REQUIRE_RUST=1 at postgres module import time (mirrors the check in
# _pg_utils.py but runs again here so test re-imports of storage.postgres see the error
# even when _pg_utils is already cached in sys.modules).
if os.getenv("OLYMPUS_REQUIRE_RUST", "").strip().lower() in {"1", "true", "yes", "on"}:
    try:
        import olympus_core as _oc  # noqa: F401
    except ImportError:
        raise RuntimeError(
            "Rust SMT extension required by OLYMPUS_REQUIRE_RUST=1, "
            "but olympus_core could not be imported — install with `maturin develop`"
        ) from None

# Re-export public sentinel so existing callers keep working.
from protocol.hashes import SNARK_SCALAR_FIELD as SNARK_SCALAR_FIELD  # noqa: F401

# RT-M1 MITIGATION: post-persist ledger entry hash verification is implemented in
# storage/_pg_write.py (_WriteMixin._append_record_inner).  Error strings emitted there:
#   "Failed to load persisted ledger entry for verification"
#   "Persisted dual-root commitment BLAKE3 root mismatch"
#   "Persisted dual-root commitment Poseidon root mismatch"
#   "Persisted ledger entry hash verification failed"
from storage._pg_anchoring import _AnchoringMixin
from storage._pg_checkpoints import _CheckpointsMixin
from storage._pg_connection import _ConnectionMixin
from storage._pg_headers import _HeadersMixin
from storage._pg_ledger import _LedgerMixin
from storage._pg_proofs import _ProofsMixin
from storage._pg_rate_limit import _RateLimitMixin
from storage._pg_schema import _SchemaMixin
from storage._pg_utils import (  # noqa: F401
    _NODE_REHASH_GATE as _NODE_REHASH_GATE,
    _RUST_SMT_AVAILABLE,
    RustSparseMerkleTree as RustSparseMerkleTree,
    _compute_poseidon_root_from_leaves,
    _normalize_timestamp_iso,
    _poseidon_incremental_update,
    _require_rust_smt,
)
from storage._pg_verification import _VerificationMixin
from storage._pg_write import _WriteMixin


logger = logging.getLogger(__name__)


class StorageLayer(
    _ConnectionMixin,
    _SchemaMixin,
    _RateLimitMixin,
    _WriteMixin,
    _ProofsMixin,
    _HeadersMixin,
    _LedgerMixin,
    _AnchoringMixin,
    _CheckpointsMixin,
    _VerificationMixin,
):
    """
    Postgres storage layer for Olympus protocol.

    All operations are append-only and deterministic.

    Methods are distributed across domain mixins (_pg_*.py); this class owns
    only the constructor and pool lifecycle.
    """

    # Default pool size — configurable via OLYMPUS_POOL_MAX_SIZE env var.
    DEFAULT_POOL_MAX_SIZE: int = int(os.environ.get("OLYMPUS_POOL_MAX_SIZE", "20"))

    # Default maximum number of cached Merkle node entries.
    DEFAULT_NODE_CACHE_SIZE: int = 4096
    DEFAULT_FLUSH_BATCH_SIZE: int = 10_000

    def __init__(
        self,
        connection_string: str,
        *,
        pool_min_size: int = 1,
        pool_max_size: int | None = None,
        connection_retries: int = 3,
        retry_base_delay_seconds: float = 0.1,
        retry_max_delay_seconds: float = 2.0,
        circuit_breaker_threshold: int | None = None,
        circuit_breaker_timeout_seconds: float | None = None,
        node_cache_size: int | None = None,
    ):
        """
        Initialize storage layer.

        Args:
            connection_string: Postgres connection string
            pool_min_size: Minimum number of pooled DB connections.
            pool_max_size: Maximum number of pooled DB connections.
                If None, reads from OLYMPUS_POOL_MAX_SIZE env var (default: 20).
            connection_retries: Number of retries for transient connection failures.
            retry_base_delay_seconds: Initial exponential backoff delay in seconds.
            retry_max_delay_seconds: Maximum retry backoff delay in seconds.
            circuit_breaker_threshold: Consecutive transient failures before opening breaker.
                If None, reads from OLYMPUS_CB_THRESHOLD env var (default: 5).
            circuit_breaker_timeout_seconds: Breaker open duration in seconds.
                If None, reads from OLYMPUS_CB_TIMEOUT_SECONDS env var (default: 30.0).
            node_cache_size: Maximum number of entries in the in-memory Merkle node
                cache.  Set to 0 to disable caching.  Defaults to
                :data:`DEFAULT_NODE_CACHE_SIZE`.
        """
        if pool_max_size is None:
            pool_max_size = self.DEFAULT_POOL_MAX_SIZE
        if pool_min_size < 1:
            raise ValueError("pool_min_size must be >= 1")
        if pool_max_size < pool_min_size:
            raise ValueError("pool_max_size must be >= pool_min_size")
        if connection_retries < 0:
            raise ValueError("connection_retries must be >= 0")
        if retry_base_delay_seconds <= 0:
            raise ValueError("retry_base_delay_seconds must be > 0")
        if retry_max_delay_seconds < retry_base_delay_seconds:
            raise ValueError("retry_max_delay_seconds must be >= retry_base_delay_seconds")

        if circuit_breaker_threshold is None:
            circuit_breaker_threshold = int(os.environ.get("OLYMPUS_CB_THRESHOLD", "5"))
        if circuit_breaker_timeout_seconds is None:
            circuit_breaker_timeout_seconds = float(
                os.environ.get("OLYMPUS_CB_TIMEOUT_SECONDS", "30.0")
            )

        if circuit_breaker_threshold < 1:
            raise ValueError("circuit_breaker_threshold must be >= 1")
        if circuit_breaker_timeout_seconds <= 0:
            raise ValueError("circuit_breaker_timeout_seconds must be > 0")

        self.connection_string = connection_string
        self._connection_retries = connection_retries
        self._retry_base_delay_seconds = retry_base_delay_seconds
        self._retry_max_delay_seconds = retry_max_delay_seconds
        self._circuit_breaker_threshold = circuit_breaker_threshold
        self._circuit_breaker_timeout_seconds = circuit_breaker_timeout_seconds
        self._circuit_open_until = 0.0
        self._consecutive_connection_failures = 0
        self._circuit_lock = Lock()
        self._pool: ConnectionPool[psycopg.Connection[dict[str, Any]]] = ConnectionPool(
            conninfo=self.connection_string,
            min_size=pool_min_size,
            max_size=pool_max_size,
            open=True,
            kwargs={"autocommit": False, "row_factory": dict_row},
        )
        self._pool_closed = False

        self._node_cache_max = (
            node_cache_size if node_cache_size is not None else self.DEFAULT_NODE_CACHE_SIZE
        )
        self._node_cache: OrderedDict[tuple[str, int, bytes], bytes] = OrderedDict()
        self._node_cache_lock = Lock()

    def close(self) -> None:
        """Close all pooled database connections."""
        if self._pool_closed:
            return
        self._pool_closed = True
        self._pool.close()

    def __del__(self) -> None:
        """Best-effort pool cleanup for tests and short-lived scripts."""
        try:
            self.close()
        except Exception:
            logger.debug(
                "Suppressed exception during PostgresStorage.__del__ cleanup",
                exc_info=True,
            )


__all__ = ["StorageLayer", "_RUST_SMT_AVAILABLE"]
