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
"""

import json
import logging
import os
import time
from collections import OrderedDict
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from threading import Lock
from typing import Any

import nacl.exceptions
import nacl.signing
import psycopg
import psycopg.errors
from psycopg import OperationalError
from psycopg.pq import TransactionStatus
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, PoolTimeout

from protocol.canonical_json import canonical_json_encode
from protocol.canonicalizer import canonicalization_provenance
from protocol.hashes import record_key, shard_header_hash
from protocol.ledger import LedgerEntry
from protocol.rfc3161 import MAX_TSA_TOKENS, _sha256_of_hash
from protocol.shards import create_shard_header, sign_header, verify_header
from protocol.ssmf import (
    ExistenceProof,
    NonExistenceProof,
    SparseMerkleTree,
    diff_sparse_merkle_trees,
)


logger = logging.getLogger(__name__)


class StorageLayer:
    """
    Postgres storage layer for Olympus protocol.

    All operations are append-only and deterministic.
    """

    # Default maximum number of cached Merkle node entries.
    DEFAULT_NODE_CACHE_SIZE: int = 4096

    def __init__(
        self,
        connection_string: str,
        *,
        pool_min_size: int = 1,
        pool_max_size: int = 10,
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

        # Load circuit breaker parameters from environment if not provided
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

        # In-memory LRU cache for Merkle nodes keyed by (shard_id, level, path_bytes).
        # SMT nodes are immutable once written so caching is safe.
        self._node_cache_max = (
            node_cache_size if node_cache_size is not None else self.DEFAULT_NODE_CACHE_SIZE
        )
        self._node_cache: OrderedDict[tuple[str, int, bytes], bytes] = OrderedDict()
        self._node_cache_lock = Lock()

    @contextmanager
    def _get_connection(self) -> Iterator[psycopg.Connection[dict[str, Any]]]:
        """
        Acquire a pooled database connection with retry and circuit-breaker protection.

        Connection semantics:
        - Connections are reused from a pool (no per-request connect calls).
        - Transient acquisition failures are retried with exponential backoff.
        - Sustained failures open a circuit breaker to fail fast for a cooldown period.
        - Any uncommitted transaction is rolled back before returning to the pool.

        Yields:
            Connection in transaction mode with dict row factory.
        """
        connection = self._acquire_connection_with_retry()
        try:
            yield connection
        finally:
            if (
                not connection.closed
                and connection.info.transaction_status != TransactionStatus.IDLE
            ):
                connection.rollback()
            self._pool.putconn(connection)

    def close(self) -> None:
        """Close all pooled database connections."""
        self._pool.close()

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
                self._node_cache.move_to_end(key)
            else:
                if len(self._node_cache) >= self._node_cache_max:
                    self._node_cache.popitem(last=False)
                self._node_cache[key] = hash_value

    def _cache_clear(self) -> None:
        """Clear the entire Merkle node cache."""
        with self._node_cache_lock:
            self._node_cache.clear()

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
            raise RuntimeError("Failed to acquire PostgreSQL connection after retries") from (
                last_transient_error
            )
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

    def init_schema(self) -> None:
        """
        Initialize database schema.

        Reads and executes all schema migration SQL files in order.
        All DDL statements execute in a single transaction.
        """
        import os

        # Find migrations directory relative to this file
        storage_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(storage_dir)
        migrations_dir = os.path.join(repo_root, "migrations")

        migration_files = sorted(f for f in os.listdir(migrations_dir) if f.endswith(".sql"))

        # BEGIN TRANSACTION (implicit via context manager)
        with self._get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                for migration_file in migration_files:
                    with open(os.path.join(migrations_dir, migration_file)) as f:
                        cur.execute(f.read())
            # COMMIT TRANSACTION (explicit)
            conn.commit()
        # END TRANSACTION (implicit via context manager exit)

    def check_ingestion_schema(self) -> None:
        """
        Verify ingestion tables exist before persisting ingestion batches.

        Raises:
            RuntimeError: When required ingestion tables are missing.
        """
        try:
            with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT 1 FROM ingestion_batches LIMIT 1")
                cur.execute("SELECT 1 FROM api_rate_limits LIMIT 1")
        except Exception as exc:  # pragma: no cover - defensive guardrail
            logger.error("Migration not applied: required ingestion tables missing")
            raise RuntimeError("Database not migrated - run migrations first") from exc

    def consume_rate_limit(
        self,
        *,
        subject_type: str,
        subject: str,
        action: str,
        capacity: float,
        refill_rate_per_second: float,
    ) -> bool:
        """
        Consume a rate-limit token using PostgreSQL for cross-worker coordination.

        Returns:
            True if a token was consumed, False if the subject is rate limited.
        """
        if capacity <= 0 or refill_rate_per_second < 0:
            raise ValueError("capacity must be > 0 and refill_rate_per_second must be >= 0")

        now = datetime.now(timezone.utc)

        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                    INSERT INTO api_rate_limits (subject_type, subject, action, tokens, last_refill_ts)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (subject_type, subject, action) DO NOTHING
                """,
                (subject_type, subject, action, capacity, now),
            )

            cur.execute(
                """
                    SELECT tokens, last_refill_ts
                    FROM api_rate_limits
                    WHERE subject_type = %s AND subject = %s AND action = %s
                    FOR UPDATE
                """,
                (subject_type, subject, action),
            )
            row = cur.fetchone()
            if row is None:
                raise RuntimeError("Failed to load rate limit state from database")

            elapsed = max(0.0, (now - row["last_refill_ts"]).total_seconds())
            tokens = min(capacity, row["tokens"] + elapsed * refill_rate_per_second)

            if tokens < 1.0:
                conn.rollback()
                return False

            tokens -= 1.0
            cur.execute(
                """
                    UPDATE api_rate_limits
                    SET tokens = %s, last_refill_ts = %s
                    WHERE subject_type = %s AND subject = %s AND action = %s
                """,
                (tokens, now, subject_type, subject, action),
            )
            conn.commit()
            return True

    def clear_rate_limits(self) -> None:
        """Clear persisted rate-limit buckets (used by tests)."""
        with self._get_connection() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM api_rate_limits")
            conn.commit()

    def append_record(
        self,
        shard_id: str,
        record_type: str,
        record_id: str,
        version: int,
        value_hash: bytes,
        signing_key: nacl.signing.SigningKey,
        canonicalization: dict[str, Any] | None = None,
        poseidon_root: bytes | None = None,
    ) -> tuple[bytes, ExistenceProof, dict[str, Any], str, LedgerEntry]:
        """
        Append a record to the sparse Merkle tree and update shard header and ledger.

        This is the main write operation. It:
        1. Loads the current tree state from DB
        2. Inserts the new leaf
        3. Updates affected nodes
        4. Creates and signs a new shard header
        5. Creates a ledger entry
        6. Persists everything atomically

        Transaction semantics:
        - All operations occur in a single transaction
        - SELECT MAX(seq)+1 queries execute inside the transaction
        - commit() finalizes all writes atomically
        - Exceptions trigger automatic rollback via context manager

        Args:
            shard_id: Shard identifier
            record_type: Type of record
            record_id: Record identifier
            version: Record version
            value_hash: 32-byte hash of record value
            signing_key: Ed25519 signing key for shard header
            canonicalization: Canonicalization provenance for the committed value
            poseidon_root: Optional 32-byte Poseidon Merkle root (BN128 field element,
                big-endian). When provided, the ledger entry hash uses the dual-root
                commitment formula to atomically bind both the BLAKE3 SMT root and the
                Poseidon root.

        Returns:
            Tuple of (root_hash, proof, header, signature, ledger_entry)
        """
        if len(value_hash) != 32:
            raise ValueError(f"Value hash must be 32 bytes, got {len(value_hash)}")

        # Generate record key
        key = record_key(record_type, record_id, version)

        # BEGIN TRANSACTION (implicit via context manager)
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            # Set SERIALIZABLE isolation level to prevent phantom reads
            # under concurrent writes, particularly for shard header chain linkage
            conn.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")

            # Load current tree state
            tree = self._load_tree_state(cur, shard_id)

            # Check if key already exists
            if tree.get(key) is not None:
                raise ValueError(f"Record already exists: {record_type}:{record_id}:{version}")

            # Update tree
            tree.update(key, value_hash)
            root_hash = tree.get_root()

            # Generate proof
            proof = tree.prove_existence(key)

            # Insert leaf
            cur.execute(
                """
                    INSERT INTO smt_leaves (shard_id, key, version, value_hash, ts)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                (shard_id, key, version, value_hash, datetime.now(timezone.utc)),
            )

            # Insert new affected nodes (append-only, skip if node exists)
            self._persist_tree_nodes(cur, shard_id, tree)

            # Get previous header
            cur.execute(
                """
                    SELECT header_hash, ts FROM shard_headers
                    WHERE shard_id = %s
                    ORDER BY seq DESC
                    LIMIT 1
                    """,
                (shard_id,),
            )
            prev_row = cur.fetchone()
            prev_header_hash = "" if prev_row is None else bytes(prev_row["header_hash"]).hex()

            # Get next sequence number
            cur.execute(
                """
                    SELECT COALESCE(MAX(seq), -1) + 1 as next_seq
                    FROM shard_headers
                    WHERE shard_id = %s
                    """,
                (shard_id,),
            )
            seq_row = cur.fetchone()
            if seq_row is None:
                raise RuntimeError("Failed to compute next shard header sequence")
            seq = seq_row["next_seq"]

            # Create shard header
            ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            if prev_row is not None:
                last_ts_value = prev_row["ts"]
                if isinstance(last_ts_value, datetime):
                    last_ts = last_ts_value.astimezone(timezone.utc)
                else:
                    last_ts = datetime.fromisoformat(str(last_ts_value).replace("Z", "+00:00"))
                if datetime.fromisoformat(ts.replace("Z", "+00:00")) <= last_ts:
                    raise ValueError("New shard header timestamp must be strictly monotonic")
            header = create_shard_header(
                shard_id=shard_id,
                root_hash=root_hash,
                timestamp=ts,
                previous_header_hash=prev_header_hash,
            )

            # Sign header
            signature = sign_header(header, signing_key)
            pubkey = signing_key.verify_key.encode()

            # Verify the header and signature before persisting — this guards
            # against any subtle serialization bug causing a corrupt DB write.
            if not verify_header(header, signature, signing_key.verify_key):
                raise RuntimeError("Shard header signature verification failed before persistence")

            # Insert shard header
            cur.execute(
                """
                    INSERT INTO shard_headers (shard_id, seq, root, header_hash, sig, pubkey, previous_header_hash, ts)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                (
                    shard_id,
                    seq,
                    root_hash,
                    bytes.fromhex(header["header_hash"]),
                    bytes.fromhex(signature),
                    pubkey,
                    prev_header_hash,
                    ts,
                ),
            )

            # Record change in the diff journal for O(changes) diffs
            cur.execute(
                """
                    INSERT INTO smt_change_journal (shard_id, key, old_value, new_value, header_seq, ts)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                (shard_id, key, None, value_hash, seq, ts),
            )

            # Create ledger entry
            record_hash_hex = value_hash.hex()
            shard_root_hex = root_hash.hex()

            # Get previous ledger entry
            cur.execute(
                """
                    SELECT entry_hash FROM ledger_entries
                    WHERE shard_id = %s
                    ORDER BY seq DESC
                    LIMIT 1
                    """,
                (shard_id,),
            )
            prev_ledger_row = cur.fetchone()
            prev_entry_hash = (
                "" if prev_ledger_row is None else bytes(prev_ledger_row["entry_hash"]).hex()
            )

            # Get next ledger sequence number
            cur.execute(
                """
                    SELECT COALESCE(MAX(seq), -1) + 1 as next_seq
                    FROM ledger_entries
                    WHERE shard_id = %s
                    """,
                (shard_id,),
            )
            ledger_row = cur.fetchone()
            if ledger_row is None:
                raise RuntimeError("Failed to compute next ledger sequence")
            ledger_seq = ledger_row["next_seq"]

            canonicalization = canonicalization or canonicalization_provenance(
                "application/octet-stream",
                "byte_preserved",
            )

            # Create ledger entry payload
            ledger_payload: dict[str, Any] = {
                "ts": ts,
                "record_hash": record_hash_hex,
                "shard_id": shard_id,
                "shard_root": shard_root_hex,
                "canonicalization": canonicalization,
                "prev_entry_hash": prev_entry_hash,
            }

            # Derive the Poseidon root decimal string for payload storage
            poseidon_root_decimal: str | None = None
            if poseidon_root is not None:
                if len(poseidon_root) != 32:
                    raise ValueError(
                        f"poseidon_root must be 32 bytes, got {len(poseidon_root)}"
                    )
                poseidon_root_decimal = str(int.from_bytes(poseidon_root, byteorder="big"))
                ledger_payload["poseidon_root"] = poseidon_root_decimal

            # Compute entry hash using canonical JSON
            from protocol.hashes import LEDGER_PREFIX, blake3_hash, create_dual_root_commitment

            if poseidon_root is not None:
                # New format: dual-root commitment atomically binds BLAKE3 and Poseidon roots
                entry_hash = create_dual_root_commitment(root_hash, poseidon_root)
            else:
                # Legacy format: hash of canonical JSON payload
                canonical_json = canonical_json_encode(ledger_payload)
                entry_hash = blake3_hash([LEDGER_PREFIX, canonical_json.encode("utf-8")])

            # Insert ledger entry
            cur.execute(
                """
                    INSERT INTO ledger_entries (shard_id, seq, entry_hash, prev_entry_hash, payload, ts)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                (
                    shard_id,
                    ledger_seq,
                    entry_hash,
                    bytes.fromhex(prev_entry_hash) if prev_entry_hash else b"",
                    json.dumps(ledger_payload),
                    ts,
                ),
            )

            # Create LedgerEntry object
            ledger_entry = LedgerEntry(
                ts=ts,
                record_hash=record_hash_hex,
                shard_id=shard_id,
                shard_root=shard_root_hex,
                canonicalization=canonicalization,
                prev_entry_hash=prev_entry_hash,
                entry_hash=entry_hash.hex(),
                poseidon_root=poseidon_root_decimal,
            )

            # COMMIT TRANSACTION (explicit)
            # All INSERTs succeed atomically or rollback on exception
            conn.commit()

            return root_hash, proof, header, signature, ledger_entry
        # END TRANSACTION (implicit via context manager exit)

    def get_proof(
        self, shard_id: str, record_type: str, record_id: str, version: int
    ) -> ExistenceProof | None:
        """
        Get existence proof for a record.

        Read-only operation. Transaction will rollback on context exit
        (no commit needed for SELECT-only operations).

        Args:
            shard_id: Shard identifier
            record_type: Type of record
            record_id: Record identifier
            version: Record version

        Returns:
            Existence proof if record exists, None otherwise
        """
        key = record_key(record_type, record_id, version)

        # READ-ONLY: No commit needed, transaction auto-rolls back
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            # Check if leaf exists
            cur.execute(
                """
                    SELECT value_hash FROM smt_leaves
                    WHERE shard_id = %s AND key = %s AND version = %s
                    """,
                (shard_id, key, version),
            )
            row = cur.fetchone()

            if row is None:
                return None

            # Load tree and generate proof
            tree = self._load_tree_state(cur, shard_id)
            return tree.prove_existence(key)

    def get_nonexistence_proof(
        self, shard_id: str, record_type: str, record_id: str, version: int
    ) -> NonExistenceProof:
        """
        Get non-existence proof for a record.

        Read-only operation. Transaction will rollback on context exit
        (no commit needed for SELECT-only operations).

        Args:
            shard_id: Shard identifier
            record_type: Type of record
            record_id: Record identifier
            version: Record version

        Returns:
            Non-existence proof

        Raises:
            ValueError: If record exists
        """
        key = record_key(record_type, record_id, version)

        # READ-ONLY: No commit needed, transaction auto-rolls back
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            # Check if leaf exists
            cur.execute(
                """
                    SELECT 1 FROM smt_leaves
                    WHERE shard_id = %s AND key = %s AND version = %s
                    """,
                (shard_id, key, version),
            )
            if cur.fetchone() is not None:
                raise ValueError("Record exists, cannot generate non-existence proof")

            # Load tree and generate proof
            tree = self._load_tree_state(cur, shard_id)
            return tree.prove_nonexistence(key)

    def store_ingestion_batch(self, batch_id: str, records: list[dict[str, Any]]) -> None:
        """
        Persist proof_id-to-record mappings for ingestion durability.

        Args:
            batch_id: Unique batch identifier for the ingestion batch.
            records: List of ingestion metadata dicts to persist.
        """
        if not records:
            return

        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                    INSERT INTO ingestion_batches (batch_id)
                    VALUES (%s)
                    ON CONFLICT (batch_id) DO NOTHING
                """,
                (batch_id,),
            )

            for idx, record in enumerate(records):
                cur.execute(
                    """
                        INSERT INTO ingestion_proofs (
                            proof_id,
                            batch_id,
                            batch_index,
                            shard_id,
                            record_type,
                            record_id,
                            version,
                            content_hash,
                            merkle_root,
                            merkle_proof,
                            ledger_entry_hash,
                            ts,
                            canonicalization,
                            persisted
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (proof_id) DO NOTHING
                    """,
                    (
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
                    ),
                )

            conn.commit()

    def get_ingestion_proof(self, proof_id: str) -> dict[str, Any] | None:
        """Retrieve a persisted ingestion proof mapping by proof_id."""
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                    SELECT
                        proof_id,
                        batch_id,
                        batch_index,
                        shard_id,
                        record_type,
                        record_id,
                        version,
                        content_hash,
                        merkle_root,
                        merkle_proof,
                        ledger_entry_hash,
                        ts,
                        canonicalization,
                        persisted
                    FROM ingestion_proofs
                    WHERE proof_id = %s
                    LIMIT 1
                """,
                (proof_id,),
            )
            row = cur.fetchone()

        if row is None:
            return None

        ts_value = row["ts"]
        ts = (
            ts_value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            if isinstance(ts_value, datetime)
            else str(ts_value)
        )

        return {
            "proof_id": row["proof_id"],
            "batch_id": row["batch_id"],
            "batch_index": row["batch_index"],
            "record_id": row["record_id"],
            "record_type": row["record_type"],
            "version": row["version"],
            "shard_id": row["shard_id"],
            "content_hash": bytes(row["content_hash"]).hex(),
            "merkle_root": bytes(row["merkle_root"]).hex(),
            "merkle_proof": row["merkle_proof"],
            "ledger_entry_hash": bytes(row["ledger_entry_hash"]).hex(),
            "timestamp": ts,
            "canonicalization": row["canonicalization"],
            "persisted": row.get("persisted", True),
        }

    def get_ingestion_proof_by_content_hash(self, content_hash: bytes) -> dict[str, Any] | None:
        """Retrieve a persisted ingestion proof mapping by content hash."""
        if len(content_hash) != 32:
            raise ValueError("content_hash must be 32 bytes")

        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                    SELECT proof_id
                    FROM ingestion_proofs
                    WHERE content_hash = %s
                    LIMIT 1
                """,
                (content_hash,),
            )
            row = cur.fetchone()

        if row is None:
            return None

        return self.get_ingestion_proof(row["proof_id"])

    def get_latest_header(self, shard_id: str) -> dict[str, Any] | None:
        """
        Get the latest shard header.

        Read-only operation. Transaction will rollback on context exit
        (no commit needed for SELECT-only operations).

        Args:
            shard_id: Shard identifier

        Returns:
            Dictionary with header, signature, and pubkey, or None if no headers exist
        """
        # READ-ONLY: No commit needed, transaction auto-rolls back
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                    SELECT root, header_hash, sig, pubkey, previous_header_hash, ts, seq
                    FROM shard_headers
                    WHERE shard_id = %s
                    ORDER BY seq DESC
                    LIMIT 1
                    """,
                (shard_id,),
            )
            row = cur.fetchone()

            if row is None:
                return None

            # Reconstruct header
            # Convert timestamp to ISO 8601 string if it's a datetime object
            ts_value = row["ts"]
            if isinstance(ts_value, str):
                timestamp_str = ts_value
            elif isinstance(ts_value, datetime):
                # It's a datetime object from Postgres - convert to ISO 8601 string
                timestamp_str = ts_value.isoformat().replace("+00:00", "Z")
            else:
                # Unexpected type - raise error for clarity
                raise TypeError(
                    f"Unexpected timestamp type: {type(ts_value).__name__}. Expected str or datetime."
                )

            header = {
                "shard_id": shard_id,
                "root_hash": bytes(row["root"]).hex(),
                "timestamp": timestamp_str,
                "previous_header_hash": row["previous_header_hash"],
                "header_hash": bytes(row["header_hash"]).hex(),
            }
            signature = bytes(row["sig"]).hex()
            verify_key = nacl.signing.VerifyKey(bytes(row["pubkey"]))
            if not verify_header(header, signature, verify_key):
                raise ValueError(f"Invalid shard header signature for shard '{shard_id}'")

            expected_hash = shard_header_hash(
                {
                    "shard_id": header["shard_id"],
                    "root_hash": header["root_hash"],
                    "timestamp": header["timestamp"],
                    "previous_header_hash": header["previous_header_hash"],
                }
            ).hex()
            if header["header_hash"] != expected_hash:
                raise ValueError(f"Invalid shard header hash for shard '{shard_id}'")

            sig_bytes = bytes(row["sig"])
            verify_key = nacl.signing.VerifyKey(bytes(row["pubkey"]))
            try:
                verify_key.verify(bytes.fromhex(header["header_hash"]), sig_bytes)
            except nacl.exceptions.BadSignatureError as e:
                raise ValueError(f"Invalid shard header signature for shard '{shard_id}'") from e

            # Guard against SMT divergence by recomputing the current root.
            self._assert_root_matches_state(cur, shard_id, bytes(row["root"]))

            return {
                "header": header,
                "signature": signature,
                "pubkey": bytes(row["pubkey"]).hex(),
                "seq": row["seq"],
            }

    def get_header_history(self, shard_id: str, n: int = 10) -> list[dict[str, Any]]:
        """
        Get the last N signed shard headers for a shard.

        Args:
            shard_id: Shard identifier
            n: Number of headers to retrieve

        Returns:
            Header snapshots in reverse chronological order
        """
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                    SELECT seq, root, header_hash, previous_header_hash, ts
                    FROM shard_headers
                    WHERE shard_id = %s
                    ORDER BY seq DESC
                    LIMIT %s
                    """,
                (shard_id, n),
            )
            rows = cur.fetchall()
            history = []
            for row in rows:
                ts_value = row["ts"]
                if isinstance(ts_value, str):
                    timestamp_str = ts_value
                elif isinstance(ts_value, datetime):
                    timestamp_str = ts_value.isoformat().replace("+00:00", "Z")
                else:
                    raise TypeError(
                        f"Unexpected timestamp type: {type(ts_value).__name__}. Expected str or datetime."
                    )

                history.append(
                    {
                        "seq": row["seq"],
                        "root_hash": bytes(row["root"]).hex(),
                        "header_hash": bytes(row["header_hash"]).hex(),
                        "previous_header_hash": bytes(row["previous_header_hash"]).hex(),
                        "timestamp": timestamp_str,
                    }
                )

            return history

    def get_root_diff(
        self,
        shard_id: str,
        from_seq: int,
        to_seq: int,
        key_range_start: bytes | None = None,
        key_range_end: bytes | None = None,
    ) -> dict[str, Any]:
        """
        Compare two historical shard states.

        When a change journal is available the diff is computed in O(changes)
        without reconstructing full SMTs.  Falls back to the original
        full-tree reconstruction when journal coverage is incomplete.

        Args:
            shard_id: Shard identifier
            from_seq: Baseline shard header sequence
            to_seq: Target shard header sequence
            key_range_start: Inclusive lower bound for key range (optional)
            key_range_end: Exclusive upper bound for key range (optional)

        Returns:
            Root hashes and leaf-level additions, changes, and removals
            within the specified key range

        Raises:
            ValueError: If either sequence does not exist
        """
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            from_header = self._get_header_by_seq(cur, shard_id, from_seq)
            to_header = self._get_header_by_seq(cur, shard_id, to_seq)

            if from_header is None:
                raise ValueError(f"Shard header not found: {shard_id}@{from_seq}")
            if to_header is None:
                raise ValueError(f"Shard header not found: {shard_id}@{to_seq}")

            # Fast path: use change journal when available
            journal_diff = self._diff_from_journal(
                cur, shard_id, from_seq, to_seq, key_range_start, key_range_end
            )
            if journal_diff is not None:
                journal_diff["from_root_hash"] = bytes(from_header["root"]).hex()
                journal_diff["to_root_hash"] = bytes(to_header["root"]).hex()
                return journal_diff

            # Slow path: reconstruct full trees
            from_tree = self._load_tree_state(cur, shard_id, up_to_ts=from_header["ts"])
            to_tree = self._load_tree_state(cur, shard_id, up_to_ts=to_header["ts"])
            diff = diff_sparse_merkle_trees(
                from_tree, to_tree, key_range_start=key_range_start, key_range_end=key_range_end
            )

            return {
                "from_root_hash": bytes(from_header["root"]).hex(),
                "to_root_hash": bytes(to_header["root"]).hex(),
                "added": [entry.to_dict() for entry in diff["added"]],
                "changed": [entry.to_dict() for entry in diff["changed"]],
                "removed": [entry.to_dict() for entry in diff["removed"]],
            }

    def _diff_from_journal(
        self,
        cur: psycopg.Cursor[Any],
        shard_id: str,
        from_seq: int,
        to_seq: int,
        key_range_start: bytes | None,
        key_range_end: bytes | None,
    ) -> dict[str, Any] | None:
        """
        Attempt to compute a diff from the change journal.

        Returns None when the journal table does not exist or has no
        coverage for the requested range.
        """
        try:
            cur.execute(
                """
                SELECT key, old_value, new_value
                FROM smt_change_journal
                WHERE shard_id = %s AND header_seq > %s AND header_seq <= %s
                ORDER BY id ASC
                """,
                (shard_id, from_seq, to_seq),
            )
        except psycopg.errors.UndefinedTable:
            # Table does not exist yet (migration 009 not applied)
            return None

        rows = cur.fetchall()
        if not rows:
            # No journal rows — either nothing changed or journal not populated
            return None

        added: list[dict[str, str | None]] = []
        changed: list[dict[str, str | None]] = []
        # Removed entries are not possible in an append-only ledger but
        # the schema supports them for completeness.
        removed: list[dict[str, str | None]] = []

        for row in rows:
            key = bytes(row["key"])
            if key_range_start is not None and key < key_range_start:
                continue
            if key_range_end is not None and key >= key_range_end:
                continue

            old_val = row["old_value"]
            new_val = bytes(row["new_value"]) if row["new_value"] else None

            if old_val is None:
                added.append(
                    {
                        "key": key.hex(),
                        "before_value_hash": None,
                        "after_value_hash": new_val.hex() if new_val else None,
                    }
                )
            elif new_val is None:
                removed.append(
                    {
                        "key": key.hex(),
                        "before_value_hash": bytes(old_val).hex(),
                        "after_value_hash": None,
                    }
                )
            else:
                changed.append(
                    {
                        "key": key.hex(),
                        "before_value_hash": bytes(old_val).hex(),
                        "after_value_hash": new_val.hex(),
                    }
                )

        return {"added": added, "changed": changed, "removed": removed}

    def get_ledger_tail(self, shard_id: str, n: int = 10) -> list[LedgerEntry]:
        """
        Get the last N ledger entries for a shard.

        Read-only operation. Transaction will rollback on context exit
        (no commit needed for SELECT-only operations).

        Args:
            shard_id: Shard identifier
            n: Number of entries to retrieve

        Returns:
            List of ledger entries (most recent first)
        """
        # READ-ONLY: No commit needed, transaction auto-rolls back
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                    SELECT payload, entry_hash
                    FROM ledger_entries
                    WHERE shard_id = %s
                    ORDER BY seq DESC
                    LIMIT %s
                    """,
                (shard_id, n),
            )
            rows = cur.fetchall()

            entries = []
            for row in rows:
                payload = row["payload"]
                entry = LedgerEntry(
                    ts=payload["ts"],
                    record_hash=payload["record_hash"],
                    shard_id=payload["shard_id"],
                    shard_root=payload["shard_root"],
                    canonicalization=payload["canonicalization"],
                    prev_entry_hash=payload["prev_entry_hash"],
                    entry_hash=bytes(row["entry_hash"]).hex(),
                )
                entries.append(entry)

            return entries

    def get_all_shard_ids(self) -> list[str]:
        """
        Get all shard IDs that have headers.

        Read-only operation. Transaction will rollback on context exit
        (no commit needed for SELECT-only operations).

        Returns:
            List of shard IDs
        """
        # READ-ONLY: No commit needed, transaction auto-rolls back
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                    SELECT DISTINCT shard_id FROM shard_headers
                    ORDER BY shard_id
                    """
            )
            rows = cur.fetchall()
            return [row["shard_id"] for row in rows]

    def verify_state_replay(self, shard_id: str) -> bool:
        """
        Replay shard state from genesis and verify roots against headers and ledger.

        Returns True when:
          * Every persisted shard header root matches the recomputed SMT root, and
          * Every ledger entry payload shard_root matches the same recomputed root.

        Args:
            shard_id: Shard identifier to replay.

        Raises:
            ValueError: If counts diverge or any root mismatch is detected.
        """
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT key, value_hash
                FROM smt_leaves
                WHERE shard_id = %s
                ORDER BY ts ASC, key ASC
                """,
                (shard_id,),
            )
            leaves = cur.fetchall()

            cur.execute(
                """
                SELECT seq, root
                FROM shard_headers
                WHERE shard_id = %s
                ORDER BY seq ASC
                """,
                (shard_id,),
            )
            headers = cur.fetchall()

            cur.execute(
                """
                SELECT seq, payload
                FROM ledger_entries
                WHERE shard_id = %s
                ORDER BY seq ASC
                """,
                (shard_id,),
            )
            ledger_rows = cur.fetchall()

            if len(headers) != len(leaves):
                raise ValueError(
                    f"Replay mismatch for shard '{shard_id}': {len(headers)} headers vs "
                    f"{len(leaves)} leaves"
                )

            if len(ledger_rows) != len(headers):
                raise ValueError(
                    f"Replay mismatch for shard '{shard_id}': {len(ledger_rows)} ledger entries "
                    f"vs {len(headers)} headers"
                )

            tree = SparseMerkleTree()

            for idx, leaf_row in enumerate(leaves):
                key = bytes(self._row_get(leaf_row, "key", 0))
                value_hash = bytes(self._row_get(leaf_row, "value_hash", 1))
                tree.update(key, value_hash)
                computed_root = tree.get_root()

                header_row = headers[idx]
                header_seq = int(self._row_get(header_row, "seq", 0))
                expected_header_root = bytes(self._row_get(header_row, "root", 1))
                if computed_root != expected_header_root:
                    raise ValueError(
                        f"Shard '{shard_id}' root mismatch at header seq {header_seq}: "
                        f"expected {expected_header_root.hex()}, computed {computed_root.hex()}"
                    )

                ledger_row = ledger_rows[idx]
                ledger_seq = int(self._row_get(ledger_row, "seq", 0))
                payload = self._row_get(ledger_row, "payload", 1)
                if isinstance(payload, str):
                    payload = json.loads(payload)
                shard_root_hex = payload.get("shard_root")
                if shard_root_hex is None:
                    raise ValueError(
                        f"Ledger entry missing shard_root for shard '{shard_id}' at seq {ledger_seq}"
                    )
                if computed_root.hex() != shard_root_hex:
                    raise ValueError(
                        f"Shard '{shard_id}' ledger root mismatch at seq {ledger_seq}: "
                        f"expected {shard_root_hex}, computed {computed_root.hex()}"
                    )

            return True

    def store_timestamp_token(
        self,
        shard_id: str,
        header_hash_hex: str,
        token: "Any",
    ) -> None:
        """
        Persist an RFC 3161 timestamp token for a shard header.

        The token must have been issued for the given ``header_hash_hex``.
        This operation is idempotent – a second insert for the same
        ``(shard_id, header_hash)`` is silently ignored.

        Args:
            shard_id: Shard identifier.
            header_hash_hex: Hex-encoded 32-byte shard header hash.
            token: :class:`protocol.rfc3161.TimestampToken` instance.
        """
        header_hash_bytes = bytes.fromhex(header_hash_hex)
        if len(header_hash_bytes) != 32:
            raise ValueError(
                f"header_hash_hex must encode exactly 32 bytes, got {len(header_hash_bytes)}"
            )

        hash_hex = token.hash_hex if hasattr(token, "hash_hex") else token["hash_hex"]
        tsa_url = token.tsa_url if hasattr(token, "tsa_url") else token["tsa_url"]
        tst_bytes = (
            token.tst_bytes if hasattr(token, "tst_bytes") else bytes.fromhex(token["tst_hex"])
        )
        tsa_cert_fingerprint = (
            token.tsa_cert_fingerprint
            if hasattr(token, "tsa_cert_fingerprint")
            else token.get("tsa_cert_fingerprint")
        )
        timestamp = token.timestamp if hasattr(token, "timestamp") else token["timestamp"]
        ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        imprint_hash = _sha256_of_hash(hash_hex)
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT COUNT(*) AS token_count,
                       BOOL_OR(tsa_url = %s) AS tsa_already_present
                FROM timestamp_tokens
                WHERE shard_id = %s AND header_hash = %s
                """,
                (tsa_url, shard_id, header_hash_bytes),
            )
            limit_row = cur.fetchone()
            if limit_row is None:
                raise RuntimeError("Failed to load timestamp token count")
            if int(limit_row["token_count"]) >= MAX_TSA_TOKENS and not bool(
                limit_row["tsa_already_present"]
            ):
                raise ValueError(
                    f"Refusing to store more than {MAX_TSA_TOKENS} TSA tokens for a header"
                )
            cur.execute(
                """
                INSERT INTO timestamp_tokens
                    (shard_id, header_hash, tsa_url, tst, imprint_hash, gen_time, tsa_cert_fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (shard_id, header_hash, tsa_url) DO NOTHING
                """,
                (
                    shard_id,
                    header_hash_bytes,
                    tsa_url,
                    tst_bytes,
                    imprint_hash,
                    ts,
                    tsa_cert_fingerprint,
                ),
            )
            conn.commit()

    def get_timestamp_tokens(self, shard_id: str, header_hash_hex: str) -> list[dict[str, Any]]:
        """
        Retrieve all stored RFC 3161 timestamp tokens for a shard header.

        Args:
            shard_id: Shard identifier.
            header_hash_hex: Hex-encoded 32-byte shard header hash.

        Returns:
            Stored timestamp tokens ordered by generation time, then TSA URL.
        """
        header_hash_bytes = bytes.fromhex(header_hash_hex)
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT tsa_url, tst, gen_time, tsa_cert_fingerprint
                FROM timestamp_tokens
                WHERE shard_id = %s AND header_hash = %s
                ORDER BY gen_time ASC, tsa_url ASC
                """,
                (shard_id, header_hash_bytes),
            )
            rows = cur.fetchall()

        tokens: list[dict[str, Any]] = []
        for row in rows:
            ts_value = row["gen_time"]
            if isinstance(ts_value, datetime):
                timestamp_str = ts_value.isoformat().replace("+00:00", "Z")
            else:
                timestamp_str = str(ts_value)

            tokens.append(
                {
                    "tsa_url": row["tsa_url"],
                    "tst_hex": bytes(row["tst"]).hex(),
                    "hash_hex": header_hash_hex,
                    "timestamp": timestamp_str,
                    "tsa_cert_fingerprint": row["tsa_cert_fingerprint"],
                }
            )
        return tokens

    def get_timestamp_token(self, shard_id: str, header_hash_hex: str) -> "dict[str, Any] | None":
        """
        Retrieve the RFC 3161 timestamp token for a shard header, if stored.

        Args:
            shard_id: Shard identifier.
            header_hash_hex: Hex-encoded 32-byte shard header hash.

        Returns:
            Dictionary with keys ``tsa_url``, ``tst_hex``, ``hash_hex``,
            ``timestamp`` (ISO 8601 with 'Z' suffix), or ``None`` if not found.
        """
        tokens = self.get_timestamp_tokens(shard_id, header_hash_hex)
        if not tokens:
            return None
        return tokens[0]

    def verify_persisted_root(self, shard_id: str) -> bool:
        """
        Verify that the persisted root matches recomputed root from leaves.

        Read-only operation. Transaction will rollback on context exit
        (no commit needed for SELECT-only operations).

        Args:
            shard_id: Shard identifier

        Returns:
            True if root is valid
        """
        # READ-ONLY: No commit needed, transaction auto-rolls back
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            # Get latest header root
            cur.execute(
                """
                    SELECT root FROM shard_headers
                    WHERE shard_id = %s
                    ORDER BY seq DESC
                    LIMIT 1
                    """,
                (shard_id,),
            )
            row = cur.fetchone()

            if row is None:
                # No headers, so root is valid (empty tree)
                return True

            persisted_root = bytes(row["root"])

            # Recompute root from leaves
            tree = self._load_tree_state(cur, shard_id)
            computed_root = tree.get_root()

            return persisted_root == computed_root

    # ------------------------------------------------------------------
    # Shard compaction (checkpoint roots)
    # ------------------------------------------------------------------

    def create_checkpoint(self, shard_id: str) -> dict[str, Any] | None:
        """
        Store a checkpoint root for the current shard state.

        Checkpoints record periodic snapshots of the SMT root so that
        historical state can be reconstructed from a recent checkpoint
        instead of replaying from genesis.

        Returns:
            Checkpoint metadata dict, or None if the shard has no headers.
        """
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT seq, root FROM shard_headers
                WHERE shard_id = %s
                ORDER BY seq DESC
                LIMIT 1
                """,
                (shard_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None

            header_seq = row["seq"]
            root_hash = bytes(row["root"])

            cur.execute(
                "SELECT COUNT(*) AS cnt FROM smt_leaves WHERE shard_id = %s",
                (shard_id,),
            )
            count_row = cur.fetchone()
            leaf_count = int(count_row["cnt"]) if count_row else 0

            ts = datetime.now(timezone.utc)
            cur.execute(
                """
                INSERT INTO smt_checkpoints (shard_id, header_seq, root_hash, leaf_count, ts)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (shard_id, header_seq) DO NOTHING
                """,
                (shard_id, header_seq, root_hash, leaf_count, ts),
            )
            conn.commit()

            return {
                "shard_id": shard_id,
                "header_seq": header_seq,
                "root_hash": root_hash.hex(),
                "leaf_count": leaf_count,
                "ts": ts.isoformat().replace("+00:00", "Z"),
            }

    def get_checkpoints(self, shard_id: str, n: int = 10) -> list[dict[str, Any]]:
        """
        Retrieve the last N checkpoints for a shard.

        Args:
            shard_id: Shard identifier
            n: Maximum number of checkpoints to return

        Returns:
            List of checkpoint dicts (most recent first)
        """
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT header_seq, root_hash, leaf_count, ts
                FROM smt_checkpoints
                WHERE shard_id = %s
                ORDER BY header_seq DESC
                LIMIT %s
                """,
                (shard_id, n),
            )
            rows = cur.fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            ts_val = row["ts"]
            ts_str = (
                ts_val.isoformat().replace("+00:00", "Z")
                if isinstance(ts_val, datetime)
                else str(ts_val)
            )
            results.append(
                {
                    "shard_id": shard_id,
                    "header_seq": row["header_seq"],
                    "root_hash": bytes(row["root_hash"]).hex(),
                    "leaf_count": row["leaf_count"],
                    "ts": ts_str,
                }
            )
        return results

    def _row_get(self, row: Any, key: str, idx: int) -> Any:
        """
        Get value from row, supporting both dict and tuple rows.

        This defensive helper ensures compatibility with different cursor row factories.

        Args:
            row: Database row (dict or tuple)
            key: Column name (for dict rows)
            idx: Column index (for tuple rows)

        Returns:
            Value at the specified column
        """
        if isinstance(row, Mapping):
            return row[key]
        return row[idx]

    def _assert_root_matches_state(
        self,
        cur: psycopg.Cursor[Any],
        shard_id: str,
        expected_root: bytes,
    ) -> None:
        """
        Recompute the current shard root and ensure it matches ``expected_root``.

        Args:
            cur: Active database cursor (read-only).
            shard_id: Shard identifier.
            expected_root: Root hash from persisted header.

        Raises:
            ValueError: When the recomputed root diverges from ``expected_root``.
        """
        tree = self._load_tree_state(cur, shard_id)
        computed_root = tree.get_root()
        if computed_root != expected_root:
            raise ValueError(
                f"Computed root {computed_root.hex()} does not match persisted root "
                f"{expected_root.hex()} for shard '{shard_id}'"
            )

    def _load_tree_state(
        self,
        cur: psycopg.Cursor[Any],
        shard_id: str,
        up_to_ts: datetime | str | None = None,
    ) -> SparseMerkleTree:
        """
        Load sparse Merkle tree state from database.

        Read-only helper. Must be called within an existing transaction.
        No writes, no commit.

        Args:
            cur: Database cursor
            shard_id: Shard identifier
            up_to_ts: Optional inclusive timestamp cutoff for historical snapshots

        Returns:
            SparseMerkleTree with all leaves loaded
        """
        tree = SparseMerkleTree()

        # Load all leaves for this shard
        # Secondary ordering by key makes replay deterministic when multiple inserts share
        # the same timestamp, while preserving the primary append order on ts. Without
        # this stable tie-break, historical reconstruction could yield different roots
        # for the same cutoff timestamp and break offline verification.
        if up_to_ts is None:
            cur.execute(
                """
                SELECT key, value_hash FROM smt_leaves
                WHERE shard_id = %s
                ORDER BY ts ASC, key ASC
                """,
                (shard_id,),
            )
        else:
            cutoff = up_to_ts
            if isinstance(cutoff, str):
                cutoff = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
            cur.execute(
                """
                SELECT key, value_hash FROM smt_leaves
                WHERE shard_id = %s AND ts <= %s
                ORDER BY ts ASC, key ASC
                """,
                (shard_id, cutoff),
            )
        rows = cur.fetchall()

        # Rebuild tree by updating each leaf
        for row in rows:
            # Support both dict and tuple rows for robustness
            # SELECT key, value_hash => indices 0, 1
            key = bytes(self._row_get(row, "key", 0))
            value_hash = bytes(self._row_get(row, "value_hash", 1))
            tree.update(key, value_hash)

        return tree

    def _get_header_by_seq(
        self, cur: psycopg.Cursor[Any], shard_id: str, seq: int
    ) -> dict[str, Any] | None:
        """
        Retrieve a shard header row by sequence number.

        Args:
            cur: Database cursor
            shard_id: Shard identifier
            seq: Header sequence number

        Returns:
            Matching row or None when absent
        """
        cur.execute(
            """
            SELECT seq, root, header_hash, previous_header_hash, ts
            FROM shard_headers
            WHERE shard_id = %s AND seq = %s
            """,
            (shard_id, seq),
        )
        return cur.fetchone()

    def _persist_tree_nodes(
        self, cur: psycopg.Cursor[Any], shard_id: str, tree: SparseMerkleTree
    ) -> None:
        """
        Persist tree nodes to database and populate the node cache.

        Only inserts new nodes (append-only).
        Node insertion failures are acceptable - they indicate the node already exists.

        Args:
            cur: Database cursor
            shard_id: Shard identifier
            tree: SparseMerkleTree to persist
        """
        # Insert all nodes from tree
        for path, hash_value in tree.nodes.items():
            # Encode path as bytes
            path_bytes = self._encode_path(path)
            level = len(path)

            cur.execute(
                """
                INSERT INTO smt_nodes (shard_id, level, index, hash, ts)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (shard_id, level, index) DO NOTHING
                """,
                (shard_id, level, path_bytes, hash_value, datetime.now(timezone.utc)),
            )

            # Populate cache with freshly persisted nodes
            self._cache_put(shard_id, level, path_bytes, hash_value)

    @staticmethod
    def _encode_path(path: tuple[int, ...]) -> bytes:
        """
        Encode path tuple as packed bytes.

        Each bit in the path is packed into bytes (MSB first), giving an 8×
        reduction compared to the naive one-byte-per-bit encoding.  A 256-bit
        path becomes 32 bytes instead of 256.  The encoding is deterministic
        and compatible with the standard SMT key representation.

        Args:
            path: Tuple of 0s and 1s (up to 256 elements)

        Returns:
            Packed bytes representation (ceil(len(path) / 8) bytes)
        """
        if not path:
            return b""
        n = len(path)
        num_bytes = (n + 7) // 8
        result = bytearray(num_bytes)
        for i, bit in enumerate(path):
            if bit:
                result[i >> 3] |= 1 << (7 - (i & 7))
        return bytes(result)
