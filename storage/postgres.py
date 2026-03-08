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

See docs/08_database_strategy.md for complete database strategy documentation.
"""

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

import nacl.exceptions
import nacl.signing
import psycopg
from psycopg.rows import dict_row

from protocol.canonical_json import canonical_json_encode
from protocol.canonicalizer import canonicalization_provenance
from protocol.hashes import record_key, shard_header_hash
from protocol.ledger import LedgerEntry
from protocol.rfc3161 import _sha256_of_hash
from protocol.shards import create_shard_header, sign_header, verify_header
from protocol.ssmf import (
    ExistenceProof,
    NonExistenceProof,
    SparseMerkleTree,
    diff_sparse_merkle_trees,
)


class StorageLayer:
    """
    Postgres storage layer for Olympus protocol.

    All operations are append-only and deterministic.
    """

    def __init__(self, connection_string: str):
        """
        Initialize storage layer.

        Args:
            connection_string: Postgres connection string
        """
        self.connection_string = connection_string

    def _get_connection(self) -> psycopg.Connection[dict[str, Any]]:
        """
        Get a database connection with autocommit disabled (transaction mode).

        psycopg3 behavior:
        - autocommit=False (default): connection starts in transaction mode
        - context manager (`with conn:`) ensures rollback on exception
        - must call conn.commit() explicitly to finalize
        - row_factory=dict_row makes all cursors return dicts by default

        Returns:
            Connection in transaction mode with dict row factory
        """
        connection: psycopg.Connection[dict[str, Any]] = psycopg.connect(
            self.connection_string, autocommit=False, row_factory=dict_row
        )
        return connection

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

    def append_record(
        self,
        shard_id: str,
        record_type: str,
        record_id: str,
        version: int,
        value_hash: bytes,
        signing_key: nacl.signing.SigningKey,
        canonicalization: dict[str, Any] | None = None,
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

        Returns:
            Tuple of (root_hash, proof, header, signature, ledger_entry)
        """
        if len(value_hash) != 32:
            raise ValueError(f"Value hash must be 32 bytes, got {len(value_hash)}")

        # Generate record key
        key = record_key(record_type, record_id, version)

        # BEGIN TRANSACTION (implicit via context manager)
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
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
                    SELECT header_hash FROM shard_headers
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
            header = create_shard_header(
                shard_id=shard_id,
                root_hash=root_hash,
                timestamp=ts,
                previous_header_hash=prev_header_hash,
            )

            # Sign header
            signature = sign_header(header, signing_key)
            pubkey = signing_key.verify_key.encode()

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
            ledger_payload = {
                "ts": ts,
                "record_hash": record_hash_hex,
                "shard_id": shard_id,
                "shard_root": shard_root_hex,
                "canonicalization": canonicalization,
                "prev_entry_hash": prev_entry_hash,
            }

            # Compute entry hash using canonical JSON
            from protocol.hashes import LEDGER_PREFIX, blake3_hash

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

    def get_root_diff(self, shard_id: str, from_seq: int, to_seq: int) -> dict[str, Any]:
        """
        Compare two historical shard states reconstructed from header timestamps.

        Args:
            shard_id: Shard identifier
            from_seq: Baseline shard header sequence
            to_seq: Target shard header sequence

        Returns:
            Root hashes and leaf-level additions, changes, and removals

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

            from_tree = self._load_tree_state(cur, shard_id, up_to_ts=from_header["ts"])
            to_tree = self._load_tree_state(cur, shard_id, up_to_ts=to_header["ts"])
            diff = diff_sparse_merkle_trees(from_tree, to_tree)

            return {
                "from_root_hash": bytes(from_header["root"]).hex(),
                "to_root_hash": bytes(to_header["root"]).hex(),
                "added": [entry.to_dict() for entry in diff["added"]],
                "changed": [entry.to_dict() for entry in diff["changed"]],
                "removed": [entry.to_dict() for entry in diff["removed"]],
            }

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
        Persist tree nodes to database.

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

            # Check if node already exists before inserting
            cur.execute(
                """
                SELECT 1 FROM smt_nodes
                WHERE shard_id = %s AND level = %s AND index = %s
                """,
                (shard_id, level, path_bytes),
            )

            if cur.fetchone() is None:
                # Node doesn't exist, insert it
                cur.execute(
                    """
                    INSERT INTO smt_nodes (shard_id, level, index, hash, ts)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (shard_id, level, path_bytes, hash_value, datetime.now(timezone.utc)),
                )

    def _encode_path(self, path: tuple[int, ...]) -> bytes:
        """
        Encode path tuple as bytes.

        Args:
            path: Tuple of 0s and 1s

        Returns:
            Bytes representation
        """
        # Simple encoding: each bit becomes a byte (0 or 1)
        # This is inefficient but maximally clear and deterministic
        return bytes(path)
