"""
Storage layer for Olympus protocol.

This module provides persistence for the Sparse Merkle State Forest,
shard headers, and ledger entries using Postgres.

All operations are append-only (no UPDATE or DELETE).
"""

import json
from datetime import UTC, datetime
from typing import Any

import nacl.signing
import psycopg
from psycopg.rows import dict_row

from protocol.canonical_json import canonical_json_encode
from protocol.hashes import record_key
from protocol.ledger import LedgerEntry
from protocol.shards import create_shard_header, sign_header
from protocol.ssmf import ExistenceProof, NonExistenceProof, SparseMerkleTree


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

    def _get_connection(self) -> psycopg.Connection[Any]:
        """
        Get a database connection with autocommit disabled (transaction mode).

        psycopg3 behavior:
        - autocommit=False (default): connection starts in transaction mode
        - context manager (`with conn:`) ensures rollback on exception
        - must call conn.commit() explicitly to finalize

        Returns:
            Connection in transaction mode
        """
        connection: psycopg.Connection[Any] = psycopg.connect(
            self.connection_string,
            autocommit=False
        )
        return connection

    def init_schema(self) -> None:
        """
        Initialize database schema.

        Reads and executes the schema migration SQL.
        All DDL statements execute in a single transaction.
        """
        with open('/home/runner/work/Olympus/Olympus/migrations/001_init_schema.sql') as f:
            schema_sql = f.read()

        # BEGIN TRANSACTION (implicit via context manager)
        with self._get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(schema_sql)
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
        signing_key: nacl.signing.SigningKey
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
                (shard_id, key, version, value_hash, datetime.now(UTC))
            )

            # Insert/update affected nodes
            self._persist_tree_nodes(cur, shard_id, tree)

            # Get previous header
            cur.execute(
                """
                    SELECT header_hash FROM shard_headers
                    WHERE shard_id = %s
                    ORDER BY seq DESC
                    LIMIT 1
                    """,
                (shard_id,)
            )
            prev_row = cur.fetchone()
            prev_header_hash = "" if prev_row is None else bytes(prev_row['header_hash']).hex()

            # Get next sequence number
            cur.execute(
                """
                    SELECT COALESCE(MAX(seq), -1) + 1 as next_seq
                    FROM shard_headers
                    WHERE shard_id = %s
                    """,
                (shard_id,)
            )
            seq_row = cur.fetchone()
            if seq_row is None:
                raise RuntimeError("Failed to compute next shard header sequence")
            seq = seq_row['next_seq']

            # Create shard header
            ts = datetime.now(UTC).isoformat().replace('+00:00', 'Z')
            header = create_shard_header(
                shard_id=shard_id,
                root_hash=root_hash,
                timestamp=ts,
                previous_header_hash=prev_header_hash
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
                    bytes.fromhex(header['header_hash']),
                    bytes.fromhex(signature),
                    pubkey,
                    prev_header_hash,
                    ts
                )
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
                (shard_id,)
            )
            prev_ledger_row = cur.fetchone()
            prev_entry_hash = "" if prev_ledger_row is None else bytes(prev_ledger_row['entry_hash']).hex()

            # Get next ledger sequence number
            cur.execute(
                """
                    SELECT COALESCE(MAX(seq), -1) + 1 as next_seq
                    FROM ledger_entries
                    WHERE shard_id = %s
                    """,
                (shard_id,)
            )
            ledger_row = cur.fetchone()
            if ledger_row is None:
                raise RuntimeError("Failed to compute next ledger sequence")
            ledger_seq = ledger_row['next_seq']

            # Create ledger entry payload
            ledger_payload = {
                "ts": ts,
                "record_hash": record_hash_hex,
                "shard_id": shard_id,
                "shard_root": shard_root_hex,
                "prev_entry_hash": prev_entry_hash
            }

            # Compute entry hash using canonical JSON
            from protocol.hashes import LEDGER_PREFIX, blake3_hash
            canonical_json = canonical_json_encode(ledger_payload)
            entry_hash = blake3_hash([LEDGER_PREFIX, canonical_json.encode('utf-8')])

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
                    bytes.fromhex(prev_entry_hash) if prev_entry_hash else b'',
                    json.dumps(ledger_payload),
                    ts
                )
            )

            # Create LedgerEntry object
            ledger_entry = LedgerEntry(
                ts=ts,
                record_hash=record_hash_hex,
                shard_id=shard_id,
                shard_root=shard_root_hex,
                prev_entry_hash=prev_entry_hash,
                entry_hash=entry_hash.hex()
            )

            # COMMIT TRANSACTION (explicit)
            # All INSERTs succeed atomically or rollback on exception
            conn.commit()

            return root_hash, proof, header, signature, ledger_entry
        # END TRANSACTION (implicit via context manager exit)

    def get_proof(
        self,
        shard_id: str,
        record_type: str,
        record_id: str,
        version: int
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
                (shard_id, key, version)
            )
            row = cur.fetchone()

            if row is None:
                return None

            # Load tree and generate proof
            tree = self._load_tree_state(cur, shard_id)
            return tree.prove_existence(key)

    def get_nonexistence_proof(
        self,
        shard_id: str,
        record_type: str,
        record_id: str,
        version: int
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
                (shard_id, key, version)
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
                (shard_id,)
            )
            row = cur.fetchone()

            if row is None:
                return None

            # Reconstruct header
            # Convert timestamp to ISO 8601 string if it's a datetime object
            ts_value = row['ts']
            if isinstance(ts_value, str):
                timestamp_str = ts_value
            elif isinstance(ts_value, datetime):
                # It's a datetime object from Postgres - convert to ISO 8601 string
                timestamp_str = ts_value.isoformat().replace('+00:00', 'Z')
            else:
                # Unexpected type - raise error for clarity
                raise TypeError(f"Unexpected timestamp type: {type(ts_value).__name__}. Expected str or datetime.")

            header = {
                "shard_id": shard_id,
                "root_hash": bytes(row['root']).hex(),
                "timestamp": timestamp_str,
                "previous_header_hash": row['previous_header_hash'],
                "header_hash": bytes(row['header_hash']).hex()
            }

            return {
                "header": header,
                "signature": bytes(row['sig']).hex(),
                "pubkey": bytes(row['pubkey']).hex(),
                "seq": row['seq']
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
                (shard_id, n)
            )
            rows = cur.fetchall()

            entries = []
            for row in rows:
                payload = row['payload']
                entry = LedgerEntry(
                    ts=payload['ts'],
                    record_hash=payload['record_hash'],
                    shard_id=payload['shard_id'],
                    shard_root=payload['shard_root'],
                    prev_entry_hash=payload['prev_entry_hash'],
                    entry_hash=bytes(row['entry_hash']).hex()
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
            return [row['shard_id'] for row in rows]

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
                (shard_id,)
            )
            row = cur.fetchone()

            if row is None:
                # No headers, so root is valid (empty tree)
                return True

            persisted_root = bytes(row['root'])

            # Recompute root from leaves
            tree = self._load_tree_state(cur, shard_id)
            computed_root = tree.get_root()

            return persisted_root == computed_root

    def _load_tree_state(self, cur: psycopg.Cursor[Any], shard_id: str) -> SparseMerkleTree:
        """
        Load sparse Merkle tree state from database.

        Read-only helper. Must be called within an existing transaction.
        No writes, no commit.

        Args:
            cur: Database cursor
            shard_id: Shard identifier

        Returns:
            SparseMerkleTree with all leaves loaded
        """
        tree = SparseMerkleTree()

        # Load all leaves for this shard
        cur.execute(
            """
            SELECT key, value_hash FROM smt_leaves
            WHERE shard_id = %s
            ORDER BY ts ASC
            """,
            (shard_id,)
        )
        rows = cur.fetchall()

        # Rebuild tree by updating each leaf
        for row in rows:
            key = bytes(row['key'])
            value_hash = bytes(row['value_hash'])
            tree.update(key, value_hash)

        return tree

    def _persist_tree_nodes(self, cur: psycopg.Cursor[Any], shard_id: str, tree: SparseMerkleTree) -> None:
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
                (shard_id, level, path_bytes)
            )

            if cur.fetchone() is None:
                # Node doesn't exist, insert it
                cur.execute(
                    """
                    INSERT INTO smt_nodes (shard_id, level, index, hash, ts)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (shard_id, level, path_bytes, hash_value, datetime.now(UTC))
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
