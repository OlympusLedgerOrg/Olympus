"""
Proof retrieval mixin (existence, non-existence, ingestion).

Internal to the storage package (_pg_* convention).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from psycopg.rows import dict_row

from protocol.hashes import global_key, record_key
from protocol.ssmf import ExistenceProof, NonExistenceProof


class _ProofsMixin:
    """SMT existence/non-existence proofs and ingestion proof persistence."""

    DEFAULT_FLUSH_BATCH_SIZE: int

    def get_proof(
        self, shard_id: str, record_type: str, record_id: str, version: int
    ) -> ExistenceProof | None:
        """Get existence proof for a record.

        Returns:
            Existence proof if record exists, None otherwise.
        """
        rec_key = record_key(record_type, record_id, version)
        key = global_key(shard_id, rec_key)

        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                    SELECT value_hash, parser_id, canonical_parser_version
                    FROM smt_leaves
                    WHERE key = %s AND version = %s
                    """,
                (key, version),
            )
            row = cur.fetchone()

            if row is None:
                return None

            value_hash_bytes = bytes(row["value_hash"])
            siblings = self._get_proof_path(cur, key)  # type: ignore[attr-defined]
            root_hash = self._get_current_global_root(cur)  # type: ignore[attr-defined]
            return ExistenceProof(
                key=key,
                value_hash=value_hash_bytes,
                parser_id=row["parser_id"],
                canonical_parser_version=row["canonical_parser_version"],
                siblings=siblings,
                root_hash=root_hash,
            )

    def get_nonexistence_proof(
        self, shard_id: str, record_type: str, record_id: str, version: int
    ) -> NonExistenceProof:
        """Get non-existence proof for a record.

        Raises:
            ValueError: If record exists.
        """
        rec_key = record_key(record_type, record_id, version)
        key = global_key(shard_id, rec_key)

        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                    SELECT 1 FROM smt_leaves
                    WHERE key = %s AND version = %s
                    """,
                (key, version),
            )
            if cur.fetchone() is not None:
                raise ValueError("Record exists, cannot generate non-existence proof")

            siblings = self._get_proof_path(cur, key)  # type: ignore[attr-defined]
            root_hash = self._get_current_global_root(cur)  # type: ignore[attr-defined]
            return NonExistenceProof(
                key=key,
                siblings=siblings,
                root_hash=root_hash,
            )

    def store_ingestion_batch(self, batch_id: str, records: list[dict[str, Any]]) -> None:
        """Persist proof_id-to-record mappings for ingestion durability."""
        if not records:
            return

        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                    INSERT INTO ingestion_batches (batch_id)
                    VALUES (%s)
                    ON CONFLICT (batch_id) DO NOTHING
                """,
                (batch_id,),
            )

            for row_batch in self._iter_batches(  # type: ignore[attr-defined]
                self._iter_ingestion_proof_rows(batch_id, records),  # type: ignore[attr-defined]
                self.DEFAULT_FLUSH_BATCH_SIZE,
            ):
                cur.executemany(
                    """
                        INSERT INTO ingestion_proofs (
                            proof_id, batch_id, batch_index, shard_id,
                            record_type, record_id, version, content_hash,
                            merkle_root, merkle_proof, ledger_entry_hash,
                            ts, canonicalization, persisted
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (proof_id) DO NOTHING
                    """,
                    row_batch,
                )

            conn.commit()

    def get_ingestion_proof(self, proof_id: str) -> dict[str, Any] | None:
        """Retrieve a persisted ingestion proof mapping by proof_id."""
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                    SELECT
                        proof_id, batch_id, batch_index, shard_id, record_type,
                        record_id, version, content_hash, merkle_root, merkle_proof,
                        ledger_entry_hash, ts, canonicalization, persisted
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

        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
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

    def get_ingestion_proof_by_record_identity(
        self, shard_id: str, record_type: str, record_id: str, version: int
    ) -> dict[str, Any] | None:
        """Retrieve a persisted ingestion proof by immutable record coordinates."""
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                    SELECT proof_id
                    FROM ingestion_proofs
                    WHERE shard_id = %s
                      AND record_type = %s
                      AND record_id = %s
                      AND version = %s
                    ORDER BY created_at ASC
                    LIMIT 1
                """,
                (shard_id, record_type, record_id, version),
            )
            row = cur.fetchone()

        if row is None:
            return None

        return self.get_ingestion_proof(row["proof_id"])
