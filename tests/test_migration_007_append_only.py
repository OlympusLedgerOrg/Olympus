"""Smoke test for migration 007 append-only ingestion tables."""

from __future__ import annotations

import os
import secrets
import uuid

import psycopg
import pytest

from storage.postgres import StorageLayer


TEST_DB = os.environ.get("TEST_DATABASE_URL", "")


@pytest.mark.postgres
@pytest.mark.skipif(
    not TEST_DB,
    reason="TEST_DATABASE_URL is not set; skipping PostgreSQL migration smoke tests.",
)
def test_ingestion_tables_reject_updates_and_deletes() -> None:
    """Migration 007 triggers must reject UPDATE and DELETE on ingestion tables."""
    storage = StorageLayer(TEST_DB)
    storage.init_schema()

    batch_id = f"migration-007-{uuid.uuid4()}"
    proof_id = f"proof-{uuid.uuid4()}"

    with storage._get_connection() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO ingestion_batches (batch_id) VALUES (%s)", (batch_id,))
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
            ) VALUES (
                %s, %s, 0, %s, %s, %s, %s, %s, %s, '{}'::jsonb, %s, NOW(), '{}'::jsonb, TRUE
            )
            """,
            (
                proof_id,
                batch_id,
                "test-shard",
                "document",
                "doc1",
                1,
                secrets.token_bytes(32),
                secrets.token_bytes(32),
                secrets.token_bytes(32),
            ),
        )
        # Commit so the rows are visible to the subsequent UPDATE/DELETE tests;
        # without this the connection context manager rolls back the transaction
        # on exit and the trigger never fires (no matching rows to mutate).
        conn.commit()

    with pytest.raises(
        psycopg.errors.ReadOnlySqlTransaction, match=r"ingestion_batches is append-only"
    ):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE ingestion_batches
                SET created_at = NOW()
                WHERE batch_id = %s
                """,
                (batch_id,),
            )

    with pytest.raises(
        psycopg.errors.ReadOnlySqlTransaction, match=r"ingestion_proofs is append-only"
    ):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM ingestion_proofs
                WHERE proof_id = %s
                """,
                (proof_id,),
            )
