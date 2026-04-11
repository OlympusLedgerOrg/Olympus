"""E2E integration tests for the ``doc_commits`` unique-hash constraint.

These tests run against a live PostgreSQL database. They are marked with
``@pytest.mark.postgres`` and are skipped when ``TEST_DATABASE_URL`` is
not set.

CI wires a Postgres 16 service container and sets the env var, so these
tests run automatically in the ``integration-postgres`` workflow job.
"""

from __future__ import annotations

import os

import psycopg
import pytest


TEST_DB = os.environ.get("TEST_DATABASE_URL", "")


@pytest.mark.postgres
@pytest.mark.skipif(
    not TEST_DB,
    reason="TEST_DATABASE_URL is not set; skipping PostgreSQL integration tests.",
)
class TestDocCommitsUniqueHash:
    """Verify that the ``ix_doc_commits_doc_hash_unique`` index prevents
    duplicate ``doc_hash`` values and that conflict handling works.
    """

    # A deterministic fake BLAKE3 hash (64 hex chars)
    _DOC_HASH = "a" * 64
    _COMMIT_ID_1 = "0x" + "b" * 64
    _COMMIT_ID_2 = "0x" + "c" * 64

    @pytest.fixture(autouse=True)
    def _ensure_table(self) -> None:
        """Create the ``doc_commits`` table (if absent) with the unique index.

        This fixture is self-contained — it does not rely on Alembic or
        SQLAlchemy model metadata so it works on a bare Postgres instance
        without any prior migration.
        """
        with psycopg.connect(TEST_DB) as conn, conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS doc_commits (
                    id          VARCHAR(36)  PRIMARY KEY,
                    request_id  VARCHAR(36),
                    doc_hash    VARCHAR(64)  NOT NULL,
                    commit_id   VARCHAR(66)  NOT NULL UNIQUE,
                    epoch_timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
                    shard_id    VARCHAR(32)  NOT NULL DEFAULT '0x4F3A',
                    merkle_root VARCHAR(64),
                    zk_proof    TEXT,
                    embargo_until TIMESTAMP,
                    is_multi_recipient BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)
            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS ix_doc_commits_doc_hash_unique
                ON doc_commits (doc_hash)
            """)
            conn.commit()

    @pytest.fixture(autouse=True)
    def _cleanup(self) -> None:
        """Remove test rows after each test."""
        yield  # type: ignore[misc]
        with psycopg.connect(TEST_DB) as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM doc_commits WHERE doc_hash = %s",
                (self._DOC_HASH,),
            )
            conn.commit()

    def test_insert_unique_doc_hash(self) -> None:
        """A single insert should succeed."""
        with psycopg.connect(TEST_DB) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO doc_commits (id, doc_hash, commit_id) VALUES (%s, %s, %s)",
                ("id-1", self._DOC_HASH, self._COMMIT_ID_1),
            )
            conn.commit()

            cur.execute(
                "SELECT commit_id FROM doc_commits WHERE doc_hash = %s",
                (self._DOC_HASH,),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] == self._COMMIT_ID_1

    def test_duplicate_doc_hash_raises_unique_violation(self) -> None:
        """A second insert with the same ``doc_hash`` must raise a
        ``UniqueViolation`` error.
        """
        with psycopg.connect(TEST_DB) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO doc_commits (id, doc_hash, commit_id) VALUES (%s, %s, %s)",
                ("id-1", self._DOC_HASH, self._COMMIT_ID_1),
            )
            conn.commit()

        with pytest.raises(psycopg.errors.UniqueViolation):
            with psycopg.connect(TEST_DB) as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO doc_commits (id, doc_hash, commit_id) VALUES (%s, %s, %s)",
                    ("id-2", self._DOC_HASH, self._COMMIT_ID_2),
                )

    def test_on_conflict_do_nothing(self) -> None:
        """``INSERT … ON CONFLICT DO NOTHING`` must silently skip the
        duplicate without raising.
        """
        with psycopg.connect(TEST_DB) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO doc_commits (id, doc_hash, commit_id) VALUES (%s, %s, %s)",
                ("id-1", self._DOC_HASH, self._COMMIT_ID_1),
            )
            conn.commit()

            # The upsert variant used in ingestion.py
            cur.execute(
                """
                INSERT INTO doc_commits (id, doc_hash, commit_id)
                VALUES (%s, %s, %s)
                ON CONFLICT (doc_hash) DO NOTHING
                RETURNING commit_id
                """,
                ("id-2", self._DOC_HASH, self._COMMIT_ID_2),
            )
            returned = cur.fetchone()
            assert returned is None, "RETURNING should yield no rows on conflict"
            conn.commit()

            # Verify only the original row exists
            cur.execute(
                "SELECT commit_id FROM doc_commits WHERE doc_hash = %s",
                (self._DOC_HASH,),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] == self._COMMIT_ID_1
