"""E2E integration tests for the ``doc_commits`` unique-hash constraint.

These tests run against a live PostgreSQL database. They are marked with
``@pytest.mark.postgres`` and are skipped when ``TEST_DATABASE_URL`` is
not set.

CI wires a Postgres 16 service container and sets the env var, so these
tests run automatically in the ``integration-postgres`` workflow job.
"""

from __future__ import annotations

import os
import uuid

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
    def _unique_values(self) -> None:
        """Use unique row values so tests are repeat-safe on persistent databases."""
        run_id = uuid.uuid4().hex
        self._id_1 = str(uuid.uuid4())
        self._id_2 = str(uuid.uuid4())
        self._doc_hash = run_id + uuid.uuid4().hex
        self._commit_id_1 = "0x" + uuid.uuid4().hex + uuid.uuid4().hex
        self._commit_id_2 = "0x" + uuid.uuid4().hex + uuid.uuid4().hex
        yield  # type: ignore[misc]
        with psycopg.connect(TEST_DB) as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM doc_commits WHERE id IN (%s, %s)",
                (self._id_1, self._id_2),
            )
            conn.commit()

    def test_insert_unique_doc_hash(self) -> None:
        """A single insert should succeed."""
        with psycopg.connect(TEST_DB) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO doc_commits (id, doc_hash, commit_id) VALUES (%s, %s, %s)",
                (self._id_1, self._doc_hash, self._commit_id_1),
            )
            conn.commit()

            cur.execute(
                "SELECT commit_id FROM doc_commits WHERE doc_hash = %s",
                (self._doc_hash,),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] == self._commit_id_1

    def test_duplicate_doc_hash_raises_unique_violation(self) -> None:
        """A second insert with the same ``doc_hash`` must raise a
        ``UniqueViolation`` error.
        """
        with psycopg.connect(TEST_DB) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO doc_commits (id, doc_hash, commit_id) VALUES (%s, %s, %s)",
                (self._id_1, self._doc_hash, self._commit_id_1),
            )
            conn.commit()

        with pytest.raises(psycopg.errors.UniqueViolation):
            with psycopg.connect(TEST_DB) as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO doc_commits (id, doc_hash, commit_id) VALUES (%s, %s, %s)",
                    (self._id_2, self._doc_hash, self._commit_id_2),
                )

    def test_on_conflict_do_nothing(self) -> None:
        """``INSERT … ON CONFLICT DO NOTHING`` must silently skip the
        duplicate without raising.
        """
        with psycopg.connect(TEST_DB) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO doc_commits (id, doc_hash, commit_id) VALUES (%s, %s, %s)",
                (self._id_1, self._doc_hash, self._commit_id_1),
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
                (self._id_2, self._doc_hash, self._commit_id_2),
            )
            returned = cur.fetchone()
            assert returned is None, "RETURNING should yield no rows on conflict"
            conn.commit()

            # Verify only the original row exists
            cur.execute(
                "SELECT commit_id FROM doc_commits WHERE doc_hash = %s",
                (self._doc_hash,),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] == self._commit_id_1
