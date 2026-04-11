"""Add unique index on doc_commits.doc_hash

Revision ID: d4e5f6a7b8c9
Revises: c1d2e3f4a5b6
Create Date: 2026-04-11
"""
from __future__ import annotations

from alembic import op


revision = "d4e5f6a7b8c9"
down_revision = "c1d2e3f4a5b6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # CONCURRENTLY cannot run inside a transaction block; Alembic wraps
    # each migration in BEGIN/COMMIT, so use a plain CREATE UNIQUE INDEX.
    # For zero-downtime on a live database use a separate psql session with
    # CREATE UNIQUE INDEX CONCURRENTLY before running alembic upgrade.
    op.create_index(
        "ix_doc_commits_doc_hash_unique",
        "doc_commits",
        ["doc_hash"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_doc_commits_doc_hash_unique", table_name="doc_commits")
