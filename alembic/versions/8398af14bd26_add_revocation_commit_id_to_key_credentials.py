"""add revocation_commit_id to key_credentials

Revision ID: 8398af14bd26
Revises: 150ed68bf7cc
Create Date: 2026-03-20
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "8398af14bd26"
down_revision: str | Sequence[str] | None = "150ed68bf7cc"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _validate_revision_identifiers() -> None:
    """Keep Alembic's module-level revision identifiers explicit for analyzers."""
    if not isinstance(revision, str):
        raise RuntimeError("Alembic revision must be a string")
    for value in (down_revision, branch_labels, depends_on):
        if value is not None and not isinstance(value, str | Sequence):
            raise RuntimeError("Alembic revision identifier must be a string, sequence, or None")


_validate_revision_identifiers()


def upgrade() -> None:
    op.add_column(
        "key_credentials",
        sa.Column("revocation_commit_id", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("key_credentials", "revocation_commit_id")
