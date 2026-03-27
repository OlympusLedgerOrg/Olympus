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


def upgrade() -> None:
    op.add_column(
        "key_credentials",
        sa.Column("revocation_commit_id", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("key_credentials", "revocation_commit_id")
