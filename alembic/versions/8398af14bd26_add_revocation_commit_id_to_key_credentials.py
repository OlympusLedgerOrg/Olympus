"""add revocation_commit_id to key_credentials

Revision ID: 8398af14bd26
Revises: 150ed68bf7cc
Create Date: 2026-05-09
"""

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op


revision = "8398af14bd26"
down_revision = "150ed68bf7cc"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)

    if "key_credentials" not in inspector.get_table_names():
        # Older/local DBs may not have key_credentials yet at this point
        # in the migration chain. Later migrations can create/populate it.
        return

    columns = {column["name"] for column in inspector.get_columns("key_credentials")}

    if "revocation_commit_id" not in columns:
        op.add_column(
            "key_credentials",
            sa.Column("revocation_commit_id", sa.String(length=64), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)

    if "key_credentials" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("key_credentials")}

    if "revocation_commit_id" in columns:
        op.drop_column("key_credentials", "revocation_commit_id")
