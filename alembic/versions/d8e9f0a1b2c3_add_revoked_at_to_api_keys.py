"""Add revoked_at to api_keys.

Revision ID: d8e9f0a1b2c3
Revises: c7d8e9f0a1b2
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "d8e9f0a1b2c3"
down_revision: str | Sequence[str] | None = "c7d8e9f0a1b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "api_keys" not in tables:
        return

    columns = {c["name"] for c in inspector.get_columns("api_keys")}
    if "revoked_at" not in columns:
        op.add_column("api_keys", sa.Column("revoked_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "api_keys" not in tables:
        return

    columns = {c["name"] for c in inspector.get_columns("api_keys")}
    if "revoked_at" in columns:
        op.drop_column("api_keys", "revoked_at")
