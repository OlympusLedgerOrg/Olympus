"""Add expires_at to api_keys.

Revision ID: c7d8e9f0a1b2
Revises: b1c2d3e4f5a6
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "c7d8e9f0a1b2"
down_revision: str | Sequence[str] | None = "b1c2d3e4f5a6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "api_keys" not in tables:
        return

    columns = {c["name"] for c in inspector.get_columns("api_keys")}
    if "expires_at" in columns:
        return

    op.add_column(
        "api_keys",
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("'2099-01-01 00:00:00'"),
        ),
    )
    op.alter_column("api_keys", "expires_at", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "api_keys" not in tables:
        return

    columns = {c["name"] for c in inspector.get_columns("api_keys")}
    if "expires_at" in columns:
        op.drop_column("api_keys", "expires_at")
