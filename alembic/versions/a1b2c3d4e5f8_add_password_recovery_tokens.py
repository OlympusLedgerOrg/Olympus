"""Add password recovery tokens table.

Revision ID: a1b2c3d4e5f8
Revises: b1c2d3e4f5a6
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "a1b2c3d4e5f8"
down_revision: str | Sequence[str] | None = "b1c2d3e4f5a6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "password_recovery_tokens" not in tables:
        op.create_table(
            "password_recovery_tokens",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                # sa.func.now() emits NOW() on PostgreSQL and CURRENT_TIMESTAMP
                # on SQLite — sa.text("NOW()") would break the in-memory SQLite
                # test path.
                server_default=sa.func.now(),
            ),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        )

    inspector = sa.inspect(bind)
    indexes = {ix["name"] for ix in inspector.get_indexes("password_recovery_tokens")}
    if "ix_password_recovery_tokens_user_id" not in indexes:
        op.create_index(
            "ix_password_recovery_tokens_user_id",
            "password_recovery_tokens",
            ["user_id"],
        )
    if "ix_password_recovery_tokens_token_hash" not in indexes:
        op.create_index(
            "ix_password_recovery_tokens_token_hash",
            "password_recovery_tokens",
            ["token_hash"],
            unique=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "password_recovery_tokens" not in tables:
        return

    indexes = {ix["name"] for ix in inspector.get_indexes("password_recovery_tokens")}
    if "ix_password_recovery_tokens_token_hash" in indexes:
        op.drop_index(
            "ix_password_recovery_tokens_token_hash", table_name="password_recovery_tokens"
        )
    if "ix_password_recovery_tokens_user_id" in indexes:
        op.drop_index("ix_password_recovery_tokens_user_id", table_name="password_recovery_tokens")
    op.drop_table("password_recovery_tokens")
