"""Add account signing keys table.

Revision ID: a1b2c3d4e5f9
Revises: a1b2c3d4e5f8
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "a1b2c3d4e5f9"
down_revision: str | Sequence[str] | None = "a1b2c3d4e5f8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "account_signing_keys" not in tables:
        op.create_table(
            "account_signing_keys",
            sa.Column("key_id", sa.String(length=36), primary_key=True),
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("public_key", sa.String(length=64), nullable=False),
            sa.Column("label", sa.String(length=128), nullable=False),
            sa.Column("purpose", sa.String(length=64), nullable=False, server_default="dataset"),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("NOW()"),
            ),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_by_key_id", sa.String(length=256), nullable=True),
            sa.Column("replaced_by_key_id", sa.String(length=36), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        )

    inspector = sa.inspect(bind)
    indexes = {ix["name"] for ix in inspector.get_indexes("account_signing_keys")}
    if "ix_account_signing_keys_user_id" not in indexes:
        op.create_index("ix_account_signing_keys_user_id", "account_signing_keys", ["user_id"])
    if "ix_account_signing_keys_public_key" not in indexes:
        op.create_index(
            "ix_account_signing_keys_public_key",
            "account_signing_keys",
            ["public_key"],
            unique=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "account_signing_keys" not in tables:
        return

    indexes = {ix["name"] for ix in inspector.get_indexes("account_signing_keys")}
    if "ix_account_signing_keys_public_key" in indexes:
        op.drop_index("ix_account_signing_keys_public_key", table_name="account_signing_keys")
    if "ix_account_signing_keys_user_id" in indexes:
        op.drop_index("ix_account_signing_keys_user_id", table_name="account_signing_keys")
    op.drop_table("account_signing_keys")
