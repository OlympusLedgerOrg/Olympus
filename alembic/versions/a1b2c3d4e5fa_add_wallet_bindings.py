"""Add wallet bindings for signing keys.

Revision ID: a1b2c3d4e5fa
Revises: a1b2c3d4e5f9
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "a1b2c3d4e5fa"
down_revision: str | Sequence[str] | None = "a1b2c3d4e5f9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "account_wallet_bindings" not in tables:
        op.create_table(
            "account_wallet_bindings",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("signing_key_id", sa.String(length=36), nullable=False),
            sa.Column("wallet_address", sa.String(length=42), nullable=False),
            sa.Column("nonce", sa.String(length=64), nullable=False),
            sa.Column("challenge_message", sa.String(length=512), nullable=False),
            sa.Column(
                "erc_standard",
                sa.String(length=16),
                nullable=False,
                server_default="ERC-5484",
            ),
            sa.Column("burn_authorization", sa.String(length=32), nullable=False),
            sa.Column(
                "issued_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("NOW()"),
            ),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(
                ["signing_key_id"], ["account_signing_keys.key_id"], ondelete="CASCADE"
            ),
        )

    inspector = sa.inspect(bind)
    indexes = {ix["name"] for ix in inspector.get_indexes("account_wallet_bindings")}
    if "ix_account_wallet_bindings_user_id" not in indexes:
        op.create_index(
            "ix_account_wallet_bindings_user_id", "account_wallet_bindings", ["user_id"]
        )
    if "ix_account_wallet_bindings_signing_key_id" not in indexes:
        op.create_index(
            "ix_account_wallet_bindings_signing_key_id",
            "account_wallet_bindings",
            ["signing_key_id"],
        )
    if "ix_account_wallet_bindings_wallet_address" not in indexes:
        op.create_index(
            "ix_account_wallet_bindings_wallet_address",
            "account_wallet_bindings",
            ["wallet_address"],
        )
    if "ix_account_wallet_bindings_nonce" not in indexes:
        op.create_index(
            "ix_account_wallet_bindings_nonce",
            "account_wallet_bindings",
            ["nonce"],
            unique=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "account_wallet_bindings" not in tables:
        return

    indexes = {ix["name"] for ix in inspector.get_indexes("account_wallet_bindings")}
    for index_name in (
        "ix_account_wallet_bindings_nonce",
        "ix_account_wallet_bindings_wallet_address",
        "ix_account_wallet_bindings_signing_key_id",
        "ix_account_wallet_bindings_user_id",
    ):
        if index_name in indexes:
            op.drop_index(index_name, table_name="account_wallet_bindings")
    op.drop_table("account_wallet_bindings")
