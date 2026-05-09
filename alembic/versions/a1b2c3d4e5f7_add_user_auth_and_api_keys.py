"""Add password_hash to users and create api_keys table.

Revision ID: a1b2c3d4e5f7
Revises: f6a7b8c9d0e1
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "a1b2c3d4e5f7"
down_revision: str | Sequence[str] | None = "f6a7b8c9d0e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "users" not in tables:
        op.create_table(
            "users",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("email", sa.String(length=320), nullable=False),
            sa.Column("password_hash", sa.String(length=256), nullable=True),
            sa.Column("role", sa.String(length=32), nullable=False, server_default="user"),
            sa.Column("plan", sa.String(length=32), nullable=False, server_default="free"),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("NOW()"),
            ),
        )
        op.create_index("ix_users_email", "users", ["email"], unique=True)
    else:
        columns = {c["name"] for c in inspector.get_columns("users")}

        if "email" not in columns:
            op.add_column("users", sa.Column("email", sa.String(length=320), nullable=True))
            op.execute(
                sa.text(
                    "UPDATE users SET email = 'legacy+' || id || '@users.local' WHERE email IS NULL"
                )
            )
            op.alter_column(
                "users",
                "email",
                existing_type=sa.String(length=320),
                nullable=False,
            )
        if "password_hash" not in columns:
            op.add_column("users", sa.Column("password_hash", sa.String(length=256), nullable=True))
        if "role" not in columns:
            op.add_column(
                "users",
                sa.Column("role", sa.String(length=32), nullable=False, server_default="user"),
            )
        if "plan" not in columns:
            op.add_column(
                "users",
                sa.Column("plan", sa.String(length=32), nullable=False, server_default="free"),
            )
        if "created_at" not in columns:
            op.add_column(
                "users",
                sa.Column(
                    "created_at",
                    sa.DateTime(timezone=True),
                    nullable=False,
                    server_default=sa.text("NOW()"),
                ),
            )

        indexes = {ix["name"] for ix in inspector.get_indexes("users")}
        if "ix_users_email" not in indexes:
            op.create_index("ix_users_email", "users", ["email"], unique=True)

    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "api_keys" not in tables:
        op.create_table(
            "api_keys",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("key_hash", sa.String(length=64), nullable=False),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("scopes", sa.Text(), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("NOW()"),
            ),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        )

    inspector = sa.inspect(bind)
    indexes = {ix["name"] for ix in inspector.get_indexes("api_keys")}

    if "ix_api_keys_user_id" not in indexes:
        op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])

    if "ix_api_keys_key_hash" not in indexes:
        op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "api_keys" in tables:
        indexes = {ix["name"] for ix in inspector.get_indexes("api_keys")}
        if "ix_api_keys_key_hash" in indexes:
            op.drop_index("ix_api_keys_key_hash", table_name="api_keys")
        if "ix_api_keys_user_id" in indexes:
            op.drop_index("ix_api_keys_user_id", table_name="api_keys")
        op.drop_table("api_keys")

    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "users" in tables:
        indexes = {ix["name"] for ix in inspector.get_indexes("users")}
        if "ix_users_email" in indexes:
            op.drop_index("ix_users_email", table_name="users")
        op.drop_table("users")
