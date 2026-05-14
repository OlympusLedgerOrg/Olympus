"""add evm_pending_ops table

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-05-13 00:00:00.000000

Queue table for batched EVM on-chain operations (SBT mints and burns).
The batch-flush service (api/services/evm_batch.py) drains this table,
coalescing rows into single mintBatch() / burnBatch() transactions.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op


revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table_name in inspector.get_table_names()


def _has_index(table_name: str, index_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return any(index["name"] == index_name for index in inspector.get_indexes(table_name))


def _create_index_if_missing(index_name: str, table_name: str, columns: list[str]) -> None:
    if not _has_index(table_name, index_name):
        op.create_index(index_name, table_name, columns)


def upgrade() -> None:
    if not _has_table("evm_pending_ops"):
        op.create_table(
            "evm_pending_ops",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("op_type", sa.String(8), nullable=False),
            sa.Column(
                "credential_id",
                sa.String(36),
                sa.ForeignKey("key_credentials.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("ledger_commit_id", sa.String(66), nullable=False),
            sa.Column("token_id", sa.String(78), nullable=False),
            sa.Column("wallet_address", sa.String(42), nullable=True),
            sa.Column("burn_authorization", sa.String(32), nullable=True),
            sa.Column("credential_type", sa.String(64), nullable=True),
            sa.Column("token_uri", sa.Text, nullable=True),
            sa.Column("status", sa.String(12), nullable=False, server_default="pending"),
            sa.Column("queued_at", sa.DateTime, nullable=False),
            sa.Column("submitted_at", sa.DateTime, nullable=True),
            sa.Column("confirmed_at", sa.DateTime, nullable=True),
            sa.Column("batch_tx_hash", sa.String(66), nullable=True),
            sa.Column("error", sa.Text, nullable=True),
        )

    _create_index_if_missing("ix_evm_pending_ops_op_type", "evm_pending_ops", ["op_type"])
    _create_index_if_missing(
        "ix_evm_pending_ops_credential_id", "evm_pending_ops", ["credential_id"]
    )
    _create_index_if_missing("ix_evm_pending_ops_status", "evm_pending_ops", ["status"])
    _create_index_if_missing(
        "ix_evm_pending_ops_batch_tx_hash", "evm_pending_ops", ["batch_tx_hash"]
    )


def downgrade() -> None:
    op.drop_index("ix_evm_pending_ops_batch_tx_hash", table_name="evm_pending_ops")
    op.drop_index("ix_evm_pending_ops_status", table_name="evm_pending_ops")
    op.drop_index("ix_evm_pending_ops_credential_id", table_name="evm_pending_ops")
    op.drop_index("ix_evm_pending_ops_op_type", table_name="evm_pending_ops")
    op.drop_table("evm_pending_ops")
