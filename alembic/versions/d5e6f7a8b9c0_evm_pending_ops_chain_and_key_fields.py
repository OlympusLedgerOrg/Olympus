"""add chain_id, contract_address, holder_key_id to evm_pending_ops

Revision ID: d5e6f7a8b9c0
Revises: c3d4e5f6a7b8
Create Date: 2026-05-13 00:00:00.000000

Extends the evm_pending_ops queue table with the fields required for
semantic batch grouping (chain_id, contract_address) and the Ed25519
keyId that is passed to OlympusCredential.mintBatch() for
duplicate-active-key enforcement on-chain (holder_key_id).

Migration strategy:
    • Adds three nullable columns so existing rows (if any) receive NULL.
    • A post-migration data backfill is NOT required: all new rows are
      written by queue_mint() / queue_burn() which supply these fields.
    • The down migration drops the columns but leaves the table intact.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op


revision = "d5e6f7a8b9c0"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def _column_names(table_name: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {column["name"] for column in inspector.get_columns(table_name)}


def _has_index(table_name: str, index_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return any(index["name"] == index_name for index in inspector.get_indexes(table_name))


def _create_index_if_missing(index_name: str, table_name: str, columns: list[str]) -> None:
    if not _has_index(table_name, index_name):
        op.create_index(index_name, table_name, columns)


def upgrade() -> None:
    columns = _column_names("evm_pending_ops")

    # chain_id defaults to 1 (Ethereum mainnet) for any legacy rows.
    if "chain_id" not in columns:
        op.add_column(
            "evm_pending_ops",
            sa.Column("chain_id", sa.Integer, nullable=False, server_default="1"),
        )
    if "contract_address" not in columns:
        op.add_column(
            "evm_pending_ops",
            sa.Column("contract_address", sa.String(42), nullable=True),
        )
    # holder_key_id: 64 hex chars (32-byte Ed25519 pubkey, no 0x prefix).
    if "holder_key_id" not in columns:
        op.add_column(
            "evm_pending_ops",
            sa.Column("holder_key_id", sa.String(64), nullable=True),
        )

    _create_index_if_missing("ix_evm_pending_ops_chain_id", "evm_pending_ops", ["chain_id"])
    _create_index_if_missing(
        "ix_evm_pending_ops_contract_address", "evm_pending_ops", ["contract_address"]
    )
    # Composite index that matches the GROUP BY used in flush queries.
    _create_index_if_missing(
        "ix_evm_pending_ops_chain_contract",
        "evm_pending_ops",
        ["chain_id", "contract_address"],
    )


def downgrade() -> None:
    op.drop_index("ix_evm_pending_ops_chain_contract", table_name="evm_pending_ops")
    op.drop_index("ix_evm_pending_ops_contract_address", table_name="evm_pending_ops")
    op.drop_index("ix_evm_pending_ops_chain_id", table_name="evm_pending_ops")
    op.drop_column("evm_pending_ops", "holder_key_id")
    op.drop_column("evm_pending_ops", "contract_address")
    op.drop_column("evm_pending_ops", "chain_id")
