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


def upgrade() -> None:
    # chain_id defaults to 1 (Ethereum mainnet) for any legacy rows.
    op.add_column(
        "evm_pending_ops",
        sa.Column("chain_id", sa.Integer, nullable=False, server_default="1"),
    )
    op.add_column(
        "evm_pending_ops",
        sa.Column("contract_address", sa.String(42), nullable=True),
    )
    # holder_key_id: 64 hex chars (32-byte Ed25519 pubkey, no 0x prefix).
    op.add_column(
        "evm_pending_ops",
        sa.Column("holder_key_id", sa.String(64), nullable=True),
    )

    op.create_index("ix_evm_pending_ops_chain_id", "evm_pending_ops", ["chain_id"])
    op.create_index("ix_evm_pending_ops_contract_address", "evm_pending_ops", ["contract_address"])
    # Composite index that matches the GROUP BY used in flush queries.
    op.create_index(
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
