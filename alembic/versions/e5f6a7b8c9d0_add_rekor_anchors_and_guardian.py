"""Add rekor_anchors and quorum_certificate tables for Guardian replication

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-04-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op


revision = "e5f6a7b8c9d0"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add rekor_anchors table and quorum_certificate column to shard_headers."""
    # Create rekor_anchors table for Sigstore Rekor transparency log anchoring
    op.create_table(
        "rekor_anchors",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("shard_id", sa.Text(), nullable=False),
        sa.Column("shard_seq", sa.BigInteger(), nullable=False),
        sa.Column("root_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("rekor_uuid", sa.Text(), nullable=True),
        sa.Column("rekor_index", sa.BigInteger(), nullable=True),
        sa.Column(
            "anchored_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Text(),
            server_default="pending",
            nullable=False,
        ),
    )
    op.create_index(
        "ix_rekor_anchors_shard_id_seq",
        "rekor_anchors",
        ["shard_id", "shard_seq"],
    )
    op.create_index(
        "ix_rekor_anchors_status",
        "rekor_anchors",
        ["status"],
    )

    # Add quorum_certificate column to shard_headers for Guardian replication
    # This stores the JSON-serialized quorum certificate when Guardian mode is enabled
    op.add_column(
        "shard_headers",
        sa.Column("quorum_certificate", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    """Remove rekor_anchors table and quorum_certificate column."""
    op.drop_column("shard_headers", "quorum_certificate")
    op.drop_index("ix_rekor_anchors_status", table_name="rekor_anchors")
    op.drop_index("ix_rekor_anchors_shard_id_seq", table_name="rekor_anchors")
    op.drop_table("rekor_anchors")
