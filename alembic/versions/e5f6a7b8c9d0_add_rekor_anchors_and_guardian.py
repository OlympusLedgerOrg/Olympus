"""Add rekor_anchors and quorum_certificate tables for Guardian replication

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "e5f6a7b8c9d0"
down_revision: str | Sequence[str] | None = "d4e5f6a7b8c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "rekor_anchors" not in tables:
        op.create_table(
            "rekor_anchors",
            sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
            sa.Column("shard_id", sa.Text(), nullable=False),
            sa.Column("shard_seq", sa.BigInteger(), nullable=False),
            sa.Column("root_hash", sa.LargeBinary(), nullable=False),
            sa.Column("rekor_uuid", sa.Text(), nullable=True),
            sa.Column("rekor_index", sa.BigInteger(), nullable=True),
            sa.Column(
                "anchored_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("NOW()"),
            ),
            sa.Column(
                "status",
                sa.Text(),
                nullable=False,
                server_default=sa.text("'pending'"),
            ),
            sa.CheckConstraint(
                "octet_length(root_hash) = 32", name="rekor_anchors_root_hash_length"
            ),
        )

    indexes = {ix["name"] for ix in sa.inspect(bind).get_indexes("rekor_anchors")}
    if "ix_rekor_anchors_shard_id_seq" not in indexes:
        op.create_index(
            "ix_rekor_anchors_shard_id_seq",
            "rekor_anchors",
            ["shard_id", "shard_seq"],
        )
    if "ix_rekor_anchors_status" not in indexes:
        op.create_index(
            "ix_rekor_anchors_status",
            "rekor_anchors",
            ["status"],
        )

    # shard_headers is owned by storage/postgres_schema.py, not this Alembic chain.
    # That core schema already creates quorum_certificate, so only alter if the table
    # exists and the column is genuinely missing.
    tables = set(sa.inspect(bind).get_table_names())
    if "shard_headers" in tables:
        columns = {c["name"] for c in sa.inspect(bind).get_columns("shard_headers")}
        if "quorum_certificate" not in columns:
            op.add_column(
                "shard_headers",
                sa.Column("quorum_certificate", sa.Text(), nullable=True),
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "shard_headers" in tables:
        columns = {c["name"] for c in inspector.get_columns("shard_headers")}
        if "quorum_certificate" in columns:
            op.drop_column("shard_headers", "quorum_certificate")

    if "rekor_anchors" in tables:
        indexes = {ix["name"] for ix in inspector.get_indexes("rekor_anchors")}
        if "ix_rekor_anchors_status" in indexes:
            op.drop_index("ix_rekor_anchors_status", table_name="rekor_anchors")
        if "ix_rekor_anchors_shard_id_seq" in indexes:
            op.drop_index("ix_rekor_anchors_shard_id_seq", table_name="rekor_anchors")
        op.drop_table("rekor_anchors")
