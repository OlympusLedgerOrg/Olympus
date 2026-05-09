"""create ledger_activities table

Revision ID: a9b8c7d6e5f4
Revises: a1b2c3d4e5f6
Create Date: 2026-05-09
"""

import sqlalchemy as sa

from alembic import op


revision = "a9b8c7d6e5f4"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "ledger_activities" in inspector.get_table_names():
        return

    op.create_table(
        "ledger_activities",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activity_type", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("related_commit_id", sa.String(length=128), nullable=True),
        sa.Column("request_id", sa.String(length=36), nullable=True),
        sa.Column("details_json", sa.Text(), nullable=True),
        sa.Column("error_help_text", sa.Text(), nullable=True),
    )

    op.create_index(
        "ix_ledger_activities_timestamp",
        "ledger_activities",
        ["timestamp"],
        unique=False,
    )
    op.create_index(
        "ix_ledger_activities_activity_type",
        "ledger_activities",
        ["activity_type"],
        unique=False,
    )
    op.create_index(
        "ix_ledger_activities_related_commit_id",
        "ledger_activities",
        ["related_commit_id"],
        unique=False,
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "ledger_activities" not in inspector.get_table_names():
        return

    indexes = {ix["name"] for ix in inspector.get_indexes("ledger_activities")}

    if "ix_ledger_activities_related_commit_id" in indexes:
        op.drop_index("ix_ledger_activities_related_commit_id", table_name="ledger_activities")
    if "ix_ledger_activities_activity_type" in indexes:
        op.drop_index("ix_ledger_activities_activity_type", table_name="ledger_activities")
    if "ix_ledger_activities_timestamp" in indexes:
        op.drop_index("ix_ledger_activities_timestamp", table_name="ledger_activities")

    op.drop_table("ledger_activities")
