"""add display_id index column to ledger_activities (C2 full-table-scan fix)

Revision ID: b3c4d5e6f7a8
Revises: a9b8c7d6e5f4
Create Date: 2026-03-29

Adds an indexed ``display_id`` column to ``ledger_activities`` so that
OLY-NNNN lookups in ``verify_by_commit_id`` can use an index scan.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "b3c4d5e6f7a8"
down_revision: str | Sequence[str] | None = "a9b8c7d6e5f4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "ledger_activities" not in inspector.get_table_names():
        raise RuntimeError(
            "ledger_activities table is missing; "
            "run/create migration a9b8c7d6e5f4_create_ledger_activities first"
        )

    columns = {c["name"] for c in inspector.get_columns("ledger_activities")}
    if "display_id" not in columns:
        op.add_column(
            "ledger_activities",
            sa.Column("display_id", sa.String(length=32), nullable=True),
        )

    indexes = {ix["name"] for ix in inspector.get_indexes("ledger_activities")}
    if "ix_ledger_activities_display_id" not in indexes:
        op.create_index(
            "ix_ledger_activities_display_id",
            "ledger_activities",
            ["display_id"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "ledger_activities" not in inspector.get_table_names():
        return

    indexes = {ix["name"] for ix in inspector.get_indexes("ledger_activities")}
    if "ix_ledger_activities_display_id" in indexes:
        op.drop_index("ix_ledger_activities_display_id", table_name="ledger_activities")

    columns = {c["name"] for c in inspector.get_columns("ledger_activities")}
    if "display_id" in columns:
        op.drop_column("ledger_activities", "display_id")
