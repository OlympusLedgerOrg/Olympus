"""add display_id index column to ledger_activities (C2 full-table-scan fix)

Revision ID: b3c4d5e6f7a8
Revises: a1b2c3d4e5f6
Create Date: 2026-03-29

Adds an indexed ``display_id`` column to ``ledger_activities`` so that
OLY-NNNN lookups in ``verify_by_commit_id`` can use an index scan (O(log n))
instead of a full-table scan with in-memory JSON parsing (O(n)).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b3c4d5e6f7a8"
down_revision: str | Sequence[str] | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "ledger_activities",
        sa.Column("display_id", sa.String(length=32), nullable=True),
    )
    op.create_index(
        "ix_ledger_activities_display_id",
        "ledger_activities",
        ["display_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_ledger_activities_display_id", table_name="ledger_activities")
    op.drop_column("ledger_activities", "display_id")
