"""Add display_id sequence for request IDs.

Revision ID: c1d2e3f4a5b6
Revises: b3c4d5e6f7a8
Create Date: 2026-03-31
"""

from collections.abc import Sequence

from alembic import op

revision: str = "c1d2e3f4a5b6"
down_revision: str | Sequence[str] | None = "b3c4d5e6f7a8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SEQUENCE IF NOT EXISTS display_id_seq START 1 INCREMENT 1")
    # Seed the sequence to the current max to avoid collisions with existing rows
    op.execute(
        """
        SELECT setval(
            'display_id_seq',
            COALESCE(
                (SELECT MAX(CAST(SPLIT_PART(display_id, '-', 2) AS INTEGER))
                 FROM public_records_requests
                 WHERE display_id LIKE 'OLY-%'),
                0
            )
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP SEQUENCE IF EXISTS display_id_seq")
