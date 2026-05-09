"""Add display_id sequence for request IDs.

Revision ID: c1d2e3f4a5b6
Revises: b3c4d5e6f7a8
"""

from collections.abc import Sequence

from alembic import op


revision: str = "c1d2e3f4a5b6"
down_revision: str | Sequence[str] | None = "b3c4d5e6f7a8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SEQUENCE IF NOT EXISTS display_id_seq START WITH 1 INCREMENT BY 1")

    # If rows already exist, advance the sequence to the highest OLY-NNNN value.
    # If no rows exist, set sequence to 1 with is_called=false so nextval() returns 1.
    op.execute(
        """
        SELECT setval(
            'display_id_seq',
            GREATEST(
                COALESCE(
                    (SELECT MAX(CAST(SPLIT_PART(display_id, '-', 2) AS INTEGER))
                     FROM public_records_requests
                     WHERE display_id LIKE 'OLY-%%'),
                    1
                ),
                1
            ),
            COALESCE(
                (SELECT MAX(CAST(SPLIT_PART(display_id, '-', 2) AS INTEGER))
                 FROM public_records_requests
                 WHERE display_id LIKE 'OLY-%%'),
                0
            ) > 0
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP SEQUENCE IF EXISTS display_id_seq")
