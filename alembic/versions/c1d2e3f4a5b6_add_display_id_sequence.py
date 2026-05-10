"""Add display_id sequence for request IDs.

Revision ID: c1d2e3f4a5b6
Revises: b3c4d5e6f7a8
"""

from sqlalchemy import inspect

from alembic import op


revision = "c1d2e3f4a5b6"
down_revision = "b3c4d5e6f7a8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())

    op.execute("CREATE SEQUENCE IF NOT EXISTS display_id_seq START WITH 1 INCREMENT BY 1")

    if "public_records_requests" not in tables:
        # Older/local DBs may not have this table at this point in the chain.
        # Keep the sequence at 1 and let later app/table logic use it.
        return

    columns = {column["name"] for column in inspector.get_columns("public_records_requests")}

    if "display_id" not in columns:
        return

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
