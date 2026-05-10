"""Add unique index on doc_commits.doc_hash

Revision ID: d4e5f6a7b8c9
Revises: c1d2e3f4a5b6
"""

from sqlalchemy import inspect

from alembic import op


revision = "d4e5f6a7b8c9"
down_revision = "c1d2e3f4a5b6"
branch_labels = None
depends_on = None


INDEX_NAME = "ix_doc_commits_doc_hash_unique"
TABLE_NAME = "doc_commits"


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)

    tables = set(inspector.get_table_names())
    if TABLE_NAME not in tables:
        return

    indexes = {index["name"] for index in inspector.get_indexes(TABLE_NAME)}
    if INDEX_NAME in indexes:
        return

    op.create_index(
        INDEX_NAME,
        TABLE_NAME,
        ["doc_hash"],
        unique=True,
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)

    tables = set(inspector.get_table_names())
    if TABLE_NAME not in tables:
        return

    indexes = {index["name"] for index in inspector.get_indexes(TABLE_NAME)}
    if INDEX_NAME not in indexes:
        return

    op.drop_index(INDEX_NAME, table_name=TABLE_NAME)
