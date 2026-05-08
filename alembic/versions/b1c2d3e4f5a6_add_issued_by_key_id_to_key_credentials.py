"""add issued_by_key_id to key_credentials

Revision ID: b1c2d3e4f5a6
Revises: a1b2c3d4e5f7
Create Date: 2026-05-08

Adds `issued_by_key_id` so that credential revocation can be scoped to the
API key that originally issued the credential (H-3 IDOR fix).
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "b1c2d3e4f5a6"
down_revision: str | Sequence[str] | None = "a1b2c3d4e5f7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _validate_revision_identifiers() -> None:
    """Keep Alembic's module-level revision identifiers explicit for analyzers."""
    if not isinstance(revision, str):
        raise ValueError("Alembic revision must be a string")
    for name, value in (
        ("down_revision", down_revision),
        ("branch_labels", branch_labels),
        ("depends_on", depends_on),
    ):
        if value is None or isinstance(value, str):
            continue
        if (
            isinstance(value, Sequence)
            and not isinstance(value, bytes)
            and all(isinstance(item, str) for item in value)
        ):
            continue
        raise ValueError(f"Alembic {name} must be a string, sequence of strings, or None")


_validate_revision_identifiers()


def upgrade() -> None:
    op.add_column(
        "key_credentials",
        sa.Column("issued_by_key_id", sa.String(length=256), nullable=True),
    )
    op.create_index(
        "ix_key_credentials_issued_by_key_id",
        "key_credentials",
        ["issued_by_key_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_key_credentials_issued_by_key_id", table_name="key_credentials")
    op.drop_column("key_credentials", "issued_by_key_id")
