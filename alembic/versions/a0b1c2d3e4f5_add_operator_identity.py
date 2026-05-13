"""Add operators table and extend api_keys with operator identity columns.

Revision ID: a0b1c2d3e4f5
Revises: f6a7b8c9d0e1
Create Date: 2026-05-13

Implements the Ed25519-identity → SBT/role → API-key chain:

  Ed25519 identity (operators.ed25519_public_key)
      ↓
  SBT/role credential (operators.credential_id → key_credentials.id)
      ↓
  API key minted for that operator (api_keys.operator_id → operators.id)
      ↓
  Every request carries operator_id + ed25519_public_key for fast identity lookup

New table:
  ``operators`` — one row per Ed25519 operator identity.

New columns on ``api_keys``:
  ``operator_id``          — FK to operators.id (nullable; NULL = legacy user key)
  ``ed25519_public_key``   — denormalised public key for zero-join identity lookup
  ``credential_id``        — FK to key_credentials.id; the SBT granting this key's role
  ``last_used_at``         — updated on each authenticated DB-lookup request
  ``user_id``              — relaxed to nullable for operator-only keys (no user account)
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "a0b1c2d3e4f5"
down_revision: str | Sequence[str] | None = "f6a7b8c9d0e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── operators ─────────────────────────────────────────────────────────────
    op.create_table(
        "operators",
        sa.Column("id", sa.String(36), primary_key=True),
        # The cryptographic identity.  Hex-encoded 32-byte Ed25519 public key.
        sa.Column("ed25519_public_key", sa.String(64), nullable=False),
        # FK to key_credentials.id — the SBT that grants this operator's role.
        # SET NULL on credential deletion so the operator survives.
        sa.Column(
            "credential_id",
            sa.String(36),
            sa.ForeignKey("key_credentials.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("role", sa.String(64), nullable=False, server_default="node_operator"),
        sa.Column("label", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("activated_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_operators_ed25519_public_key",
        "operators",
        ["ed25519_public_key"],
        unique=True,
    )
    op.create_index("ix_operators_credential_id", "operators", ["credential_id"])

    # ── api_keys: relax user_id to nullable ───────────────────────────────────
    # Operator-only keys have no user account.  Existing rows keep their value.
    op.alter_column("api_keys", "user_id", existing_type=sa.String(36), nullable=True)

    # ── api_keys: operator identity columns ───────────────────────────────────
    op.add_column(
        "api_keys",
        sa.Column(
            "operator_id",
            sa.String(36),
            sa.ForeignKey("operators.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )
    op.create_index("ix_api_keys_operator_id", "api_keys", ["operator_id"])

    op.add_column(
        "api_keys",
        sa.Column("ed25519_public_key", sa.String(64), nullable=True),
    )
    op.create_index("ix_api_keys_ed25519_public_key", "api_keys", ["ed25519_public_key"])

    op.add_column(
        "api_keys",
        sa.Column(
            "credential_id",
            sa.String(36),
            sa.ForeignKey("key_credentials.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_api_keys_credential_id", "api_keys", ["credential_id"])

    op.add_column(
        "api_keys",
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("api_keys", "last_used_at")
    op.drop_index("ix_api_keys_credential_id", table_name="api_keys")
    op.drop_column("api_keys", "credential_id")
    op.drop_index("ix_api_keys_ed25519_public_key", table_name="api_keys")
    op.drop_column("api_keys", "ed25519_public_key")
    op.drop_index("ix_api_keys_operator_id", table_name="api_keys")
    op.drop_column("api_keys", "operator_id")
    op.alter_column("api_keys", "user_id", existing_type=sa.String(36), nullable=False)
    op.drop_index("ix_operators_credential_id", table_name="operators")
    op.drop_index("ix_operators_ed25519_public_key", table_name="operators")
    op.drop_table("operators")
