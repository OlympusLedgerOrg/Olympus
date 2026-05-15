"""Olympus-native credential tables and columns.

Adds the infrastructure for chain-agnostic, account-bound, signing-key-bound
credentials that are historically verifiable through the Olympus Merkle/SMT
proof system.

Changes:
  • New table  credential_consents       — Ed25519-signed holder consent artifact
  • New table  credential_ledger_events  — per-event commit_id log (issued/revoked)
  • New column key_credentials.burn_authorization  — chain-agnostic enum string
  • New column key_credentials.holder_account_id   — FK to users (account-bound)
  • New column key_credentials.consent_id          — FK to credential_consents

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5fa
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "b2c3d4e5f6a7"
down_revision: str | Sequence[str] | None = "a1b2c3d4e5fa"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    # ── credential_consents ────────────────────────────────────────────────────
    if "credential_consents" not in existing_tables:
        op.create_table(
            "credential_consents",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "user_id",
                sa.String(36),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "signing_key_id",
                sa.String(36),
                sa.ForeignKey("account_signing_keys.key_id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("credential_type", sa.String(64), nullable=False),
            sa.Column("issuer", sa.String(256), nullable=False),
            sa.Column(
                "burn_authorization",
                sa.String(32),
                nullable=False,
                server_default="issuer_only",
            ),
            sa.Column("consent_payload", sa.Text, nullable=False),
            sa.Column("consent_signature", sa.String(128), nullable=True),
            sa.Column("nonce", sa.String(64), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime,
                nullable=False,
                server_default=sa.text("NOW()"),
            ),
            sa.Column("expires_at", sa.DateTime, nullable=False),
            sa.Column("accepted_at", sa.DateTime, nullable=True),
            sa.Column("revoked_at", sa.DateTime, nullable=True),
        )
        op.create_index("ix_credential_consents_user_id", "credential_consents", ["user_id"])
        op.create_index(
            "ix_credential_consents_signing_key_id",
            "credential_consents",
            ["signing_key_id"],
        )
        op.create_index(
            "ix_credential_consents_nonce", "credential_consents", ["nonce"], unique=True
        )

    # ── credential_ledger_events ───────────────────────────────────────────────
    if "credential_ledger_events" not in existing_tables:
        op.create_table(
            "credential_ledger_events",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "credential_id",
                sa.String(36),
                sa.ForeignKey("key_credentials.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("event_type", sa.String(16), nullable=False),
            sa.Column("ledger_commit_id", sa.String(66), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime,
                nullable=False,
                server_default=sa.text("NOW()"),
            ),
            sa.Column("inclusion_proof", sa.Text, nullable=True),
            sa.Column("smt_root", sa.String(66), nullable=True),
        )
        op.create_index(
            "ix_credential_ledger_events_credential_id",
            "credential_ledger_events",
            ["credential_id"],
        )
        op.create_index(
            "ix_credential_ledger_events_event_type",
            "credential_ledger_events",
            ["event_type"],
        )
        op.create_index(
            "ix_credential_ledger_events_ledger_commit_id",
            "credential_ledger_events",
            ["ledger_commit_id"],
            unique=True,
        )

    # ── key_credentials new columns ────────────────────────────────────────────
    if "key_credentials" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("key_credentials")}

        if "burn_authorization" not in existing_cols:
            op.add_column(
                "key_credentials",
                sa.Column(
                    "burn_authorization",
                    sa.String(32),
                    nullable=False,
                    server_default="issuer_only",
                ),
            )

        if "holder_account_id" not in existing_cols:
            op.add_column(
                "key_credentials",
                sa.Column("holder_account_id", sa.String(36), nullable=True),
            )
            op.create_index(
                "ix_key_credentials_holder_account_id",
                "key_credentials",
                ["holder_account_id"],
            )

        if "consent_id" not in existing_cols:
            op.add_column(
                "key_credentials",
                sa.Column("consent_id", sa.String(36), nullable=True),
            )
            op.create_index(
                "ix_key_credentials_consent_id",
                "key_credentials",
                ["consent_id"],
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    # Drop new columns from key_credentials
    if "key_credentials" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("key_credentials")}
        existing_indexes = {ix["name"] for ix in inspector.get_indexes("key_credentials")}

        for idx in ("ix_key_credentials_consent_id", "ix_key_credentials_holder_account_id"):
            if idx in existing_indexes:
                op.drop_index(idx, table_name="key_credentials")

        for col in ("consent_id", "holder_account_id", "burn_authorization"):
            if col in existing_cols:
                op.drop_column("key_credentials", col)

    # Drop credential_ledger_events
    if "credential_ledger_events" in existing_tables:
        for idx in (
            "ix_credential_ledger_events_ledger_commit_id",
            "ix_credential_ledger_events_event_type",
            "ix_credential_ledger_events_credential_id",
        ):
            try:
                op.drop_index(idx, table_name="credential_ledger_events")
            except Exception:  # index may not exist if migration was partially applied
                pass
        op.drop_table("credential_ledger_events")

    # Drop credential_consents
    if "credential_consents" in existing_tables:
        for idx in (
            "ix_credential_consents_nonce",
            "ix_credential_consents_signing_key_id",
            "ix_credential_consents_user_id",
        ):
            try:
                op.drop_index(idx, table_name="credential_consents")
            except Exception:  # index may not exist if migration was partially applied
                pass
        op.drop_table("credential_consents")
