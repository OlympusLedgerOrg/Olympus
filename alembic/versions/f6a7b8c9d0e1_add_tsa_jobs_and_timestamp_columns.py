"""Add tsa_jobs queue table and timestamp_attempts/last_error columns (H-5).

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-04-20

H-5: move RFC 3161 TSA call out of the request handler into a background
worker.  This migration provisions:

* ``tsa_jobs`` — append-only queue of pending timestamp jobs claimed by
  ``api.workers.tsa_worker``.  One row per ``(target_table, target_pk)``;
  uniqueness prevents duplicate enqueueing for the same artifact.
* ``dataset_artifacts.timestamp_attempts`` / ``timestamp_last_error`` —
  observability for retry behaviour.  Same columns added to
  ``dataset_lineage_events`` for symmetry; that endpoint currently writes
  ``timestamp_status='pending'`` and is also enqueued by the same worker.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


revision: str = "f6a7b8c9d0e1"
down_revision: str | Sequence[str] | None = "e5f6a7b8c9d0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- tsa_jobs queue table -------------------------------------------------
    op.create_table(
        "tsa_jobs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        # Logical pointer back to the row that needs a timestamp.  We don't
        # use a real FK because the worker may be deployed against a slightly
        # different schema and we want to be tolerant of schema drift on the
        # job table (deletion-resistant).
        sa.Column("target_table", sa.String(length=64), nullable=False),
        sa.Column("target_pk", sa.String(length=64), nullable=False),
        # Hash to timestamp (the commit_id).  Stored explicitly so the worker
        # never has to re-derive it from the target row.
        sa.Column("hash_hex", sa.String(length=66), nullable=False),
        sa.Column("tsa_url", sa.String(length=512), nullable=False),
        # Job lifecycle.  ``pending`` -> ``in_flight`` -> ``done`` | ``failed``.
        # ``in_flight`` is short-lived and only used to prevent two worker
        # instances from racing on the same row.
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        # Time-based gating.  ``next_attempt_at`` enables exponential backoff
        # without an external scheduler.
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        # Prevent duplicate enqueueing for the same artifact.
        sa.UniqueConstraint("target_table", "target_pk", name="uq_tsa_jobs_target"),
    )
    op.create_index(
        "ix_tsa_jobs_pending_due",
        "tsa_jobs",
        ["status", "next_attempt_at"],
    )

    # --- dataset_artifacts: observability columns ----------------------------
    op.add_column(
        "dataset_artifacts",
        sa.Column(
            "timestamp_attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "dataset_artifacts",
        sa.Column("timestamp_last_error", sa.Text(), nullable=True),
    )

    # --- dataset_lineage_events: same observability columns ------------------
    op.add_column(
        "dataset_lineage_events",
        sa.Column(
            "timestamp_attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "dataset_lineage_events",
        sa.Column("timestamp_last_error", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dataset_lineage_events", "timestamp_last_error")
    op.drop_column("dataset_lineage_events", "timestamp_attempts")
    op.drop_column("dataset_artifacts", "timestamp_last_error")
    op.drop_column("dataset_artifacts", "timestamp_attempts")
    op.drop_index("ix_tsa_jobs_pending_due", table_name="tsa_jobs")
    op.drop_table("tsa_jobs")
