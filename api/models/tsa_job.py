"""TSA job queue ORM model (H-5).

A persistent queue of pending RFC 3161 timestamp requests, populated by the
``commit_dataset`` and ``commit_lineage`` endpoints, drained by the
``api.workers.tsa_worker`` background process.

Why a queue table rather than ``BackgroundTasks``:

* In-process tasks are lost on restart.  TSA failures are common (network
  blips, TSA rate limits) and every commit needs a token before its
  ``epoch_timestamp + grace_seconds`` deadline.
* A queue table is observable from SQL — operators can ``SELECT`` to see
  backlog without a side-channel.
* No new infrastructure: the only dependency is the Postgres / SQLite
  database that already exists.

The worker uses an atomic ``UPDATE ... WHERE status='pending'`` to claim a
row, so multiple worker processes can run safely.  See
``api.workers.tsa_worker`` for the lifecycle.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class TsaJob(Base):
    """A pending or completed RFC 3161 timestamp job.

    Attributes:
        id: UUID primary key.
        target_table: Name of the table that owns the row needing a stamp,
            e.g. ``"dataset_artifacts"`` or ``"dataset_lineage_events"``.
            Stored as a string rather than a foreign key so the worker is
            tolerant of schema drift on its own table.
        target_pk: Primary-key value of the target row.  For dataset
            artifacts and lineage events this is the UUID ``id`` column.
        hash_hex: Hex-encoded BLAKE3 hash to timestamp (the artifact's
            ``commit_id``).  Stored explicitly so the worker never has to
            re-derive it from the target row.
        tsa_url: TSA endpoint to use for this job.  Captured at enqueue
            time so changing the default later does not retroactively
            redirect in-flight jobs.
        status: ``"pending"`` | ``"in_flight"`` | ``"done"`` | ``"failed"``.
            ``in_flight`` is short-lived and used to prevent two worker
            instances from racing on the same row.
        attempts: Number of times the worker has tried this job.
        last_error: Short error string on the most recent failure.
        created_at: When the job was enqueued (UTC).
        next_attempt_at: Earliest time the worker should try this job
            again (UTC).  Drives exponential backoff without a separate
            scheduler.
        claimed_at: When the worker most recently took this job.
        completed_at: When the job reached a terminal state
            (``done`` or ``failed``).
    """

    __tablename__ = "tsa_jobs"

    __table_args__ = (UniqueConstraint("target_table", "target_pk", name="uq_tsa_jobs_target"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_table: Mapped[str] = mapped_column(String(64), nullable=False)
    target_pk: Mapped[str] = mapped_column(String(64), nullable=False)
    hash_hex: Mapped[str] = mapped_column(String(66), nullable=False)
    tsa_url: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
