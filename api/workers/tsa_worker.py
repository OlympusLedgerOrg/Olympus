"""RFC 3161 background worker (H-5).

Drains the ``tsa_jobs`` queue populated by the dataset commit endpoints,
fetches signed timestamp tokens from the configured TSA, and updates the
target row (a ``DatasetArtifact`` or ``DatasetLineageEvent``) with the
result.  A periodic *sweeper* coroutine in the same process flips
long-pending rows to ``failed`` once their grace window has elapsed.

Why a separate process:

* The TSA call is network-bound and occasionally hangs even with a 5s
  timeout.  Running it on the FastAPI request path lets a slow TSA pin
  worker processes (H-5).
* The queue is a durable SQL table so jobs survive a worker restart and
  multiple workers can share the load.

Concurrency model:

* A single worker process runs ``run_worker`` (the consumer) and
  ``run_sweeper`` (the deadline enforcer) as concurrent asyncio tasks.
* Multiple worker processes can run concurrently — claiming a job is an
  atomic ``UPDATE ... WHERE status='pending' AND id=?`` that returns the
  number of rows updated, so two workers never act on the same job.
* The TSA call itself is synchronous (``rfc3161ng`` is a sync HTTP client)
  and is dispatched to a thread via ``asyncio.to_thread`` so it doesn't
  block the event loop.

Run with::

    python -m api.workers.tsa_worker

Observability: structured INFO log lines on every state transition.  Set
``OLYMPUS_LOG_FORMAT=json`` to emit one JSON object per event.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import get_settings
from api.db import AsyncSessionLocal
from api.models.dataset import DatasetArtifact, DatasetLineageEvent
from api.models.tsa_job import TsaJob


logger = logging.getLogger(__name__)


# Mapping of ``target_table`` values stored on TsaJob rows back to their
# ORM models.  Adding a new row type requires registering it here.  Both
# models in this map share the contract: they expose ``id``,
# ``timestamp_status``, ``timestamp_attempts``, ``timestamp_last_error``,
# ``rfc3161_tst_hex``, ``rfc3161_tsa_url``, and ``epoch_timestamp``.
_TARGET_MODELS: dict[str, type[DatasetArtifact] | type[DatasetLineageEvent]] = {
    "dataset_artifacts": DatasetArtifact,
    "dataset_lineage_events": DatasetLineageEvent,
}


def _utc_now() -> datetime:
    """Return the current UTC time as a naive datetime.

    SQLite (used in tests) stores ``DateTime`` as naive UTC; matching the
    storage convention here keeps comparisons consistent across SQLite
    and Postgres.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _backoff_seconds(attempts: int) -> float:
    """Exponential backoff with a hard cap.

    ``attempts`` is the new attempt count *after* incrementing.  Schedule
    is 1, 2, 4, 8, ... up to 5 minutes between retries.  A hard cap
    avoids unbounded delays that would push past the grace window with
    no chance to recover.
    """
    return float(min(300, 2 ** max(0, attempts - 1)))


async def claim_one_job(session: AsyncSession) -> TsaJob | None:
    """Atomically claim a single pending job whose ``next_attempt_at`` is due.

    Returns ``None`` when there is nothing to do.  Uses an explicit
    conditional ``UPDATE`` rather than ``SELECT ... FOR UPDATE`` so the
    same code path works on SQLite (no row locks) and Postgres.
    """
    now = _utc_now()
    candidate = (
        (
            await session.execute(
                select(TsaJob)
                .where(TsaJob.status == "pending", TsaJob.next_attempt_at <= now)
                .order_by(TsaJob.next_attempt_at.asc())
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    if candidate is None:
        return None

    # Conditional update: only one worker may claim this row.
    result = await session.execute(
        update(TsaJob)
        .where(TsaJob.id == candidate.id, TsaJob.status == "pending")
        .values(status="in_flight", claimed_at=now)
    )
    rowcount = getattr(result, "rowcount", 0) or 0
    await session.commit()
    if rowcount == 0:
        # Lost the race to another worker; try again next tick.
        return None
    await session.refresh(candidate)
    return candidate


def _fetch_token_sync(hash_hex: str, tsa_url: str):
    """Synchronous wrapper around ``request_timestamp`` for ``to_thread``."""
    from protocol.rfc3161 import request_timestamp

    return request_timestamp(hash_hex, tsa_url=tsa_url)


async def _mark_target_verified(
    session: AsyncSession,
    job: TsaJob,
    tst_hex: str,
    tsa_url: str,
    new_attempts: int,
) -> None:
    """Stamp the target row as verified.  No-op if the row vanished."""
    model = _TARGET_MODELS.get(job.target_table)
    if model is None:
        logger.warning(
            "TSA job %s targets unknown table %s; skipping target update",
            job.id,
            job.target_table,
        )
        return
    await session.execute(
        update(model)
        .where(model.id == job.target_pk)
        .values(
            rfc3161_tst_hex=tst_hex,
            rfc3161_tsa_url=tsa_url,
            timestamp_status="verified",
            timestamp_attempts=new_attempts,
            timestamp_last_error=None,
        )
    )


async def _mark_target_failed(
    session: AsyncSession,
    job: TsaJob,
    error: str,
    new_attempts: int,
) -> None:
    """Reflect a permanent failure onto the target row."""
    model = _TARGET_MODELS.get(job.target_table)
    if model is None:
        logger.warning(
            "TSA job %s targets unknown table %s; skipping target update",
            job.id,
            job.target_table,
        )
        return
    await session.execute(
        update(model)
        .where(model.id == job.target_pk)
        .values(
            timestamp_status="failed",
            timestamp_attempts=new_attempts,
            timestamp_last_error=error,
        )
    )


async def _bump_target_attempts(
    session: AsyncSession,
    job: TsaJob,
    error: str,
    new_attempts: int,
) -> None:
    """Record a transient failure on the target row without flipping status."""
    model = _TARGET_MODELS.get(job.target_table)
    if model is None:
        return
    await session.execute(
        update(model)
        .where(model.id == job.target_pk)
        .values(
            timestamp_attempts=new_attempts,
            timestamp_last_error=error,
        )
    )


async def process_job(session: AsyncSession, job: TsaJob, max_attempts: int) -> None:
    """Run one TSA fetch attempt for ``job`` and persist the outcome.

    The job has already been marked ``in_flight`` by ``claim_one_job``.
    On success we transition to ``done`` and stamp the target row.  On a
    transient failure we bump ``attempts`` and reschedule with backoff.
    On exhausting ``max_attempts`` we transition to ``failed`` and
    reflect that on the target row.
    """
    now = _utc_now()
    try:
        token = await asyncio.to_thread(_fetch_token_sync, job.hash_hex, job.tsa_url)
    except Exception as exc:  # noqa: BLE001 — TSA libs raise many shapes
        new_attempts = job.attempts + 1
        # Truncate to keep the column small even if the TSA returned a
        # huge HTML error page in the exception text.
        error = repr(exc)[:512]
        if new_attempts >= max_attempts:
            await session.execute(
                update(TsaJob)
                .where(TsaJob.id == job.id)
                .values(
                    status="failed",
                    attempts=new_attempts,
                    last_error=error,
                    completed_at=now,
                )
            )
            await _mark_target_failed(session, job, error, new_attempts)
            await session.commit()
            logger.warning(
                "TSA job %s failed permanently after %d attempts: %s",
                job.id,
                new_attempts,
                error,
            )
            return
        backoff = _backoff_seconds(new_attempts)
        await session.execute(
            update(TsaJob)
            .where(TsaJob.id == job.id)
            .values(
                status="pending",
                attempts=new_attempts,
                last_error=error,
                next_attempt_at=now + timedelta(seconds=backoff),
                claimed_at=None,
            )
        )
        await _bump_target_attempts(session, job, error, new_attempts)
        await session.commit()
        logger.info(
            "TSA job %s transient failure (attempt %d/%d); retrying in %.1fs: %s",
            job.id,
            new_attempts,
            max_attempts,
            backoff,
            error,
        )
        return

    # Success path.
    new_attempts = job.attempts + 1
    tst_hex = token.tst_bytes.hex()
    await session.execute(
        update(TsaJob)
        .where(TsaJob.id == job.id)
        .values(
            status="done",
            attempts=new_attempts,
            last_error=None,
            completed_at=now,
        )
    )
    await _mark_target_verified(session, job, tst_hex, token.tsa_url, new_attempts)
    await session.commit()
    logger.info(
        "TSA job %s verified target=%s pk=%s",
        job.id,
        job.target_table,
        job.target_pk,
    )


async def run_sweeper_once(session: AsyncSession, grace_seconds: int) -> int:
    """Promote past-grace pending target rows to ``failed`` exactly once.

    Returns the number of rows flipped (useful for tests).  Idempotent:
    rows already past grace and still pending will simply be flipped on
    the first call and ignored on subsequent calls because the WHERE
    clause restricts to ``timestamp_status='pending'``.

    The sweeper is the safety net.  The worker promotes its own jobs to
    ``failed`` once ``max_attempts`` is reached, but a row can also age
    out without the worker ever picking it up (e.g. the worker process
    was down when the row was created and the rolling backlog never
    drained in time).  This sweep ensures ``/verify`` callers eventually
    see a definitive answer even in degraded operating conditions.
    """
    cutoff = _utc_now() - timedelta(seconds=grace_seconds)
    flipped = 0
    for model in (DatasetArtifact, DatasetLineageEvent):
        result = await session.execute(
            update(model)
            .where(
                model.timestamp_status == "pending",
                model.epoch_timestamp < cutoff,
            )
            .values(
                timestamp_status="failed",
                timestamp_last_error="grace_window_exceeded",
            )
        )
        flipped += getattr(result, "rowcount", 0) or 0
    if flipped:
        await session.commit()
        logger.info("TSA sweeper flipped %d past-grace pending rows to failed", flipped)
    else:
        # No-op: nothing to commit, but keep transactional cleanliness.
        await session.rollback()
    return flipped


async def run_worker(stop_event: asyncio.Event) -> None:
    """Consumer loop: claim and process jobs until ``stop_event`` is set."""
    settings = get_settings()
    poll = settings.tsa_worker_poll_interval_seconds
    max_attempts = settings.tsa_max_attempts
    logger.info(
        "TSA worker starting (poll=%.2fs max_attempts=%d)",
        poll,
        max_attempts,
    )
    while not stop_event.is_set():
        try:
            async with AsyncSessionLocal() as session:
                job = await claim_one_job(session)
                if job is None:
                    # Use wait_for so we wake up immediately on shutdown
                    # rather than sleeping out the full poll interval.
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=poll)
                    except asyncio.TimeoutError:
                        pass
                    continue
                await process_job(session, job, max_attempts)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — keep the worker alive on logic bugs
            logger.exception("TSA worker iteration failed; sleeping before retry")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=poll)
            except asyncio.TimeoutError:
                pass
    logger.info("TSA worker stopped")


async def run_sweeper(stop_event: asyncio.Event) -> None:
    """Sweeper loop: periodically expire past-grace pending rows."""
    settings = get_settings()
    interval = settings.tsa_sweeper_interval_seconds
    grace = settings.tsa_grace_seconds
    logger.info(
        "TSA sweeper starting (interval=%.2fs grace=%ds)",
        interval,
        grace,
    )
    while not stop_event.is_set():
        try:
            async with AsyncSessionLocal() as session:
                await run_sweeper_once(session, grace)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("TSA sweeper iteration failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
    logger.info("TSA sweeper stopped")


async def _main() -> None:
    """Entry point for ``python -m api.workers.tsa_worker``."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            # Windows / restricted environments — fall back to default
            # signal handling; ``asyncio.run`` will still cancel tasks.
            pass

    await asyncio.gather(
        run_worker(stop_event),
        run_sweeper(stop_event),
    )


def _main_sync() -> None:
    """Synchronous entry point for the ``olympus-tsa-worker`` console script."""
    asyncio.run(_main())


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(_main())
