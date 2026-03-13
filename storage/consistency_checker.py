"""
Background consistency checker for Olympus SMT roots.

Provides a periodic job that:
  1. Recomputes the SMT root from authoritative leaves.
  2. Compares the computed root to the latest persisted shard header.
  3. Logs divergence and optionally halts ingestion.

Usage::

    checker = SMTConsistencyChecker(storage_layer)
    checker.run_once("us-gov-foia")        # single shard check
    checker.run_all()                       # check every shard
    checker.start(interval_seconds=300)     # background loop
    checker.stop()
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from storage.postgres import StorageLayer

logger = logging.getLogger(__name__)


@dataclass
class ConsistencyResult:
    """Result of a single shard consistency check."""

    shard_id: str
    consistent: bool
    persisted_root_hex: str | None = None
    computed_root_hex: str | None = None
    checked_at: str = ""
    error: str | None = None

    def __post_init__(self) -> None:
        if not self.checked_at:
            self.checked_at = (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )


@dataclass
class ConsistencyReport:
    """Aggregate report for all checked shards."""

    results: list[ConsistencyResult] = field(default_factory=list)

    @property
    def all_consistent(self) -> bool:
        return all(r.consistent for r in self.results)

    @property
    def divergent_shards(self) -> list[str]:
        return [r.shard_id for r in self.results if not r.consistent]


class SMTConsistencyChecker:
    """Periodic SMT root consistency checker."""

    def __init__(
        self,
        storage: StorageLayer,
        *,
        halt_on_divergence: bool = False,
    ) -> None:
        self._storage = storage
        self._halt_on_divergence = halt_on_divergence
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_once(self, shard_id: str) -> ConsistencyResult:
        """
        Check a single shard's SMT root against its latest header.

        Returns:
            ConsistencyResult with outcome details.
        """
        try:
            is_valid = self._storage.verify_persisted_root(shard_id)
            if is_valid:
                logger.info("SMT consistency OK for shard '%s'", shard_id)
                return ConsistencyResult(shard_id=shard_id, consistent=True)

            msg = f"SMT root divergence detected for shard '{shard_id}'"
            logger.error(msg)
            return ConsistencyResult(shard_id=shard_id, consistent=False, error=msg)

        except Exception as exc:
            msg = f"Consistency check failed for shard '{shard_id}': {exc}"
            logger.error(msg)
            return ConsistencyResult(shard_id=shard_id, consistent=False, error=msg)

    def run_all(self) -> ConsistencyReport:
        """
        Check all known shards.

        Returns:
            ConsistencyReport with per-shard results.
        """
        report = ConsistencyReport()
        try:
            shard_ids = self._storage.get_all_shard_ids()
        except Exception as exc:
            logger.error("Failed to enumerate shards: %s", exc)
            report.results.append(
                ConsistencyResult(shard_id="*", consistent=False, error=str(exc))
            )
            return report

        for shard_id in shard_ids:
            result = self.run_once(shard_id)
            report.results.append(result)

            if not result.consistent and self._halt_on_divergence:
                logger.critical(
                    "Halting consistency checks due to divergence in shard '%s'",
                    shard_id,
                )
                break

        return report

    def start(self, interval_seconds: float = 300.0) -> None:
        """Start a background thread that runs ``run_all()`` periodically."""
        if self._thread is not None and self._thread.is_alive():
            return  # Already running
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            args=(interval_seconds,),
            daemon=True,
            name="smt-consistency-checker",
        )
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        """Signal the background thread to stop and wait for it."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _loop(self, interval: float) -> None:
        """Background loop: check all shards, then sleep."""
        while not self._stop_event.is_set():
            try:
                report = self.run_all()
                if not report.all_consistent:
                    logger.warning(
                        "Divergent shards detected: %s", report.divergent_shards
                    )
            except Exception:
                logger.exception("Unhandled error in consistency checker loop")
            self._stop_event.wait(interval)
