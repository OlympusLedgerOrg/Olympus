"""
Tests for storage.consistency_checker — SMT consistency checker.

Covers:
- ConsistencyResult dataclass and auto-timestamp
- ConsistencyReport aggregation properties
- SMTConsistencyChecker.run_once() with mocked StorageLayer
- SMTConsistencyChecker.run_all() including halt_on_divergence
- Background thread start/stop lifecycle
"""

from __future__ import annotations

from unittest.mock import MagicMock

from storage.consistency_checker import (
    ConsistencyReport,
    ConsistencyResult,
    SMTConsistencyChecker,
)


# ------------------------------------------------------------------ #
# ConsistencyResult
# ------------------------------------------------------------------ #


class TestConsistencyResult:
    """Tests for the ConsistencyResult dataclass."""

    def test_auto_timestamp(self) -> None:
        result = ConsistencyResult(shard_id="s1", consistent=True)
        assert result.checked_at
        assert result.checked_at.endswith("Z")

    def test_explicit_timestamp_preserved(self) -> None:
        result = ConsistencyResult(
            shard_id="s1", consistent=True, checked_at="2024-01-01T00:00:00Z"
        )
        assert result.checked_at == "2024-01-01T00:00:00Z"

    def test_consistent_result(self) -> None:
        result = ConsistencyResult(shard_id="test", consistent=True)
        assert result.consistent
        assert result.error is None

    def test_inconsistent_result(self) -> None:
        result = ConsistencyResult(
            shard_id="test",
            consistent=False,
            error="Root mismatch",
        )
        assert not result.consistent
        assert result.error == "Root mismatch"


# ------------------------------------------------------------------ #
# ConsistencyReport
# ------------------------------------------------------------------ #


class TestConsistencyReport:
    """Tests for the ConsistencyReport aggregate."""

    def test_empty_report_all_consistent(self) -> None:
        report = ConsistencyReport()
        assert report.all_consistent
        assert report.divergent_shards == []

    def test_all_consistent(self) -> None:
        report = ConsistencyReport(
            results=[
                ConsistencyResult(shard_id="s1", consistent=True),
                ConsistencyResult(shard_id="s2", consistent=True),
            ]
        )
        assert report.all_consistent
        assert report.divergent_shards == []

    def test_one_divergent(self) -> None:
        report = ConsistencyReport(
            results=[
                ConsistencyResult(shard_id="s1", consistent=True),
                ConsistencyResult(shard_id="s2", consistent=False, error="bad"),
            ]
        )
        assert not report.all_consistent
        assert report.divergent_shards == ["s2"]

    def test_all_divergent(self) -> None:
        report = ConsistencyReport(
            results=[
                ConsistencyResult(shard_id="s1", consistent=False, error="e1"),
                ConsistencyResult(shard_id="s2", consistent=False, error="e2"),
            ]
        )
        assert not report.all_consistent
        assert set(report.divergent_shards) == {"s1", "s2"}


# ------------------------------------------------------------------ #
# SMTConsistencyChecker.run_once
# ------------------------------------------------------------------ #


class TestRunOnce:
    """Tests for SMTConsistencyChecker.run_once()."""

    def _make_checker(
        self,
        verify_result: bool = True,
        verify_side_effect: Exception | None = None,
    ) -> tuple[SMTConsistencyChecker, MagicMock]:
        storage = MagicMock()
        if verify_side_effect:
            storage.verify_persisted_root.side_effect = verify_side_effect
        else:
            storage.verify_persisted_root.return_value = verify_result
        checker = SMTConsistencyChecker(storage)
        return checker, storage

    def test_consistent_shard(self) -> None:
        checker, storage = self._make_checker(verify_result=True)
        result = checker.run_once("shard-1")
        assert result.consistent
        assert result.shard_id == "shard-1"
        storage.verify_persisted_root.assert_called_once_with("shard-1")

    def test_inconsistent_shard(self) -> None:
        checker, _ = self._make_checker(verify_result=False)
        result = checker.run_once("shard-bad")
        assert not result.consistent
        assert "divergence" in result.error.lower()

    def test_storage_exception(self) -> None:
        checker, _ = self._make_checker(verify_side_effect=RuntimeError("db down"))
        result = checker.run_once("shard-err")
        assert not result.consistent
        assert "db down" in result.error


# ------------------------------------------------------------------ #
# SMTConsistencyChecker.run_all
# ------------------------------------------------------------------ #


class TestRunAll:
    """Tests for SMTConsistencyChecker.run_all()."""

    def test_all_shards_consistent(self) -> None:
        storage = MagicMock()
        storage.get_all_shard_ids.return_value = ["s1", "s2"]
        storage.verify_persisted_root.return_value = True
        checker = SMTConsistencyChecker(storage)
        report = checker.run_all()
        assert report.all_consistent
        assert len(report.results) == 2

    def test_one_shard_divergent(self) -> None:
        storage = MagicMock()
        storage.get_all_shard_ids.return_value = ["s1", "s2"]
        storage.verify_persisted_root.side_effect = [True, False]
        checker = SMTConsistencyChecker(storage)
        report = checker.run_all()
        assert not report.all_consistent
        assert report.divergent_shards == ["s2"]

    def test_shard_enumeration_failure(self) -> None:
        storage = MagicMock()
        storage.get_all_shard_ids.side_effect = RuntimeError("connection lost")
        checker = SMTConsistencyChecker(storage)
        report = checker.run_all()
        assert not report.all_consistent
        assert len(report.results) == 1
        assert report.results[0].shard_id == "*"

    def test_halt_on_divergence(self) -> None:
        """When halt_on_divergence=True, stop after first inconsistent shard."""
        storage = MagicMock()
        storage.get_all_shard_ids.return_value = ["s1", "s2", "s3"]
        storage.verify_persisted_root.side_effect = [False, True, True]
        checker = SMTConsistencyChecker(storage, halt_on_divergence=True)
        report = checker.run_all()
        # Should stop after s1 (first divergent)
        assert len(report.results) == 1
        assert not report.all_consistent


# ------------------------------------------------------------------ #
# Background thread lifecycle
# ------------------------------------------------------------------ #


class TestBackgroundThread:
    """Tests for start/stop lifecycle."""

    def test_start_and_stop(self) -> None:
        storage = MagicMock()
        storage.get_all_shard_ids.return_value = []
        checker = SMTConsistencyChecker(storage)

        checker.start(interval_seconds=0.1)
        assert checker._thread is not None
        assert checker._thread.is_alive()

        checker.stop(timeout=2.0)
        assert checker._thread is None

    def test_double_start_idempotent(self) -> None:
        storage = MagicMock()
        storage.get_all_shard_ids.return_value = []
        checker = SMTConsistencyChecker(storage)

        checker.start(interval_seconds=0.1)
        thread1 = checker._thread
        checker.start(interval_seconds=0.1)
        thread2 = checker._thread
        assert thread1 is thread2

        checker.stop(timeout=2.0)

    def test_stop_without_start(self) -> None:
        storage = MagicMock()
        checker = SMTConsistencyChecker(storage)
        checker.stop()  # Should not raise
