"""
Global log monitoring utilities for Olympus transparency logs.

Monitors collect Signed Tree Heads (STHs) from multiple nodes, verify
append-only growth via Merkle consistency proofs, and surface split-view
evidence when peers disagree on the same shard history.

Prometheus integration
----------------------
When ``prometheus-client`` is installed, the monitor emits:

- ``olympus_monitor_observations_total`` — observations recorded per shard/node.
- ``olympus_monitor_split_views_total`` — split-view evidence events detected.
- ``olympus_monitor_consistency_failures_total`` — consistency proof failures.
- ``olympus_monitor_poll_seconds`` — poll_node latency histogram.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .consistency import ConsistencyProof
from .epochs import SignedTreeHead, verify_sth_consistency


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics (optional)
# ---------------------------------------------------------------------------

try:  # pragma: no cover
    import prometheus_client as _prom

    _MONITOR_OBSERVATIONS = _prom.Counter(
        "olympus_monitor_observations_total",
        "Total STH observations recorded",
        labelnames=["shard_id", "node_id"],
    )
    _MONITOR_SPLIT_VIEWS = _prom.Counter(
        "olympus_monitor_split_views_total",
        "Total split-view evidence events detected",
        labelnames=["shard_id"],
    )
    _MONITOR_CONSISTENCY_FAILURES = _prom.Counter(
        "olympus_monitor_consistency_failures_total",
        "Total consistency proof failures during monitoring",
        labelnames=["shard_id", "node_id"],
    )
    _MONITOR_POLL_LATENCY = _prom.Histogram(
        "olympus_monitor_poll_seconds",
        "Latency of poll_node operations",
        labelnames=["node_id", "shard_id"],
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    )
    _PROM_MONITOR = True
except ImportError:

    class _NullMonitorMetric:
        def labels(self, **_kw: object) -> _NullMonitorMetric:
            return self

        def inc(self, _amount: float = 1) -> None:
            return

        def observe(self, _v: float) -> None:
            return

    _MONITOR_OBSERVATIONS = _NullMonitorMetric()  # type: ignore[assignment]
    _MONITOR_SPLIT_VIEWS = _NullMonitorMetric()  # type: ignore[assignment]
    _MONITOR_CONSISTENCY_FAILURES = _NullMonitorMetric()  # type: ignore[assignment]
    _MONITOR_POLL_LATENCY = _NullMonitorMetric()  # type: ignore[assignment]
    _PROM_MONITOR = False


@dataclass(frozen=True)
class Observation:
    """Observation of a Signed Tree Head from a specific node and shard."""

    node_id: str
    shard_id: str
    sth: SignedTreeHead


@dataclass(frozen=True)
class SplitViewEvidence:
    """
    Evidence that two or more nodes present conflicting roots at the same size.

    Attributes:
        shard_id: Shard under observation.
        tree_size: Tree size where roots diverged.
        observations: Mapping of node_id -> SignedTreeHead for conflicting views.
    """

    shard_id: str
    tree_size: int
    observations: dict[str, SignedTreeHead]


class LogMonitor:
    """
    Append-only monitor for Olympus STH gossip.

    A monitor tracks the latest STH seen per (node, shard) tuple, verifies
    consistency proofs for growth, and detects split-view presentations where
    nodes disagree on the same tree size.
    """

    def __init__(
        self,
        *,
        sth_fetcher: Callable[[str, str], SignedTreeHead] | None = None,
        consistency_fetcher: Callable[[str, str, int, int], ConsistencyProof] | None = None,
    ) -> None:
        self._sth_fetcher = sth_fetcher
        self._consistency_fetcher = consistency_fetcher
        self._latest: dict[tuple[str, str], SignedTreeHead] = {}

    # ------------------------------------------------------------------#
    # Observation ingest
    # ------------------------------------------------------------------#

    def record_observation(
        self,
        *,
        node_id: str,
        shard_id: str,
        sth: SignedTreeHead,
        proof: ConsistencyProof | None = None,
    ) -> Observation:
        """
        Record an observed STH and verify append-only growth against prior state.

        Raises:
            ValueError: If the STH is invalid or the consistency proof fails.
        """
        if not sth.verify():
            raise ValueError("Invalid STH signature")

        key = (node_id, shard_id)
        previous = self._latest.get(key)

        if previous is not None:
            if sth.tree_size < previous.tree_size:
                raise ValueError("Observed STH regressed in tree size")
            if sth.tree_size == previous.tree_size:
                if sth.merkle_root != previous.merkle_root:
                    raise ValueError("Split view detected: same size, different root")
            else:
                if proof is None:
                    raise ValueError("Consistency proof required for append-only growth")
                if not verify_sth_consistency(previous, sth, proof):
                    _MONITOR_CONSISTENCY_FAILURES.labels(
                        shard_id=shard_id, node_id=node_id
                    ).inc()
                    raise ValueError("Consistency proof rejected")

        self._latest[key] = sth
        _MONITOR_OBSERVATIONS.labels(shard_id=shard_id, node_id=node_id).inc()
        return Observation(node_id=node_id, shard_id=shard_id, sth=sth)

    def poll_node(self, *, node_id: str, shard_id: str) -> Observation:
        """
        Fetch and record the latest STH for a node/shard via configured fetchers.

        Returns:
            Recorded :class:`Observation`.

        Raises:
            ValueError: If fetchers are not configured or verification fails.
        """
        if self._sth_fetcher is None:
            raise ValueError("sth_fetcher not configured for LogMonitor")
        start = time.monotonic()
        try:
            latest = self._sth_fetcher(node_id, shard_id)
            previous = self._latest.get((node_id, shard_id))
            proof: ConsistencyProof | None = None
            if (
                previous is not None
                and self._consistency_fetcher is not None
                and latest.tree_size > previous.tree_size
            ):
                proof = self._consistency_fetcher(
                    node_id, shard_id, previous.tree_size, latest.tree_size
                )
            return self.record_observation(
                node_id=node_id, shard_id=shard_id, sth=latest, proof=proof
            )
        finally:
            elapsed = time.monotonic() - start
            _MONITOR_POLL_LATENCY.labels(node_id=node_id, shard_id=shard_id).observe(elapsed)

    # ------------------------------------------------------------------#
    # Gossip analysis
    # ------------------------------------------------------------------#

    def split_view_evidence(self, shard_id: str) -> tuple[SplitViewEvidence, ...]:
        """
        Detect split views among recorded observations for a shard.

        A split view exists when two nodes report the same tree_size but
        different Merkle roots. Only the latest observation per node is
        considered.
        """
        shard_views: dict[str, SignedTreeHead] = {
            node_id: sth for (node_id, shard), sth in self._latest.items() if shard == shard_id
        }
        if len(shard_views) < 2:
            return ()

        evidence: list[SplitViewEvidence] = []
        # Group by tree_size to identify disagreements at the same size.
        sizes: dict[int, dict[str, SignedTreeHead]] = {}
        for node_id, sth in shard_views.items():
            sizes.setdefault(sth.tree_size, {})[node_id] = sth

        for tree_size, observations in sorted(sizes.items()):
            roots = {obs.merkle_root for obs in observations.values()}
            if len(roots) > 1:
                evidence.append(
                    SplitViewEvidence(
                        shard_id=shard_id,
                        tree_size=tree_size,
                        observations=observations,
                    )
                )
                _MONITOR_SPLIT_VIEWS.labels(shard_id=shard_id).inc()
        return tuple(evidence)

    def observed(self) -> Iterable[Observation]:
        """Return the latest observations across all nodes and shards."""
        for (node_id, shard_id), sth in self._latest.items():
            yield Observation(node_id=node_id, shard_id=shard_id, sth=sth)
