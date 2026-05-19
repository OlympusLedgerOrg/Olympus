"""
Checkpoint (SMT snapshot) mixin.

Internal to the storage package (_pg_* convention).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from psycopg.rows import dict_row


class _CheckpointsMixin:
    """Periodic SMT root checkpoints for fast historical state reconstruction."""

    def create_checkpoint(self, shard_id: str) -> dict[str, Any] | None:
        """Store a checkpoint root for the current shard state.

        Returns:
            Checkpoint metadata dict, or None if the shard has no headers.
        """
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                SELECT seq, root FROM shard_headers
                WHERE shard_id = %s
                ORDER BY seq DESC
                LIMIT 1
                """,
                (shard_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None

            header_seq = row["seq"]
            root_hash = bytes(row["root"])

            # Scope to this shard — checkpoint creation is shard-scoped and a
            # global COUNT(*) would inflate `leaf_count` once the database
            # holds rows for more than one shard.
            cur.execute(
                "SELECT COUNT(*) AS cnt FROM smt_leaves WHERE shard_id = %s",
                (shard_id,),
            )
            count_row = cur.fetchone()
            leaf_count = int(count_row["cnt"]) if count_row else 0

            ts = datetime.now(timezone.utc)
            cur.execute(
                """
                INSERT INTO smt_checkpoints (shard_id, header_seq, root_hash, leaf_count, ts)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (shard_id, header_seq) DO NOTHING
                """,
                (shard_id, header_seq, root_hash, leaf_count, ts),
            )
            conn.commit()

            return {
                "shard_id": shard_id,
                "header_seq": header_seq,
                "root_hash": root_hash.hex(),
                "leaf_count": leaf_count,
                "ts": ts.isoformat().replace("+00:00", "Z"),
            }

    def get_checkpoints(self, shard_id: str, n: int = 10) -> list[dict[str, Any]]:
        """Retrieve the last N checkpoints for a shard (most recent first)."""
        if n <= 0:
            raise ValueError(f"n must be a positive integer, got {n}")
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                SELECT header_seq, root_hash, leaf_count, ts
                FROM smt_checkpoints
                WHERE shard_id = %s
                ORDER BY header_seq DESC
                LIMIT %s
                """,
                (shard_id, n),
            )
            rows = cur.fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            ts_val = row["ts"]
            ts_str = (
                ts_val.isoformat().replace("+00:00", "Z")
                if isinstance(ts_val, datetime)
                else str(ts_val)
            )
            results.append(
                {
                    "shard_id": shard_id,
                    "header_seq": row["header_seq"],
                    "root_hash": bytes(row["root_hash"]).hex(),
                    "leaf_count": row["leaf_count"],
                    "ts": ts_str,
                }
            )
        return results
