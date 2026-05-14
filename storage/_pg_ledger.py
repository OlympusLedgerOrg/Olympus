"""
Ledger, root-diff, shard metadata, and leaf-count mixin.

Internal to the storage package (_pg_* convention).
"""

from __future__ import annotations

import warnings
from datetime import datetime
from typing import Any, cast

import psycopg
import psycopg.errors
from psycopg import sql
from psycopg.rows import dict_row

from protocol.ledger import LedgerEntry


class _LedgerMixin:
    """Ledger tail queries, root diffs, shard enumeration, and leaf counts."""

    def get_root_diff(
        self,
        shard_id: str,
        from_seq: int,
        to_seq: int,
        key_range_start: bytes | None = None,
        key_range_end: bytes | None = None,
    ) -> dict[str, Any]:
        """Compare two historical shard states.

        Uses the change journal (O(changes)) when available; falls back to
        full SQL-level diff on ``smt_leaves`` otherwise.

        Raises:
            ValueError: If either sequence does not exist.
        """
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            from_header = self._get_header_by_seq(cur, shard_id, from_seq)  # type: ignore[attr-defined]
            to_header = self._get_header_by_seq(cur, shard_id, to_seq)  # type: ignore[attr-defined]

            if from_header is None:
                raise ValueError(f"Shard header not found: {shard_id}@{from_seq}")
            if to_header is None:
                raise ValueError(f"Shard header not found: {shard_id}@{to_seq}")

            journal_diff = self._diff_from_journal(
                cur, shard_id, from_seq, to_seq, key_range_start, key_range_end
            )
            if journal_diff is not None:
                journal_diff["from_root_hash"] = bytes(from_header["root"]).hex()
                journal_diff["to_root_hash"] = bytes(to_header["root"]).hex()
                return journal_diff

            from_ts = from_header["ts"]
            to_ts = to_header["ts"]

            if isinstance(from_ts, str):
                from_ts = datetime.fromisoformat(from_ts.replace("Z", "+00:00"))
            if isinstance(to_ts, str):
                to_ts = datetime.fromisoformat(to_ts.replace("Z", "+00:00"))

            range_clause = ""
            range_params: list[Any] = []
            if key_range_start is not None:
                range_clause += " AND key >= %s"
                range_params.append(key_range_start)
            if key_range_end is not None:
                range_clause += " AND key < %s"
                range_params.append(key_range_end)

            cur.execute(
                sql.SQL(
                    """
                    SELECT key, value_hash FROM smt_leaves
                    WHERE ts > %s AND ts <= %s
                    {}
                    ORDER BY key ASC
                    """
                ).format(sql.SQL(range_clause)),
                (from_ts, to_ts, *range_params),
            )
            added_rows = cur.fetchall()

            added = [
                {
                    "key": bytes(r["key"]).hex(),
                    "before_value_hash": None,
                    "after_value_hash": bytes(r["value_hash"]).hex(),
                }
                for r in added_rows
            ]

            return {
                "from_root_hash": bytes(from_header["root"]).hex(),
                "to_root_hash": bytes(to_header["root"]).hex(),
                "added": added,
                "changed": [],
                "removed": [],
            }

    def _diff_from_journal(
        self,
        cur: psycopg.Cursor[Any],
        shard_id: str,
        from_seq: int,
        to_seq: int,
        key_range_start: bytes | None,
        key_range_end: bytes | None,
    ) -> dict[str, Any] | None:
        """Attempt to compute a diff from the change journal.

        Returns None when the journal table does not exist or has no coverage.
        """
        try:
            cur.execute(
                """
                SELECT key, old_value, new_value
                FROM smt_change_journal
                WHERE shard_id = %s AND header_seq > %s AND header_seq <= %s
                ORDER BY id ASC
                """,
                (shard_id, from_seq, to_seq),
            )
        except psycopg.errors.UndefinedTable:
            return None

        rows = cur.fetchall()
        if not rows:
            return None

        added: list[dict[str, str | None]] = []
        changed: list[dict[str, str | None]] = []
        removed: list[dict[str, str | None]] = []

        for row in rows:
            key = bytes(row["key"])
            if key_range_start is not None and key < key_range_start:
                continue
            if key_range_end is not None and key >= key_range_end:
                continue

            old_val = row["old_value"]
            new_val = bytes(row["new_value"]) if row["new_value"] else None

            if old_val is None:
                added.append(
                    {
                        "key": key.hex(),
                        "before_value_hash": None,
                        "after_value_hash": new_val.hex() if new_val else None,
                    }
                )
            elif new_val is None:
                removed.append(
                    {
                        "key": key.hex(),
                        "before_value_hash": bytes(old_val).hex(),
                        "after_value_hash": None,
                    }
                )
            else:
                changed.append(
                    {
                        "key": key.hex(),
                        "before_value_hash": bytes(old_val).hex(),
                        "after_value_hash": new_val.hex(),
                    }
                )

        return {"added": added, "changed": changed, "removed": removed}

    def get_ledger_tail(self, shard_id: str, n: int = 10) -> list[LedgerEntry]:
        """Get the last N ledger entries for a shard (most recent first)."""
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                    SELECT payload, entry_hash
                    FROM ledger_entries
                    WHERE shard_id = %s
                    ORDER BY seq DESC
                    LIMIT %s
                    """,
                (shard_id, n),
            )
            rows = cur.fetchall()

            entries = []
            for row in rows:
                payload = row["payload"]
                entry = LedgerEntry(
                    ts=payload["ts"],
                    record_hash=payload["record_hash"],
                    shard_id=payload["shard_id"],
                    shard_root=payload["shard_root"],
                    canonicalization=payload["canonicalization"],
                    prev_entry_hash=payload["prev_entry_hash"],
                    entry_hash=bytes(row["entry_hash"]).hex(),
                )
                entries.append(entry)

            return entries

    def get_all_shard_ids(self) -> list[str]:
        """Get all shard IDs that have headers."""
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                    SELECT DISTINCT shard_id FROM shard_headers
                    ORDER BY shard_id
                    """
            )
            rows = cur.fetchall()
            return [row["shard_id"] for row in rows]

    def verify_state_replay(
        self,
        shard_id: str,
        max_headers: int | None = None,
        after_seq: int = -1,
    ) -> dict[str, Any]:
        """Replay global SMT state at each shard header and verify roots.

        Delegates to :meth:`replay_tree_incremental` (O(N) streaming delta replay).
        Supports RFC 6962 §4.6 cursor-based pagination via ``next_seq``.

        Raises:
            ValueError: If structural seq integrity fails or any root mismatch detected.
        """
        return cast(
            dict[str, Any],
            self.replay_tree_incremental(  # type: ignore[attr-defined]
                shard_id,
                max_headers=max_headers,
                after_seq=after_seq,
            ),
        )

    def get_leaf_count(self, shard_id: str, *, up_to_ts: str | datetime | None = None) -> int:
        """Return the number of leaves in the global SMT.

        Args:
            shard_id: Deprecated — ignored; counts are over the global SMT.
            up_to_ts: Optional ISO 8601 / datetime upper bound.
        """
        if shard_id is not None:
            warnings.warn(
                "get_leaf_count() shard_id parameter is deprecated and ignored. "
                "The global SMT count is returned regardless of shard.",
                DeprecationWarning,
                stacklevel=2,
            )
        query = "SELECT COUNT(*) AS cnt FROM smt_leaves"
        params: list[object] = []
        if up_to_ts is not None:
            ts_val = (
                up_to_ts
                if isinstance(up_to_ts, datetime)
                else datetime.fromisoformat(str(up_to_ts).replace("Z", "+00:00"))
            )
            query += " WHERE ts <= %s"
            params.append(ts_val)

        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(query, params)
            row = cur.fetchone()
        return int(row["cnt"]) if row else 0
