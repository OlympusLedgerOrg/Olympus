"""
Shard header query mixin.

Internal to the storage package (_pg_* convention).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, cast

import nacl.signing
import psycopg
from psycopg.rows import dict_row

from protocol.hashes import shard_header_hash
from protocol.shards import verify_header


class _HeadersMixin:
    """Shard header reads, history, and seq-windowed range queries."""

    def get_latest_header(self, shard_id: str) -> dict[str, Any] | None:
        """Get the latest shard header with signature verification.

        Returns:
            Dict with ``header``, ``signature``, ``pubkey``, ``seq``, or None.
        """
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                    SELECT root, tree_size, leaf_seq, header_hash, sig, pubkey,
                           previous_header_hash, ts, seq
                    FROM shard_headers
                    WHERE shard_id = %s
                    ORDER BY seq DESC
                    LIMIT 1
                    """,
                (shard_id,),
            )
            row = cur.fetchone()

            if row is None:
                return None

            ts_value = row["ts"]
            if isinstance(ts_value, str):
                timestamp_str = ts_value
            elif isinstance(ts_value, datetime):
                timestamp_str = ts_value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            else:
                raise TypeError(
                    f"Unexpected timestamp type: {type(ts_value).__name__}. "
                    "Expected str or datetime."
                )

            header = {
                "shard_id": shard_id,
                "root_hash": bytes(row["root"]).hex(),
                "tree_size": int(row["tree_size"]),
                "timestamp": timestamp_str,
                "height": 0,
                "round": 0,
                "previous_header_hash": row["previous_header_hash"],
                "header_hash": bytes(row["header_hash"]).hex(),
            }
            signature = bytes(row["sig"]).hex()
            verify_key = nacl.signing.VerifyKey(bytes(row["pubkey"]))
            if not verify_header(header, signature, verify_key):
                raise ValueError(f"Invalid shard header signature for shard '{shard_id}'")

            expected_hash = shard_header_hash(
                {k: v for k, v in header.items() if k != "header_hash"}
            ).hex()
            if header["header_hash"] != expected_hash:
                raise ValueError(f"Invalid shard header hash for shard '{shard_id}'")

            self._assert_root_matches_state(  # type: ignore[attr-defined]
                cur, shard_id, bytes(row["root"]), as_of_leaf_seq=int(row["leaf_seq"])
            )
            self._assert_leaf_seq_integrity(  # type: ignore[attr-defined]
                cur, shard_id, "Computed root integrity failure", upper_leaf_seq=None
            )

            return {
                "header": header,
                "signature": signature,
                "pubkey": bytes(row["pubkey"]).hex(),
                "seq": row["seq"],
            }

    def get_header_history(self, shard_id: str, n: int = 10) -> list[dict[str, Any]]:
        """Get the last N signed shard headers in reverse chronological order."""
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                    SELECT seq, root, tree_size, header_hash, previous_header_hash, ts,
                           sig, pubkey
                    FROM shard_headers
                    WHERE shard_id = %s
                    ORDER BY seq DESC
                    LIMIT %s
                    """,
                (shard_id, n),
            )
            rows = cur.fetchall()
            history = []
            for row in rows:
                ts_value = row["ts"]
                if isinstance(ts_value, str):
                    timestamp_str = ts_value
                elif isinstance(ts_value, datetime):
                    timestamp_str = (
                        ts_value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                    )
                else:
                    raise TypeError(
                        f"Unexpected timestamp type: {type(ts_value).__name__}. "
                        "Expected str or datetime."
                    )

                history.append(
                    {
                        "seq": row["seq"],
                        "root_hash": bytes(row["root"]).hex(),
                        "tree_size": int(row["tree_size"]),
                        "height": 0,
                        "round": 0,
                        "header_hash": bytes(row["header_hash"]).hex(),
                        "previous_header_hash": (
                            row["previous_header_hash"]
                            if isinstance(row["previous_header_hash"], str)
                            else bytes(row["previous_header_hash"]).hex()
                        ),
                        "timestamp": timestamp_str,
                        "signature": bytes(row["sig"]).hex(),
                        "pubkey": bytes(row["pubkey"]).hex(),
                    }
                )

            return history

    def get_shard_headers_by_leaf_seq_range(
        self,
        shard_id: str,
        min_leaf_seq: int,
        max_leaf_seq: int,
    ) -> list[dict[str, Any]]:
        """Return shard headers whose ``leaf_seq`` falls in ``[min_leaf_seq, max_leaf_seq]``."""
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                SELECT leaf_seq, root
                FROM shard_headers
                WHERE shard_id = %s
                  AND leaf_seq >= %s
                  AND leaf_seq <= %s
                ORDER BY leaf_seq ASC
                """,
                (shard_id, min_leaf_seq, max_leaf_seq),
            )
            return cast(list[dict[str, Any]], cur.fetchall())

    def _get_header_by_seq(
        self,
        cur: psycopg.Cursor[Any],
        shard_id: str,
        seq: int,
    ) -> dict[str, Any] | None:
        """Retrieve a shard header row by sequence number."""
        cur.execute(
            """
            SELECT seq, root, tree_size, header_hash, previous_header_hash, ts
            FROM shard_headers
            WHERE shard_id = %s AND seq = %s
            """,
            (shard_id, seq),
        )
        return cur.fetchone()
