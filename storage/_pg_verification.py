"""
SMT integrity verification mixin (proof paths, root assertions, incremental replay).

Internal to the storage package (_pg_* convention).
Do NOT clean up logic while moving — behavior-preserving extraction only.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from protocol.ssmf import EMPTY_HASHES, _key_to_path_bits
from storage._pg_utils import _encode_path, _get_smt_class, _require_rust_smt


class _VerificationMixin:
    """Proof-path fetching, root assertions, tree replay, and integrity checks."""

    DEFAULT_FLUSH_BATCH_SIZE: int

    # ------------------------------------------------------------------
    # Row access helper
    # ------------------------------------------------------------------

    def _row_get(self, row: Any, key: str, idx: int) -> Any:
        """Get value from row, supporting both dict and tuple rows."""
        if isinstance(row, Mapping):
            return row[key]
        return row[idx]

    # ------------------------------------------------------------------
    # Leaf-seq and root integrity assertions
    # ------------------------------------------------------------------

    def _assert_leaf_seq_integrity(
        self,
        cur: psycopg.Cursor[Any],
        shard_id: str,
        error_prefix: str,
        upper_leaf_seq: int | None,
        lower_leaf_seq_exclusive: int | None = None,
    ) -> None:
        """Verify that shard_headers.leaf_seq claims match smt_leaves.global_seq rows.

        Scoped to *shard_id* so cross-shard leaf insertions cannot falsely trigger
        or mask integrity failures for unrelated shards.  Headers with
        ``leaf_seq <= 0`` are skipped (genesis / setup rows).
        """
        if upper_leaf_seq is None:
            cur.execute(
                """
                SELECT GREATEST(
                    COALESCE((SELECT MAX(global_seq) FROM smt_leaves WHERE shard_id = %s), 0),
                    COALESCE((SELECT MAX(leaf_seq)   FROM shard_headers WHERE shard_id = %s), 0)
                ) AS max_seq
                """,
                (shard_id, shard_id),
            )
            row = cur.fetchone()
            upper_leaf_seq = int(self._row_get(row, "max_seq", 0)) if row is not None else 0

        if lower_leaf_seq_exclusive is None:
            header_params: tuple[Any, ...] = (shard_id, upper_leaf_seq, shard_id)
            header_sql = """
                SELECT sh.leaf_seq
                FROM shard_headers sh
                WHERE sh.shard_id = %s
                  AND sh.leaf_seq > 0 AND sh.leaf_seq <= %s
                  AND NOT EXISTS (
                      SELECT 1
                      FROM smt_leaves sl
                      WHERE sl.global_seq = sh.leaf_seq
                        AND sl.shard_id = %s
                  )
                ORDER BY sh.leaf_seq ASC
                LIMIT 1
            """
        else:
            header_params = (shard_id, lower_leaf_seq_exclusive, upper_leaf_seq, shard_id)
            header_sql = """
                SELECT sh.leaf_seq
                FROM shard_headers sh
                WHERE sh.shard_id = %s
                  AND sh.leaf_seq > %s AND sh.leaf_seq <= %s
                  AND NOT EXISTS (
                      SELECT 1
                      FROM smt_leaves sl
                      WHERE sl.global_seq = sh.leaf_seq
                        AND sl.shard_id = %s
                  )
                ORDER BY sh.leaf_seq ASC
                LIMIT 1
            """

        cur.execute(header_sql, header_params)
        missing_row = cur.fetchone()
        if missing_row is not None:
            missing_leaf_seq = int(self._row_get(missing_row, "leaf_seq", 0))
            raise ValueError(
                f"{error_prefix} for shard '{shard_id}': shard_headers.leaf_seq "
                f"{missing_leaf_seq} has no corresponding smt_leaves.global_seq"
            )

        if lower_leaf_seq_exclusive is None:
            leaf_params: tuple[Any, ...] = (shard_id, upper_leaf_seq, shard_id)
            leaf_sql = """
                SELECT sl.global_seq
                FROM smt_leaves sl
                WHERE sl.shard_id = %s
                  AND sl.global_seq > 0 AND sl.global_seq <= %s
                  AND NOT EXISTS (
                      SELECT 1
                      FROM shard_headers sh
                      WHERE sh.shard_id = %s
                        AND sh.leaf_seq = sl.global_seq
                  )
                ORDER BY sl.global_seq ASC
                LIMIT 1
            """
        else:
            leaf_params = (shard_id, lower_leaf_seq_exclusive, upper_leaf_seq, shard_id)
            leaf_sql = """
                SELECT sl.global_seq
                FROM smt_leaves sl
                WHERE sl.shard_id = %s
                  AND sl.global_seq > %s AND sl.global_seq <= %s
                  AND NOT EXISTS (
                      SELECT 1
                      FROM shard_headers sh
                      WHERE sh.shard_id = %s
                        AND sh.leaf_seq = sl.global_seq
                  )
                ORDER BY sl.global_seq ASC
                LIMIT 1
            """

        cur.execute(leaf_sql, leaf_params)
        orphan_row = cur.fetchone()
        if orphan_row is not None:
            orphaned_leaf_seq = int(self._row_get(orphan_row, "global_seq", 0))
            raise ValueError(
                f"{error_prefix} for shard '{shard_id}': orphaned "
                f"smt_leaves.global_seq {orphaned_leaf_seq} has no corresponding "
                "shard_headers.leaf_seq claim"
            )

    def _assert_root_matches_state(
        self,
        cur: psycopg.Cursor[Any],
        shard_id: str,
        expected_root: bytes,
        as_of_leaf_seq: int | None = None,
    ) -> None:
        """Recompute the global SMT root and ensure it matches *expected_root*.

        When *as_of_leaf_seq* is None reads the root directly from smt_nodes (O(1)).
        Otherwise replays leaves up to that seq (O(N) historical snapshot).

        Raises:
            ValueError: When the recomputed root diverges from *expected_root* or
                when leaf_seq / global_seq structural integrity is violated.
        """
        if as_of_leaf_seq is None:
            cur.execute("SELECT hash FROM smt_nodes WHERE level = 0 AND index = ''::bytea")
            node_row = cur.fetchone()
            computed_root = (
                bytes(node_row["hash"] if isinstance(node_row, Mapping) else node_row[0])
                if node_row is not None
                else EMPTY_HASHES[256]
            )
            self._assert_leaf_seq_integrity(
                cur,
                shard_id,
                "Computed root integrity failure",
                upper_leaf_seq=None,
            )
        else:
            _require_rust_smt()
            replay_tree = _get_smt_class()()

            batch_size = self.DEFAULT_FLUSH_BATCH_SIZE
            offset = 0
            while True:
                cur.execute(
                    """
                    SELECT key, value_hash, parser_id, canonical_parser_version
                    FROM smt_leaves
                    WHERE global_seq <= %s
                    ORDER BY global_seq ASC
                    LIMIT %s OFFSET %s
                    """,
                    (as_of_leaf_seq, batch_size, offset),
                )
                rows = cur.fetchall()
                if not rows:
                    break
                for row in rows:
                    replay_tree.update(
                        bytes(row["key"]),
                        bytes(row["value_hash"]),
                        row["parser_id"],
                        row["canonical_parser_version"],
                    )
                offset += len(rows)

            computed_root = replay_tree.get_root()
            self._assert_leaf_seq_integrity(
                cur,
                shard_id,
                "Computed root integrity failure",
                upper_leaf_seq=as_of_leaf_seq,
            )

        if computed_root != expected_root:
            raise ValueError(
                f"Computed root {computed_root.hex()} does not match persisted root "
                f"{expected_root.hex()} for shard '{shard_id}'"
            )

    # ------------------------------------------------------------------
    # Proof-path helpers (ADR-0001 §2 — O(256) instead of O(N))
    # ------------------------------------------------------------------

    def _get_proof_path(
        self,
        cur: psycopg.Cursor[Any],
        key: bytes,
    ) -> list[bytes]:
        """Fetch 256 BLAKE3 sibling hashes for an inclusion/non-inclusion proof."""
        path = tuple(_key_to_path_bits(key))

        db_levels: list[int] = []
        db_indices: list[bytes] = []
        for level in range(256):
            bit_pos = 255 - level
            sub_path = path[: bit_pos + 1]
            sibling_path = sub_path[:-1] + (1 - sub_path[-1],)
            db_levels.append(len(sibling_path))
            db_indices.append(_encode_path(sibling_path))

        cur.execute(
            """
            SELECT n.hash
            FROM UNNEST(
                %s::SMALLINT[],
                %s::BYTEA[],
                %s::INT[]
            ) AS t(level, index, ord)
            LEFT JOIN smt_nodes n
                   ON n.level = t.level AND n.index = t.index
            ORDER BY t.ord
            """,
            (db_levels, db_indices, list(range(256))),
        )
        rows = cur.fetchall()

        siblings: list[bytes] = []
        for i, row in enumerate(rows):
            raw = row[0] if not isinstance(row, Mapping) else row.get("hash")
            if raw is not None:
                siblings.append(bytes(raw))
            else:
                siblings.append(EMPTY_HASHES[i])
        return siblings

    def _get_poseidon_proof_path(
        self,
        cur: psycopg.Cursor[Any],
        key: bytes,
    ) -> list[int]:
        """Fetch 256 Poseidon sibling hashes for an incremental Poseidon root update."""
        from protocol.poseidon_smt import POSEIDON_EMPTY_HASHES

        path = tuple(_key_to_path_bits(key))

        db_levels: list[int] = []
        db_indices: list[bytes] = []
        for level in range(256):
            bit_pos = 255 - level
            sub_path = path[: bit_pos + 1]
            sibling_path = sub_path[:-1] + (1 - sub_path[-1],)
            db_levels.append(len(sibling_path))
            db_indices.append(_encode_path(sibling_path))

        cur.execute(
            """
            SELECT n.hash
            FROM UNNEST(
                %s::SMALLINT[],
                %s::BYTEA[],
                %s::INT[]
            ) AS t(level, index, ord)
            LEFT JOIN poseidon_smt_nodes n
                   ON n.level = t.level AND n.index = t.index
            ORDER BY t.ord
            """,
            (db_levels, db_indices, list(range(256))),
        )
        rows = cur.fetchall()

        siblings: list[int] = []
        for i, row in enumerate(rows):
            raw = row[0] if not isinstance(row, Mapping) else row.get("hash")
            if raw is not None:
                siblings.append(int(raw))
            else:
                siblings.append(POSEIDON_EMPTY_HASHES[i])
        return siblings

    def _get_current_global_root(self, cur: psycopg.Cursor[Any]) -> bytes:
        """Read the current global SMT root from persisted node state."""
        cur.execute(
            """
            SELECT hash
            FROM smt_nodes
            WHERE level = 0 AND index = %s
            LIMIT 1
            """,
            (b"",),
        )
        row = cur.fetchone()
        if row is None:
            return EMPTY_HASHES[256]
        raw = row[0] if not isinstance(row, Mapping) else row.get("hash")
        return bytes(cast(bytes, raw))

    def get_current_root(self, shard_id: str) -> bytes:
        """Read the current SMT root from the latest shard header (ADR-0001 §3).

        Returns the empty-tree sentinel when no headers exist.
        """
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                SELECT root FROM shard_headers
                WHERE shard_id = %s
                ORDER BY seq DESC
                LIMIT 1
                """,
                (shard_id,),
            )
            row = cur.fetchone()
            if row is None:
                return EMPTY_HASHES[256]
            return bytes(row["root"])

    @staticmethod
    def _normalize_root(root: bytes | str | memoryview | None) -> str:
        """Standardize a cryptographic root to a lowercase hex string."""
        if root is None:
            return ""
        if isinstance(root, memoryview):
            root = bytes(root)
        if isinstance(root, bytes):
            return root.hex()
        return str(root).lower().removeprefix("0x")

    @staticmethod
    def _encode_path(path: tuple[int, ...]) -> bytes:
        """Encode a path tuple as packed bytes (delegates to module-level helper)."""
        return _encode_path(path)

    # ------------------------------------------------------------------
    # Shard integrity verification
    # ------------------------------------------------------------------

    def verify_shard_integrity(
        self,
        shard_id: str,
        roots_by_leaf_seq: Mapping[int, bytes | str | memoryview | None],
    ) -> None:
        """Verify persisted shard-header roots against replayed SMT roots.

        Raises:
            ValueError: When a header is missing from the mapping, has a null
                replayed root, or the persisted root does not match.
        """
        if not roots_by_leaf_seq:
            return

        min_leaf_seq = min(roots_by_leaf_seq)
        max_leaf_seq = max(roots_by_leaf_seq)

        headers = self.get_shard_headers_by_leaf_seq_range(  # type: ignore[attr-defined]
            shard_id, min_leaf_seq, max_leaf_seq
        )

        for header in headers:
            leaf_seq = int(header["leaf_seq"])

            if leaf_seq <= 0:
                continue

            if leaf_seq not in roots_by_leaf_seq:
                raise ValueError(
                    f"Integrity Error: shard {shard_id!r} header references "
                    f"missing leaf_seq={leaf_seq} — replay window lacks an entry "
                    "for this checkpoint"
                )

            replayed_root = roots_by_leaf_seq[leaf_seq]

            if replayed_root is None:
                raise ValueError(
                    f"Integrity Error: shard {shard_id!r} header has null replayed "
                    f"root at leaf_seq={leaf_seq}"
                )

            persisted_root = self._normalize_root(header["root"])
            replayed_root_hex = self._normalize_root(replayed_root)

            if persisted_root != replayed_root_hex:
                raise ValueError(
                    f"Shard {shard_id!r} root mismatch at leaf_seq={leaf_seq}: "
                    f"header_root={persisted_root} replay_root={replayed_root_hex}"
                )

    # ------------------------------------------------------------------
    # Incremental tree replay (ADR-0001 §4, ADR-0004)
    # ------------------------------------------------------------------

    def replay_tree_incremental(
        self,
        shard_id: str,
        batch_size: int = 10_000,
        max_headers: int | None = None,
        after_seq: int = -1,
    ) -> dict[str, Any]:
        """Verify shard integrity by streaming leaves and replaying roots incrementally.

        ADR-0001 §4 — O(N) total work instead of O(N²).
        ADR-0004 — seq-based windowing replaces timestamp-based windowing.

        Returns:
            Dict with ``verified`` (bool), ``headers_checked`` (int),
            ``next_seq`` (int | None) for RFC 6962 §4.6 cursor pagination.

        Raises:
            ValueError: On any root mismatch or structural seq divergence.
        """
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                SELECT seq, root, leaf_seq
                FROM shard_headers
                WHERE shard_id = %s AND seq > %s
                ORDER BY seq ASC
                """,
                (shard_id, after_seq),
            )
            headers = cur.fetchall()

            cur.execute(
                """
                SELECT seq, payload
                FROM ledger_entries
                WHERE shard_id = %s AND seq > %s
                ORDER BY seq ASC
                """,
                (shard_id, after_seq),
            )
            ledger_rows = cur.fetchall()

            if len(ledger_rows) != len(headers):
                raise ValueError(
                    f"Replay mismatch for shard '{shard_id}': {len(ledger_rows)} ledger "
                    f"entries vs {len(headers)} headers (after_seq={after_seq})"
                )

            if max_headers is not None:
                headers_to_check = headers[:max_headers]
                ledger_rows = ledger_rows[:max_headers]
            else:
                headers_to_check = headers

            _require_rust_smt()
            tree = _get_smt_class()()
            prev_leaf_seq: int | None = None

            if after_seq >= 0:
                cur.execute(
                    """
                    SELECT leaf_seq FROM shard_headers
                    WHERE shard_id = %s AND seq = %s
                    """,
                    (shard_id, after_seq),
                )
                prev_row = cur.fetchone()
                if prev_row is not None:
                    prev_leaf_seq = int(
                        prev_row["leaf_seq"] if isinstance(prev_row, Mapping) else prev_row[0]
                    )
                    offset = 0
                    while True:
                        cur.execute(
                            """
                            SELECT key, value_hash, parser_id, canonical_parser_version
                            FROM smt_leaves
                            WHERE global_seq <= %s
                            ORDER BY global_seq ASC
                            LIMIT %s OFFSET %s
                            """,
                            (prev_leaf_seq, batch_size, offset),
                        )
                        rows = cur.fetchall()
                        if not rows:
                            break
                        for row in rows:
                            tree.update(
                                bytes(row["key"]),
                                bytes(row["value_hash"]),
                                row["parser_id"],
                                row["canonical_parser_version"],
                            )
                        offset += len(rows)

            headers_checked = 0

            for idx, header_row in enumerate(headers_to_check):
                header_leaf_seq = int(
                    header_row["leaf_seq"] if isinstance(header_row, Mapping) else header_row[2]
                )

                if prev_leaf_seq is None:
                    seq_clause = "WHERE global_seq <= %s"
                    seq_params: tuple[Any, ...] = (header_leaf_seq,)
                else:
                    seq_clause = "WHERE global_seq > %s AND global_seq <= %s"
                    seq_params = (prev_leaf_seq, header_leaf_seq)

                offset = 0
                while True:
                    cur.execute(
                        sql.SQL("""
                        SELECT key, value_hash, parser_id, canonical_parser_version
                        FROM smt_leaves
                        {}
                        ORDER BY global_seq ASC
                        LIMIT %s OFFSET %s
                        """).format(sql.SQL(seq_clause)),
                        (*seq_params, batch_size, offset),
                    )
                    rows = cur.fetchall()
                    if not rows:
                        break
                    for row in rows:
                        tree.update(
                            bytes(row["key"]),
                            bytes(row["value_hash"]),
                            row["parser_id"],
                            row["canonical_parser_version"],
                        )
                    offset += len(rows)

                self._assert_leaf_seq_integrity(
                    cur,
                    shard_id,
                    "Replay mismatch",
                    upper_leaf_seq=header_leaf_seq,
                    lower_leaf_seq_exclusive=prev_leaf_seq,
                )

                computed_root = tree.get_root()
                header_seq = int(self._row_get(header_row, "seq", 0))
                expected_header_root = bytes(self._row_get(header_row, "root", 1))

                if computed_root != expected_header_root:
                    raise ValueError(
                        f"Shard '{shard_id}' root mismatch at header seq {header_seq}: "
                        f"expected {expected_header_root.hex()}, computed {computed_root.hex()}"
                    )

                ledger_row = ledger_rows[idx]
                ledger_seq = int(self._row_get(ledger_row, "seq", 0))
                payload = self._row_get(ledger_row, "payload", 1)
                if isinstance(payload, str):
                    payload = json.loads(payload)
                shard_root_hex = payload.get("shard_root")
                if shard_root_hex is None:
                    raise ValueError(
                        f"Ledger entry missing shard_root for shard "
                        f"'{shard_id}' at seq {ledger_seq}"
                    )
                if computed_root.hex() != shard_root_hex:
                    raise ValueError(
                        f"Shard '{shard_id}' ledger root mismatch at seq {ledger_seq}: "
                        f"expected {shard_root_hex}, computed {computed_root.hex()}"
                    )

                prev_leaf_seq = header_leaf_seq
                headers_checked += 1

            remaining = len(headers) - len(headers_to_check)
            if remaining > 0:
                next_seq = int(self._row_get(headers_to_check[-1], "seq", 0))
            else:
                next_seq = None

            if next_seq is None and headers:
                latest_header_root = bytes(self._row_get(headers[-1], "root", 1))
                if tree.get_root() != latest_header_root:
                    raise ValueError(
                        f"Replay mismatch for shard '{shard_id}': latest persisted root "
                        f"{latest_header_root.hex()} does not match current state "
                        f"{tree.get_root().hex()}"
                    )
                self._assert_leaf_seq_integrity(
                    cur, shard_id, "Replay mismatch", upper_leaf_seq=None
                )

            return {
                "verified": True,
                "headers_checked": headers_checked,
                "next_seq": next_seq,
            }
