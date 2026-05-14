"""
RFC 3161 timestamp token and Rekor anchoring mixin.

Internal to the storage package (_pg_* convention).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from psycopg.rows import dict_row

from protocol.rfc3161 import MAX_TSA_TOKENS, _sha256_of_hash
from protocol.ssmf import EMPTY_HASHES
from storage._pg_utils import _normalize_timestamp_iso


class _AnchoringMixin:
    """RFC 3161 timestamp tokens, Rekor anchors, and persisted root verification."""

    # ------------------------------------------------------------------
    # RFC 3161 timestamp tokens
    # ------------------------------------------------------------------

    def store_timestamp_token(
        self,
        shard_id: str,
        header_hash_hex: str,
        token: Any,
    ) -> None:
        """Persist an RFC 3161 timestamp token for a shard header.

        Idempotent — a second insert for the same ``(shard_id, header_hash)``
        is silently ignored.
        """
        header_hash_bytes = bytes.fromhex(header_hash_hex)
        if len(header_hash_bytes) != 32:
            raise ValueError(
                f"header_hash_hex must encode exactly 32 bytes, got {len(header_hash_bytes)}"
            )

        hash_hex = token.hash_hex if hasattr(token, "hash_hex") else token["hash_hex"]
        tsa_url = token.tsa_url if hasattr(token, "tsa_url") else token["tsa_url"]
        tst_bytes = (
            token.tst_bytes if hasattr(token, "tst_bytes") else bytes.fromhex(token["tst_hex"])
        )
        tsa_cert_fingerprint = (
            token.tsa_cert_fingerprint
            if hasattr(token, "tsa_cert_fingerprint")
            else token.get("tsa_cert_fingerprint")
        )
        timestamp = token.timestamp if hasattr(token, "timestamp") else token["timestamp"]
        ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        imprint_hash = _sha256_of_hash(hash_hex)

        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                SELECT COUNT(*) AS token_count,
                       BOOL_OR(tsa_url = %s) AS tsa_already_present
                FROM timestamp_tokens
                WHERE shard_id = %s AND header_hash = %s
                """,
                (tsa_url, shard_id, header_hash_bytes),
            )
            limit_row = cur.fetchone()
            if limit_row is None:
                raise RuntimeError("Failed to load timestamp token count")
            if int(limit_row["token_count"]) >= MAX_TSA_TOKENS and not bool(
                limit_row["tsa_already_present"]
            ):
                raise ValueError(
                    f"Refusing to store more than {MAX_TSA_TOKENS} TSA tokens for a header"
                )
            cur.execute(
                """
                INSERT INTO timestamp_tokens
                    (shard_id, header_hash, tsa_url, tst,
                     imprint_hash, gen_time, tsa_cert_fingerprint)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (shard_id, header_hash, tsa_url) DO NOTHING
                """,
                (
                    shard_id,
                    header_hash_bytes,
                    tsa_url,
                    tst_bytes,
                    imprint_hash,
                    ts,
                    tsa_cert_fingerprint,
                ),
            )
            conn.commit()

    def get_timestamp_tokens(self, shard_id: str, header_hash_hex: str) -> list[dict[str, Any]]:
        """Retrieve all stored RFC 3161 timestamp tokens for a shard header."""
        header_hash_bytes = bytes.fromhex(header_hash_hex)
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                SELECT tsa_url, tst, gen_time, tsa_cert_fingerprint
                FROM timestamp_tokens
                WHERE shard_id = %s AND header_hash = %s
                ORDER BY gen_time ASC, tsa_url ASC
                """,
                (shard_id, header_hash_bytes),
            )
            rows = cur.fetchall()

        tokens: list[dict[str, Any]] = []
        for row in rows:
            ts_value = row["gen_time"]
            if isinstance(ts_value, datetime):
                timestamp_str = ts_value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            else:
                timestamp_str = str(ts_value)

            tokens.append(
                {
                    "tsa_url": row["tsa_url"],
                    "tst_hex": bytes(row["tst"]).hex(),
                    "hash_hex": header_hash_hex,
                    "timestamp": timestamp_str,
                    "tsa_cert_fingerprint": row["tsa_cert_fingerprint"],
                }
            )
        return tokens

    def get_timestamp_token(self, shard_id: str, header_hash_hex: str) -> dict[str, Any] | None:
        """Retrieve the first RFC 3161 timestamp token for a shard header, if stored."""
        tokens = self.get_timestamp_tokens(shard_id, header_hash_hex)
        if not tokens:
            return None
        return tokens[0]

    # ------------------------------------------------------------------
    # Rekor anchoring
    # ------------------------------------------------------------------

    def create_rekor_anchor(
        self,
        *,
        shard_id: str,
        shard_seq: int,
        root_hash: bytes,
    ) -> int:
        """Create a pending Rekor anchor record.

        Returns:
            The ID of the created anchor record.
        """
        if len(root_hash) != 32:
            raise ValueError(f"root_hash must be 32 bytes, got {len(root_hash)}")

        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                INSERT INTO rekor_anchors (shard_id, shard_seq, root_hash, status)
                VALUES (%s, %s, %s, 'pending')
                RETURNING id
                """,
                (shard_id, shard_seq, root_hash),
            )
            row = cur.fetchone()
            conn.commit()
            if row is None:
                raise RuntimeError("INSERT INTO rekor_anchors did not return an id")
            return int(row["id"])

    def update_rekor_anchor(
        self,
        *,
        anchor_id: int,
        status: str,
        rekor_uuid: str | None = None,
        rekor_index: int | None = None,
    ) -> None:
        """Update a Rekor anchor record with the anchoring result."""
        with self._get_connection() as conn, conn.cursor() as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                UPDATE rekor_anchors
                SET status = %s, rekor_uuid = %s, rekor_index = %s, anchored_at = NOW()
                WHERE id = %s
                """,
                (status, rekor_uuid, rekor_index, anchor_id),
            )
            conn.commit()

    def get_latest_rekor_anchor(self, shard_id: str) -> dict[str, Any] | None:
        """Get the most recent Rekor anchor for a shard."""
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                SELECT id, shard_id, shard_seq, root_hash, rekor_uuid, rekor_index,
                       anchored_at, status
                FROM rekor_anchors
                WHERE shard_id = %s
                ORDER BY shard_seq DESC, id DESC
                LIMIT 1
                """,
                (shard_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None

            return {
                "id": row["id"],
                "shard_id": row["shard_id"],
                "shard_seq": row["shard_seq"],
                "root_hash": bytes(row["root_hash"]).hex(),
                "rekor_uuid": row["rekor_uuid"],
                "rekor_index": row["rekor_index"],
                "anchored_at": _normalize_timestamp_iso(row["anchored_at"]),
                "status": row["status"],
            }

    def get_rekor_anchor_by_seq(self, shard_id: str, shard_seq: int) -> dict[str, Any] | None:
        """Get a Rekor anchor for a specific shard header sequence."""
        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                SELECT id, shard_id, shard_seq, root_hash, rekor_uuid, rekor_index,
                       anchored_at, status
                FROM rekor_anchors
                WHERE shard_id = %s AND shard_seq = %s
                ORDER BY id DESC
                LIMIT 1
                """,
                (shard_id, shard_seq),
            )
            row = cur.fetchone()
            if row is None:
                return None

            return {
                "id": row["id"],
                "shard_id": row["shard_id"],
                "shard_seq": row["shard_seq"],
                "root_hash": bytes(row["root_hash"]).hex(),
                "rekor_uuid": row["rekor_uuid"],
                "rekor_index": row["rekor_index"],
                "anchored_at": _normalize_timestamp_iso(row["anchored_at"]),
                "status": row["status"],
            }

    def verify_persisted_root(self, shard_id: str) -> bool:
        """Verify that the persisted root matches recomputed root from smt_nodes (O(1)).

        Returns:
            True if root is valid.
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
                return True

            persisted_root = bytes(row["root"])

            cur.execute("SELECT hash FROM smt_nodes WHERE level = 0 AND index = ''::bytea")
            node_row = cur.fetchone()
            if node_row is not None:
                computed_root = bytes(node_row["hash"])
            else:
                computed_root = EMPTY_HASHES[256]

            return persisted_root == computed_root
