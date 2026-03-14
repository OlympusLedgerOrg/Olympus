"""
Operational state operations for the Olympus storage layer.

This module isolates operational plumbing — rate limiting, ingestion batch
tracking, and timestamp token management — from protocol-critical state.

Operational state tables:
    - api_rate_limits: Token-bucket rate limiting with PostgreSQL coordination
    - ingestion_batches / ingestion_proofs: Ingestion durability metadata
    - timestamp_tokens: RFC 3161 timestamp token persistence

Bugs in this module cannot compromise cryptographic guarantees (hashes,
signatures, Merkle roots, chain linkage) because protocol state is managed
separately in :mod:`storage.protocol_state`.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from psycopg.rows import dict_row

from protocol.rfc3161 import MAX_TSA_TOKENS, _sha256_of_hash


if TYPE_CHECKING:
    import psycopg

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


def consume_rate_limit(
    conn: psycopg.Connection[Any],
    *,
    subject_type: str,
    subject: str,
    action: str,
    capacity: float,
    refill_rate_per_second: float,
) -> bool:
    """
    Consume a rate-limit token using PostgreSQL for cross-worker coordination.

    Returns:
        True if a token was consumed, False if the subject is rate-limited.
    """
    if capacity <= 0 or refill_rate_per_second < 0:
        raise ValueError("capacity must be > 0 and refill_rate_per_second must be >= 0")

    now = datetime.now(timezone.utc)

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO api_rate_limits (subject_type, subject, action, tokens, last_refill_ts)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (subject_type, subject, action) DO NOTHING
            """,
            (subject_type, subject, action, capacity, now),
        )

        cur.execute(
            """
            SELECT tokens, last_refill_ts
            FROM api_rate_limits
            WHERE subject_type = %s AND subject = %s AND action = %s
            FOR UPDATE
            """,
            (subject_type, subject, action),
        )
        row = cur.fetchone()
        if row is None:
            raise RuntimeError("Failed to load rate limit state from database")

        elapsed = max(0.0, (now - row["last_refill_ts"]).total_seconds())
        tokens = min(capacity, row["tokens"] + elapsed * refill_rate_per_second)

        if tokens < 1.0:
            conn.rollback()
            return False

        tokens -= 1.0
        cur.execute(
            """
            UPDATE api_rate_limits
            SET tokens = %s, last_refill_ts = %s
            WHERE subject_type = %s AND subject = %s AND action = %s
            """,
            (tokens, now, subject_type, subject, action),
        )
        conn.commit()
        return True


def clear_rate_limits(conn: psycopg.Connection[Any]) -> None:
    """Clear persisted rate-limit buckets (used by tests)."""
    with conn.cursor() as cur:
        cur.execute("DELETE FROM api_rate_limits")
        conn.commit()


# ---------------------------------------------------------------------------
# Ingestion batches
# ---------------------------------------------------------------------------


def store_ingestion_batch(
    conn: psycopg.Connection[Any],
    batch_id: str,
    records: list[dict[str, Any]],
) -> None:
    """Persist proof_id-to-record mappings for ingestion durability."""
    if not records:
        return

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO ingestion_batches (batch_id)
            VALUES (%s)
            ON CONFLICT (batch_id) DO NOTHING
            """,
            (batch_id,),
        )

        for idx, record in enumerate(records):
            cur.execute(
                """
                INSERT INTO ingestion_proofs (
                    proof_id, batch_id, batch_index, shard_id,
                    record_type, record_id, version, content_hash,
                    merkle_root, merkle_proof, ledger_entry_hash,
                    ts, canonicalization, persisted
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (proof_id) DO NOTHING
                """,
                (
                    record["proof_id"],
                    batch_id,
                    record.get("batch_index", idx),
                    record["shard_id"],
                    record.get("record_type", "document"),
                    record["record_id"],
                    record.get("version", 1),
                    bytes.fromhex(record["content_hash"]),
                    bytes.fromhex(record["merkle_root"]),
                    json.dumps(record["merkle_proof"]),
                    bytes.fromhex(record["ledger_entry_hash"]),
                    record["timestamp"],
                    json.dumps(record.get("canonicalization")),
                    record.get("persisted", True),
                ),
            )

        conn.commit()


def get_ingestion_proof(conn: psycopg.Connection[Any], proof_id: str) -> dict[str, Any] | None:
    """Retrieve a persisted ingestion proof mapping by proof_id."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT
                proof_id, batch_id, batch_index, shard_id,
                record_type, record_id, version, content_hash,
                merkle_root, merkle_proof, ledger_entry_hash,
                ts, canonicalization, persisted
            FROM ingestion_proofs
            WHERE proof_id = %s
            LIMIT 1
            """,
            (proof_id,),
        )
        row = cur.fetchone()

    if row is None:
        return None

    ts_value = row["ts"]
    ts = (
        ts_value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if isinstance(ts_value, datetime)
        else str(ts_value)
    )

    return {
        "proof_id": row["proof_id"],
        "batch_id": row["batch_id"],
        "batch_index": row["batch_index"],
        "record_id": row["record_id"],
        "record_type": row["record_type"],
        "version": row["version"],
        "shard_id": row["shard_id"],
        "content_hash": bytes(row["content_hash"]).hex(),
        "merkle_root": bytes(row["merkle_root"]).hex(),
        "merkle_proof": row["merkle_proof"],
        "ledger_entry_hash": bytes(row["ledger_entry_hash"]).hex(),
        "timestamp": ts,
        "canonicalization": row["canonicalization"],
        "persisted": row.get("persisted", True),
    }


# ---------------------------------------------------------------------------
# Timestamp tokens
# ---------------------------------------------------------------------------


def store_timestamp_token(
    conn: psycopg.Connection[Any],
    shard_id: str,
    header_hash_hex: str,
    token: Any,
) -> None:
    """
    Persist an RFC 3161 timestamp token for a shard header.

    Idempotent – a second insert for the same ``(shard_id, header_hash)``
    is silently ignored.
    """
    header_hash_bytes = bytes.fromhex(header_hash_hex)
    if len(header_hash_bytes) != 32:
        raise ValueError(
            f"header_hash_hex must encode exactly 32 bytes, got {len(header_hash_bytes)}"
        )

    hash_hex = token.hash_hex if hasattr(token, "hash_hex") else token["hash_hex"]
    tsa_url = token.tsa_url if hasattr(token, "tsa_url") else token["tsa_url"]
    tst_bytes = token.tst_bytes if hasattr(token, "tst_bytes") else bytes.fromhex(token["tst_hex"])
    tsa_cert_fingerprint = (
        token.tsa_cert_fingerprint
        if hasattr(token, "tsa_cert_fingerprint")
        else token.get("tsa_cert_fingerprint")
    )
    timestamp = token.timestamp if hasattr(token, "timestamp") else token["timestamp"]
    ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    imprint_hash = _sha256_of_hash(hash_hex)

    with conn.cursor(row_factory=dict_row) as cur:
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
                (shard_id, header_hash, tsa_url, tst, imprint_hash, gen_time, tsa_cert_fingerprint)
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


def get_timestamp_tokens(
    conn: psycopg.Connection[Any],
    shard_id: str,
    header_hash_hex: str,
) -> list[dict[str, Any]]:
    """Retrieve all stored RFC 3161 timestamp tokens for a shard header."""
    header_hash_bytes = bytes.fromhex(header_hash_hex)
    with conn.cursor(row_factory=dict_row) as cur:
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
            timestamp_str = ts_value.isoformat().replace("+00:00", "Z")
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
