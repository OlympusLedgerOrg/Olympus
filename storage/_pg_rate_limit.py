"""
Rate limiting mixin (token-bucket via PostgreSQL).

Internal to the storage package (_pg_* convention).
"""

from __future__ import annotations

from psycopg.rows import dict_row


class _RateLimitMixin:
    """PostgreSQL-backed token-bucket rate limiting."""

    def consume_rate_limit(
        self,
        *,
        subject_type: str,
        subject: str,
        action: str,
        capacity: float,
        refill_rate_per_second: float,
    ) -> bool:
        """Consume a rate-limit token using PostgreSQL for cross-worker coordination.

        All timestamps are sourced from the PostgreSQL server clock (``NOW()``) to
        prevent clock-skew attacks in distributed deployments.

        Returns:
            True if a token was consumed, False if the subject is rate limited.
        """
        if capacity <= 0 or refill_rate_per_second < 0:
            raise ValueError("capacity must be > 0 and refill_rate_per_second must be >= 0")

        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            cur.execute(
                """
                    INSERT INTO api_rate_limits
                        (subject_type, subject, action, tokens, last_refill_ts)
                    VALUES (%s, %s, %s, %s, NOW())
                    ON CONFLICT (subject_type, subject, action) DO NOTHING
                """,
                (subject_type, subject, action, capacity),
            )

            cur.execute(
                """
                    SELECT tokens,
                           EXTRACT(EPOCH FROM (NOW() - last_refill_ts)) AS elapsed_seconds
                    FROM api_rate_limits
                    WHERE subject_type = %s AND subject = %s AND action = %s
                    FOR UPDATE
                """,
                (subject_type, subject, action),
            )
            row = cur.fetchone()
            if row is None:
                raise RuntimeError("Failed to load rate limit state from database")

            elapsed = max(0.0, float(row["elapsed_seconds"]))
            tokens = round(min(capacity, row["tokens"] + elapsed * refill_rate_per_second), 6)

            if tokens < 1.0:
                conn.rollback()
                return False

            tokens -= 1.0
            cur.execute(
                """
                    UPDATE api_rate_limits
                    SET tokens = %s, last_refill_ts = NOW()
                    WHERE subject_type = %s AND subject = %s AND action = %s
                """,
                (tokens, subject_type, subject, action),
            )
            conn.commit()
            return True

    def clear_rate_limits(self) -> None:
        """Clear persisted rate-limit buckets (used by tests)."""
        with self._get_connection() as conn, conn.cursor() as cur:  # type: ignore[attr-defined]
            cur.execute("DELETE FROM api_rate_limits")
            conn.commit()
