-- Persistent rate-limit buckets shared across API workers
CREATE TABLE IF NOT EXISTS api_rate_limits (
    subject_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    action TEXT NOT NULL,
    tokens DOUBLE PRECISION NOT NULL,
    last_refill_ts TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (subject_type, subject, action)
);
