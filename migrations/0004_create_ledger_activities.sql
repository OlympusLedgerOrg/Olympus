-- ledger_activities table (alembic: a9b8c7d6e5f4)

CREATE TABLE ledger_activities (
    id                VARCHAR(36) PRIMARY KEY,
    timestamp         TIMESTAMPTZ NOT NULL,
    activity_type     VARCHAR(64) NOT NULL,
    title             VARCHAR(255) NOT NULL,
    description       TEXT NOT NULL,
    related_commit_id VARCHAR(128),
    request_id        VARCHAR(36),
    details_json      TEXT,
    error_help_text   TEXT
);
CREATE INDEX ix_ledger_activities_timestamp        ON ledger_activities (timestamp);
CREATE INDEX ix_ledger_activities_activity_type    ON ledger_activities (activity_type);
CREATE INDEX ix_ledger_activities_related_commit_id ON ledger_activities (related_commit_id);
