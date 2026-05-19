-- display_id index column on ledger_activities (alembic: b3c4d5e6f7a8)

ALTER TABLE ledger_activities
    ADD COLUMN IF NOT EXISTS display_id VARCHAR(32);

CREATE INDEX IF NOT EXISTS ix_ledger_activities_display_id ON ledger_activities (display_id);
