-- Add revoked_at and expires_at to api_keys so the auth middleware query works.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS revoked_at  TIMESTAMPTZ;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expires_at  TIMESTAMPTZ;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS revoked_by  VARCHAR(36);
