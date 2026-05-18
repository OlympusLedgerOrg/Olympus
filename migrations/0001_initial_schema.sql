-- Consolidated initial schema converted from Alembic migrations.
-- All 13 Alembic versions collapsed into one idempotent baseline.

-- ── Enums ─────────────────────────────────────────────────────────────────────

DO $$ BEGIN
    CREATE TYPE agency_level AS ENUM ('MUNICIPAL', 'COUNTY', 'STATE', 'FEDERAL');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE request_type AS ENUM ('NC_PUBLIC_RECORDS', 'FEDERAL_FOIA', 'FERPA');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE request_status AS ENUM (
        'PENDING', 'ACKNOWLEDGED', 'IN_REVIEW', 'FULFILLED',
        'DENIED', 'OVERDUE', 'APPEALED'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE request_priority AS ENUM (
        'STANDARD', 'EXPEDITED_SAFETY', 'EXPEDITED_PUBLIC_INTEREST'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE appeal_grounds AS ENUM (
        'NO_RESPONSE', 'IMPROPER_EXEMPTION', 'PARTIAL_RESPONSE',
        'EXCESSIVE_FEE', 'BAD_FAITH'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE appeal_status AS ENUM (
        'UNDER_REVIEW', 'UPHELD', 'OVERTURNED', 'DENIED_ON_APPEAL'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ── Core tables ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS agencies (
    id               VARCHAR(36) PRIMARY KEY,
    name             VARCHAR(256) NOT NULL,
    short_name       VARCHAR(64)  NOT NULL,
    level            agency_level NOT NULL,
    category         VARCHAR(128) NOT NULL,
    avg_response_days FLOAT,
    compliance_rate  FLOAT
);

CREATE TABLE IF NOT EXISTS key_credentials (
    id                  VARCHAR(36) PRIMARY KEY,
    holder_key          VARCHAR(512) NOT NULL,
    credential_type     VARCHAR(64)  NOT NULL,
    issued_at           TIMESTAMPTZ  NOT NULL,
    revoked_at          TIMESTAMPTZ,
    issuer              VARCHAR(256) NOT NULL,
    sbt_nontransferable BOOLEAN      NOT NULL,
    commit_id           VARCHAR(64)  NOT NULL,
    revocation_commit_id VARCHAR(64),
    issued_by_key_id    VARCHAR(36)
);

CREATE TABLE IF NOT EXISTS merkle_nodes (
    id             VARCHAR(36) PRIMARY KEY,
    shard_id       VARCHAR(32) NOT NULL,
    level          INTEGER     NOT NULL,
    position       INTEGER     NOT NULL,
    hash           VARCHAR(64) NOT NULL,
    left_child_id  VARCHAR(36) REFERENCES merkle_nodes(id),
    right_child_id VARCHAR(36) REFERENCES merkle_nodes(id),
    created_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_merkle_nodes_shard_id ON merkle_nodes(shard_id);

CREATE TABLE IF NOT EXISTS public_records_requests (
    id              VARCHAR(36) PRIMARY KEY,
    display_id      VARCHAR(16) NOT NULL UNIQUE,
    subject         VARCHAR(512) NOT NULL,
    description     TEXT         NOT NULL,
    agency_id       VARCHAR(36)  REFERENCES agencies(id),
    request_type    request_type NOT NULL,
    status          request_status NOT NULL,
    date_from       TIMESTAMPTZ,
    date_to         TIMESTAMPTZ,
    response_format VARCHAR(128) NOT NULL,
    fee_waiver_basis TEXT,
    priority        request_priority NOT NULL,
    filed_at        TIMESTAMPTZ NOT NULL,
    deadline        TIMESTAMPTZ,
    fulfilled_at    TIMESTAMPTZ,
    commit_hash     VARCHAR(64) NOT NULL,
    shard_id        VARCHAR(32) NOT NULL
);

CREATE SEQUENCE IF NOT EXISTS display_id_seq START 1000;

CREATE TABLE IF NOT EXISTS appeals (
    id          VARCHAR(36) PRIMARY KEY,
    request_id  VARCHAR(36) NOT NULL REFERENCES public_records_requests(id),
    grounds     appeal_grounds NOT NULL,
    statement   TEXT        NOT NULL,
    filed_at    TIMESTAMPTZ NOT NULL,
    status      appeal_status NOT NULL,
    commit_hash VARCHAR(64) NOT NULL
);

-- ── Document commits (primary ledger table) ───────────────────────────────────

CREATE TABLE IF NOT EXISTS doc_commits (
    id                 VARCHAR(36) PRIMARY KEY,
    request_id         VARCHAR(36) REFERENCES public_records_requests(id),
    doc_hash           VARCHAR(64) NOT NULL,
    commit_id          VARCHAR(64) NOT NULL UNIQUE,
    epoch_timestamp    TIMESTAMPTZ NOT NULL,
    shard_id           VARCHAR(32) NOT NULL,
    merkle_root        VARCHAR(64),
    zk_proof           TEXT,
    embargo_until      TIMESTAMPTZ,
    is_multi_recipient BOOLEAN     NOT NULL DEFAULT FALSE
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_doc_commits_doc_hash ON doc_commits(doc_hash);
CREATE INDEX IF NOT EXISTS ix_doc_commits_shard_id ON doc_commits(shard_id);

-- ── Dataset artifacts ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS dataset_artifacts (
    id           VARCHAR(36) PRIMARY KEY,
    artifact_hash VARCHAR(64) NOT NULL UNIQUE,
    namespace    VARCHAR(256) NOT NULL,
    artifact_id  VARCHAR(512) NOT NULL,
    source_url   TEXT,
    raw_pdf_hash VARCHAR(64),
    committed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    commit_id    VARCHAR(64)
);

-- ── TSA (RFC 3161 timestamp) jobs ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tsa_jobs (
    id           VARCHAR(36) PRIMARY KEY,
    commit_id    VARCHAR(64) NOT NULL,
    status       VARCHAR(32) NOT NULL DEFAULT 'pending',
    tsr_bytes    BYTEA,
    tsa_url      TEXT,
    attempted_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_tsa_jobs_commit_id ON tsa_jobs(commit_id);
CREATE INDEX IF NOT EXISTS ix_tsa_jobs_status ON tsa_jobs(status);

-- ── Ledger activity feed ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ledger_activities (
    id                 BIGSERIAL PRIMARY KEY,
    activity_type      VARCHAR(64) NOT NULL,
    timestamp          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    related_commit_id  VARCHAR(64),
    details_json       JSONB,
    display_id         VARCHAR(16)
);
CREATE INDEX IF NOT EXISTS ix_ledger_activities_type ON ledger_activities(activity_type);
CREATE INDEX IF NOT EXISTS ix_ledger_activities_ts   ON ledger_activities(timestamp DESC);

-- ── Users & API keys ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id            VARCHAR(36) PRIMARY KEY,
    email         VARCHAR(320) NOT NULL,
    password_hash VARCHAR(256),
    role          VARCHAR(32)  NOT NULL DEFAULT 'user',
    plan          VARCHAR(32)  NOT NULL DEFAULT 'free',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users(email);

CREATE TABLE IF NOT EXISTS api_keys (
    id         VARCHAR(36) PRIMARY KEY,
    user_id    VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash   VARCHAR(64) NOT NULL,
    key_id     VARCHAR(36),
    name       VARCHAR(128) NOT NULL,
    scopes     TEXT         NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_api_keys_user_id  ON api_keys(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_api_keys_key_hash ON api_keys(key_hash);

-- ── Rekor anchors & guardian quorum ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS rekor_anchors (
    id           VARCHAR(36) PRIMARY KEY,
    commit_id    VARCHAR(64) NOT NULL UNIQUE,
    log_index    BIGINT,
    log_id       TEXT,
    entry_hash   VARCHAR(64),
    anchored_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS guardian_signatures (
    id           VARCHAR(36) PRIMARY KEY,
    commit_id    VARCHAR(64) NOT NULL,
    guardian_key VARCHAR(128) NOT NULL,
    signature    TEXT         NOT NULL,
    signed_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_guardian_sigs_commit ON guardian_signatures(commit_id);
