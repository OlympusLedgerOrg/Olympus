-- initial FOIA schema (alembic: 150ed68bf7cc)

CREATE TYPE agency_level AS ENUM ('MUNICIPAL', 'COUNTY', 'STATE', 'FEDERAL');
CREATE TYPE request_type AS ENUM ('NC_PUBLIC_RECORDS', 'FEDERAL_FOIA', 'FERPA');
CREATE TYPE request_status AS ENUM (
    'PENDING', 'ACKNOWLEDGED', 'IN_REVIEW', 'FULFILLED',
    'DENIED', 'OVERDUE', 'APPEALED'
);
CREATE TYPE request_priority AS ENUM (
    'STANDARD', 'EXPEDITED_SAFETY', 'EXPEDITED_PUBLIC_INTEREST'
);
CREATE TYPE appeal_grounds AS ENUM (
    'NO_RESPONSE', 'IMPROPER_EXEMPTION', 'PARTIAL_RESPONSE',
    'EXCESSIVE_FEE', 'BAD_FAITH'
);
CREATE TYPE appeal_status AS ENUM (
    'UNDER_REVIEW', 'UPHELD', 'OVERTURNED', 'DENIED_ON_APPEAL'
);

CREATE TABLE agencies (
    id          VARCHAR(36) PRIMARY KEY,
    name        VARCHAR(256) NOT NULL,
    short_name  VARCHAR(64) NOT NULL,
    level       agency_level NOT NULL,
    category    VARCHAR(128) NOT NULL,
    avg_response_days FLOAT,
    compliance_rate   FLOAT
);

CREATE TABLE key_credentials (
    id               VARCHAR(36) PRIMARY KEY,
    holder_key       VARCHAR(512) NOT NULL,
    credential_type  VARCHAR(64) NOT NULL,
    issued_at        TIMESTAMP NOT NULL,
    revoked_at       TIMESTAMP,
    issuer           VARCHAR(256) NOT NULL,
    sbt_nontransferable BOOLEAN NOT NULL,
    commit_id        VARCHAR(64) NOT NULL
);

CREATE TABLE merkle_nodes (
    id             VARCHAR(36) PRIMARY KEY,
    shard_id       VARCHAR(32) NOT NULL,
    level          INTEGER NOT NULL,
    position       INTEGER NOT NULL,
    hash           VARCHAR(64) NOT NULL,
    left_child_id  VARCHAR(36) REFERENCES merkle_nodes(id),
    right_child_id VARCHAR(36) REFERENCES merkle_nodes(id),
    created_at     TIMESTAMP NOT NULL
);
CREATE INDEX ix_merkle_nodes_shard_id ON merkle_nodes (shard_id);

CREATE TABLE public_records_requests (
    id              VARCHAR(36) PRIMARY KEY,
    display_id      VARCHAR(16) NOT NULL UNIQUE,
    subject         VARCHAR(512) NOT NULL,
    description     TEXT NOT NULL,
    agency_id       VARCHAR(36) REFERENCES agencies(id),
    request_type    request_type NOT NULL,
    status          request_status NOT NULL,
    date_from       TIMESTAMP,
    date_to         TIMESTAMP,
    response_format VARCHAR(128) NOT NULL,
    fee_waiver_basis TEXT,
    priority        request_priority NOT NULL,
    filed_at        TIMESTAMP NOT NULL,
    deadline        TIMESTAMP,
    fulfilled_at    TIMESTAMP,
    commit_hash     VARCHAR(64) NOT NULL,
    shard_id        VARCHAR(32) NOT NULL
);

CREATE TABLE appeals (
    id          VARCHAR(36) PRIMARY KEY,
    request_id  VARCHAR(36) NOT NULL REFERENCES public_records_requests(id),
    grounds     appeal_grounds NOT NULL,
    statement   TEXT NOT NULL,
    filed_at    TIMESTAMP NOT NULL,
    status      appeal_status NOT NULL,
    commit_hash VARCHAR(64) NOT NULL
);

CREATE TABLE doc_commits (
    id                  VARCHAR(36) PRIMARY KEY,
    request_id          VARCHAR(36) REFERENCES public_records_requests(id),
    doc_hash            VARCHAR(64) NOT NULL,
    commit_id           VARCHAR(64) NOT NULL UNIQUE,
    epoch_timestamp     TIMESTAMP NOT NULL,
    shard_id            VARCHAR(32) NOT NULL,
    merkle_root         VARCHAR(64),
    zk_proof            TEXT,
    embargo_until       TIMESTAMP,
    is_multi_recipient  BOOLEAN NOT NULL
);
