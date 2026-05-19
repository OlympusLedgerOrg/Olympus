-- dataset provenance tables ADR-0010 v4 (alembic: a1b2c3d4e5f6)

CREATE TABLE dataset_artifacts (
    id                      VARCHAR(36) PRIMARY KEY,
    dataset_id              VARCHAR(64) NOT NULL,
    commit_id               VARCHAR(64) NOT NULL,
    parent_commit_id        VARCHAR(64) NOT NULL DEFAULT '',
    epoch_timestamp         TIMESTAMP NOT NULL,
    shard_id                VARCHAR(32) NOT NULL DEFAULT '0x4F3A',
    merkle_root             VARCHAR(64),
    zk_proof                TEXT,
    committer_pubkey        VARCHAR(64) NOT NULL,
    commit_signature        VARCHAR(128) NOT NULL,
    committer_label         VARCHAR(256),
    rfc3161_tst_hex         TEXT,
    rfc3161_tsa_url         VARCHAR(512),
    timestamp_status        VARCHAR(16) NOT NULL DEFAULT 'pending',
    anchor_tx_hash          VARCHAR(128),
    anchor_network          VARCHAR(32),
    anchor_block_height     INTEGER,
    dataset_name            VARCHAR(256) NOT NULL,
    dataset_version         VARCHAR(64) NOT NULL,
    source_uri              VARCHAR(2048) NOT NULL,
    canonical_namespace     VARCHAR(256) NOT NULL,
    granularity             VARCHAR(16) NOT NULL,
    license_spdx            VARCHAR(64) NOT NULL,
    license_uri             VARCHAR(2048),
    usage_restrictions      TEXT,
    manifest_hash           VARCHAR(64) NOT NULL,
    manifest_schema_version VARCHAR(32) NOT NULL DEFAULT 'dataset_manifest_v1',
    canonicalization_method VARCHAR(32) NOT NULL DEFAULT 'canonical_json_v2',
    total_byte_size         BIGINT NOT NULL,
    total_record_count      INTEGER,
    file_count              INTEGER NOT NULL,
    file_format             VARCHAR(32) NOT NULL,
    parent_dataset_id       VARCHAR(64),
    transform_description   TEXT,
    proof_bundle_uri        VARCHAR(2048),
    poseidon_hash           VARCHAR(78),
    CONSTRAINT uq_dataset_commit_content
        UNIQUE (dataset_id, parent_commit_id, manifest_hash)
);
CREATE INDEX ix_dataset_artifacts_dataset_id      ON dataset_artifacts (dataset_id);
CREATE UNIQUE INDEX ix_dataset_artifacts_commit_id ON dataset_artifacts (commit_id);
CREATE INDEX ix_dataset_artifacts_shard_id        ON dataset_artifacts (shard_id);
CREATE INDEX ix_dataset_artifacts_license_spdx    ON dataset_artifacts (license_spdx);
CREATE INDEX ix_dataset_artifacts_committer_pubkey ON dataset_artifacts (committer_pubkey);

CREATE TABLE dataset_artifact_files (
    id          VARCHAR(36) PRIMARY KEY,
    artifact_id VARCHAR(36) NOT NULL REFERENCES dataset_artifacts(id),
    path        VARCHAR(2048) NOT NULL,
    content_hash VARCHAR(64) NOT NULL,
    byte_size   BIGINT NOT NULL,
    record_count INTEGER
);
CREATE INDEX ix_dataset_artifact_files_artifact_id ON dataset_artifact_files (artifact_id);

CREATE TABLE dataset_lineage_events (
    id                VARCHAR(36) PRIMARY KEY,
    dataset_id        VARCHAR(64) NOT NULL,
    commit_id         VARCHAR(64) NOT NULL,
    parent_commit_id  VARCHAR(64) NOT NULL DEFAULT '',
    epoch_timestamp   TIMESTAMP NOT NULL,
    shard_id          VARCHAR(32) NOT NULL DEFAULT '0x4F3A',
    merkle_root       VARCHAR(64),
    committer_pubkey  VARCHAR(64) NOT NULL,
    commit_signature  VARCHAR(128) NOT NULL,
    timestamp_status  VARCHAR(16) NOT NULL DEFAULT 'pending',
    model_id          VARCHAR(256) NOT NULL,
    model_version     VARCHAR(64),
    model_org         VARCHAR(256),
    event_type        VARCHAR(32) NOT NULL,
    CONSTRAINT uq_lineage_event
        UNIQUE (dataset_id, model_id, event_type, committer_pubkey)
);
CREATE INDEX ix_dataset_lineage_events_dataset_id  ON dataset_lineage_events (dataset_id);
CREATE INDEX ix_dataset_lineage_events_model_id    ON dataset_lineage_events (model_id);
CREATE UNIQUE INDEX ix_dataset_lineage_events_commit_id ON dataset_lineage_events (commit_id);
