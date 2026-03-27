"""
Tests for dataset provenance models, hash functions, and schemas (ADR-0010 v4).

Validates:
  - ORM models: columns, constraints, defaults, round-trip persistence
  - Hash functions: deterministic dataset_key and commit_id (no timestamp)
  - Pydantic schemas: timestamp_status, key_revoked fields
  - Unique constraints: replay protection (D10)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.models.base import Base
from api.models.dataset import DatasetArtifact, DatasetArtifactFile, DatasetLineageEvent


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="module")
async def db_engine():
    engine = create_async_engine(TEST_DB_URL)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    async_session = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session
        await session.rollback()


def _sample_artifact(**overrides) -> DatasetArtifact:
    """Return a DatasetArtifact with valid defaults for all required fields."""
    defaults = {
        "dataset_id": "a" * 64,
        "commit_id": "b" * 64,
        "parent_commit_id": "",
        "merkle_root": None,
        "committer_pubkey": "c" * 64,
        "commit_signature": "d" * 128,
        "dataset_name": "test-dataset",
        "dataset_version": "1.0.0",
        "source_uri": "https://example.gov/data.csv",
        "canonical_namespace": "example.gov",
        "granularity": "file",
        "license_spdx": "CC0-1.0",
        "manifest_hash": "e" * 64,
        "total_byte_size": 1024,
        "file_count": 1,
        "file_format": "parquet",
        "committer_label": "Test Org",
    }
    defaults.update(overrides)
    return DatasetArtifact(**defaults)


# ── DatasetArtifact schema tests ─────────────────────────────────────────

class TestDatasetArtifactSchema:
    """Verify table name, columns, constraints, and indexes."""

    def test_tablename(self):
        assert DatasetArtifact.__tablename__ == "dataset_artifacts"

    def test_expected_columns_present(self):
        col_names = {c.name for c in DatasetArtifact.__table__.columns}
        expected = {
            "id", "dataset_id", "commit_id", "parent_commit_id",
            "epoch_timestamp", "shard_id", "merkle_root", "zk_proof",
            "committer_pubkey", "commit_signature", "committer_label",
            "rfc3161_tst_hex", "rfc3161_tsa_url", "timestamp_status",
            "anchor_tx_hash", "anchor_network", "anchor_block_height",
            "dataset_name", "dataset_version", "source_uri",
            "canonical_namespace", "granularity",
            "license_spdx", "license_uri", "usage_restrictions",
            "manifest_hash", "manifest_schema_version", "canonicalization_method",
            "total_byte_size", "total_record_count", "file_count", "file_format",
            "parent_dataset_id", "transform_description",
            "proof_bundle_uri", "poseidon_hash",
        }
        assert expected == col_names

    def test_primary_key_is_id(self):
        pk_cols = [c.name for c in DatasetArtifact.__table__.primary_key.columns]
        assert pk_cols == ["id"]

    def test_commit_id_unique(self):
        col = DatasetArtifact.__table__.c.commit_id
        assert col.unique

    def test_dataset_id_indexed(self):
        col = DatasetArtifact.__table__.c.dataset_id
        assert any(
            idx for idx in DatasetArtifact.__table__.indexes
            if "dataset_id" in {c.name for c in idx.columns}
        )

    def test_unique_constraint_replay_protection(self):
        """D10: UNIQUE(dataset_id, parent_commit_id, manifest_hash)."""
        constraint_names = {
            c.name for c in DatasetArtifact.__table__.constraints
            if hasattr(c, "name") and c.name
        }
        assert "uq_dataset_commit_content" in constraint_names

    def test_timestamp_status_column_exists(self):
        col = DatasetArtifact.__table__.c.timestamp_status
        assert not col.nullable

    def test_nullable_optional_fields(self):
        nullable_cols = {
            "merkle_root", "zk_proof", "committer_label",
            "rfc3161_tst_hex", "rfc3161_tsa_url",
            "anchor_tx_hash", "anchor_network", "anchor_block_height",
            "license_uri", "usage_restrictions",
            "total_record_count", "parent_dataset_id",
            "transform_description", "proof_bundle_uri", "poseidon_hash",
        }
        for name in nullable_cols:
            col = DatasetArtifact.__table__.c[name]
            assert col.nullable, f"{name} should be nullable"

    def test_non_nullable_required_fields(self):
        required_cols = {
            "id", "dataset_id", "commit_id", "parent_commit_id",
            "epoch_timestamp", "shard_id",
            "committer_pubkey", "commit_signature", "timestamp_status",
            "dataset_name", "dataset_version", "source_uri",
            "canonical_namespace", "granularity",
            "license_spdx", "manifest_hash", "manifest_schema_version",
            "canonicalization_method", "total_byte_size", "file_count",
            "file_format",
        }
        for name in required_cols:
            col = DatasetArtifact.__table__.c[name]
            assert not col.nullable, f"{name} should not be nullable"


# ── DatasetArtifactFile schema tests ─────────────────────────────────────

class TestDatasetArtifactFileSchema:
    def test_tablename(self):
        assert DatasetArtifactFile.__tablename__ == "dataset_artifact_files"

    def test_expected_columns(self):
        cols = {c.name for c in DatasetArtifactFile.__table__.columns}
        assert cols == {"id", "artifact_id", "path", "content_hash", "byte_size", "record_count"}

    def test_artifact_id_fk(self):
        col = DatasetArtifactFile.__table__.c.artifact_id
        fks = list(col.foreign_keys)
        assert len(fks) == 1
        assert fks[0].target_fullname == "dataset_artifacts.id"


# ── DatasetLineageEvent schema tests ─────────────────────────────────────

class TestDatasetLineageEventSchema:
    def test_tablename(self):
        assert DatasetLineageEvent.__tablename__ == "dataset_lineage_events"

    def test_unique_constraint(self):
        constraint_names = {
            c.name for c in DatasetLineageEvent.__table__.constraints
            if hasattr(c, "name") and c.name
        }
        assert "uq_lineage_event" in constraint_names

    def test_timestamp_status_column_exists(self):
        col = DatasetLineageEvent.__table__.c.timestamp_status
        assert not col.nullable

    def test_expected_columns(self):
        cols = {c.name for c in DatasetLineageEvent.__table__.columns}
        expected = {
            "id", "dataset_id", "commit_id", "parent_commit_id",
            "epoch_timestamp", "shard_id", "merkle_root",
            "committer_pubkey", "commit_signature", "timestamp_status",
            "model_id", "model_version", "model_org", "event_type",
        }
        assert expected == cols


# ── Defaults tests ───────────────────────────────────────────────────────

class TestDatasetArtifactDefaults:
    """Verify Python-side defaults after DB flush (SQLAlchemy evaluates defaults at INSERT)."""

    @pytest.mark.asyncio
    async def test_id_auto_generated(self, db_session: AsyncSession):
        artifact = _sample_artifact(commit_id="z1" + "a" * 62)
        db_session.add(artifact)
        await db_session.flush()
        assert artifact.id is not None
        uuid.UUID(artifact.id)

    @pytest.mark.asyncio
    async def test_shard_id_default(self, db_session: AsyncSession):
        artifact = _sample_artifact(commit_id="z2" + "a" * 62)
        db_session.add(artifact)
        await db_session.flush()
        assert artifact.shard_id == "0x4F3A"

    @pytest.mark.asyncio
    async def test_epoch_timestamp_default(self, db_session: AsyncSession):
        before = datetime.now(timezone.utc)
        artifact = _sample_artifact(commit_id="z3" + "a" * 62)
        db_session.add(artifact)
        await db_session.flush()
        after = datetime.now(timezone.utc)
        assert artifact.epoch_timestamp is not None
        assert before <= artifact.epoch_timestamp.replace(tzinfo=timezone.utc) <= after

    @pytest.mark.asyncio
    async def test_timestamp_status_default_pending(self, db_session: AsyncSession):
        artifact = _sample_artifact(commit_id="z4" + "a" * 62)
        db_session.add(artifact)
        await db_session.flush()
        assert artifact.timestamp_status == "pending"

    def test_parent_commit_id_default_empty(self):
        artifact = _sample_artifact()
        # parent_commit_id is set explicitly in _sample_artifact
        assert artifact.parent_commit_id == ""

    @pytest.mark.asyncio
    async def test_manifest_schema_version_default(self, db_session: AsyncSession):
        artifact = _sample_artifact(commit_id="z5" + "a" * 62)
        db_session.add(artifact)
        await db_session.flush()
        assert artifact.manifest_schema_version == "dataset_manifest_v1"

    @pytest.mark.asyncio
    async def test_canonicalization_method_default(self, db_session: AsyncSession):
        artifact = _sample_artifact(commit_id="z6" + "a" * 62)
        db_session.add(artifact)
        await db_session.flush()
        assert artifact.canonicalization_method == "canonical_json_v2"


# ── Hash functions (v4: no timestamp, pubkey in dataset_key) ─────────────

class TestHashFunctions:
    """Verify deterministic hash functions per ADR-0010 v4."""

    def test_dataset_key_deterministic(self):
        from protocol.hashes import dataset_key

        key1 = dataset_key("ds", "https://ex.com", "ns", "aa" * 32)
        key2 = dataset_key("ds", "https://ex.com", "ns", "aa" * 32)
        assert key1 == key2
        assert len(key1) == 64

    def test_dataset_key_includes_pubkey(self):
        """Different pubkeys produce different dataset_ids."""
        from protocol.hashes import dataset_key

        key_a = dataset_key("ds", "https://ex.com", "ns", "aa" * 32)
        key_b = dataset_key("ds", "https://ex.com", "ns", "bb" * 32)
        assert key_a != key_b

    def test_commit_id_no_timestamp(self):
        """commit_id is content-only — no timestamp argument."""
        from protocol.hashes import compute_dataset_commit_id

        cid = compute_dataset_commit_id("a" * 64, "", "b" * 64, "c" * 64)
        assert len(cid) == 64
        # Same inputs → same output
        cid2 = compute_dataset_commit_id("a" * 64, "", "b" * 64, "c" * 64)
        assert cid == cid2

    def test_commit_id_changes_with_parent(self):
        from protocol.hashes import compute_dataset_commit_id

        cid1 = compute_dataset_commit_id("a" * 64, "", "b" * 64, "c" * 64)
        cid2 = compute_dataset_commit_id("a" * 64, "f" * 64, "b" * 64, "c" * 64)
        assert cid1 != cid2

    def test_commit_id_changes_with_manifest(self):
        from protocol.hashes import compute_dataset_commit_id

        cid1 = compute_dataset_commit_id("a" * 64, "", "b" * 64, "c" * 64)
        cid2 = compute_dataset_commit_id("a" * 64, "", "e" * 64, "c" * 64)
        assert cid1 != cid2

    def test_domain_prefixes_exist(self):
        from protocol.hashes import (
            DATASET_COMMIT_PREFIX,
            DATASET_LINEAGE_PREFIX,
            DATASET_PREFIX,
        )

        assert DATASET_PREFIX == b"OLY:DATASET:V1"
        assert DATASET_COMMIT_PREFIX == b"OLY:DATASET-COMMIT:V1"
        assert DATASET_LINEAGE_PREFIX == b"OLY:DATASET-LINEAGE:V1"


# ── Pydantic schema tests (v4 fields) ───────────────────────────────────

class TestPydanticSchemas:
    def test_commit_response_has_timestamp_status(self):
        from api.schemas.dataset import DatasetCommitResponse

        resp = DatasetCommitResponse(
            dataset_id="a" * 64, commit_id="b" * 64, manifest_hash="c" * 64,
            epoch=datetime.now(timezone.utc), shard_id="0x4F3A",
            merkle_root=None, file_count=1, timestamp_status="verified",
        )
        assert resp.timestamp_status == "verified"

    def test_verify_response_has_key_revoked(self):
        from api.schemas.dataset import DatasetVerifyResponse

        resp = DatasetVerifyResponse(verified=False, key_revoked=True)
        assert resp.key_revoked is True

    def test_lineage_response_has_timestamp_status(self):
        from api.schemas.dataset import LineageCommitResponse

        resp = LineageCommitResponse(
            commit_id="d" * 64, dataset_id="a" * 64, model_id="m1",
            event_type="evaluation", epoch=datetime.now(timezone.utc),
            timestamp_status="pending",
        )
        assert resp.timestamp_status == "pending"


# ── Round-trip persistence ───────────────────────────────────────────────

class TestDatasetArtifactPersistence:
    @pytest.mark.asyncio
    async def test_insert_and_read(self, db_session: AsyncSession):
        artifact = _sample_artifact()
        db_session.add(artifact)
        await db_session.flush()

        loaded = await db_session.get(DatasetArtifact, artifact.id)
        assert loaded is not None
        assert loaded.dataset_id == "a" * 64
        assert loaded.commit_id == "b" * 64
        assert loaded.parent_commit_id == ""
        assert loaded.committer_pubkey == "c" * 64
        assert loaded.commit_signature == "d" * 128
        assert loaded.timestamp_status == "pending"
        assert loaded.manifest_hash == "e" * 64
        assert loaded.file_format == "parquet"
        assert loaded.canonical_namespace == "example.gov"

    @pytest.mark.asyncio
    async def test_optional_fields_persist_none(self, db_session: AsyncSession):
        artifact = _sample_artifact(commit_id="f" * 64)
        assert artifact.rfc3161_tst_hex is None
        assert artifact.anchor_tx_hash is None
        assert artifact.poseidon_hash is None
        assert artifact.proof_bundle_uri is None

        db_session.add(artifact)
        await db_session.flush()

        loaded = await db_session.get(DatasetArtifact, artifact.id)
        assert loaded is not None
        assert loaded.rfc3161_tst_hex is None
        assert loaded.anchor_tx_hash is None
        assert loaded.poseidon_hash is None
        assert loaded.proof_bundle_uri is None

    @pytest.mark.asyncio
    async def test_files_relationship(self, db_session: AsyncSession):
        artifact = _sample_artifact(commit_id="1" * 64)
        db_session.add(artifact)
        await db_session.flush()

        file_entry = DatasetArtifactFile(
            artifact_id=artifact.id,
            path="data/train.parquet",
            content_hash="f" * 64,
            byte_size=512,
        )
        db_session.add(file_entry)
        await db_session.flush()

        loaded = await db_session.get(DatasetArtifact, artifact.id)
        assert loaded is not None
        # Relationship loaded
        await db_session.refresh(loaded, ["files"])
        assert len(loaded.files) == 1
        assert loaded.files[0].path == "data/train.parquet"

    @pytest.mark.asyncio
    async def test_unique_constraint_prevents_replay(self, db_session: AsyncSession):
        """D10: Same (dataset_id, parent_commit_id, manifest_hash) → IntegrityError."""
        a1 = _sample_artifact(
            commit_id="2" * 64,
            dataset_id="x" * 64,
            parent_commit_id="",
            manifest_hash="y" * 64,
        )
        db_session.add(a1)
        await db_session.flush()

        a2 = _sample_artifact(
            commit_id="3" * 64,
            dataset_id="x" * 64,
            parent_commit_id="",
            manifest_hash="y" * 64,
        )
        db_session.add(a2)
        with pytest.raises(IntegrityError):
            await db_session.flush()
        await db_session.rollback()

    @pytest.mark.asyncio
    async def test_lineage_event_persistence(self, db_session: AsyncSession):
        event = DatasetLineageEvent(
            dataset_id="a" * 64,
            commit_id="4" * 64,
            parent_commit_id="",
            committer_pubkey="c" * 64,
            commit_signature="d" * 128,
            model_id="gpt-5",
            event_type="training_completed",
        )
        db_session.add(event)
        await db_session.flush()

        loaded = await db_session.get(DatasetLineageEvent, event.id)
        assert loaded is not None
        assert loaded.model_id == "gpt-5"
        assert loaded.event_type == "training_completed"
        assert loaded.timestamp_status == "pending"

    @pytest.mark.asyncio
    async def test_lineage_unique_constraint(self, db_session: AsyncSession):
        """Unique(dataset_id, model_id, event_type, committer_pubkey)."""
        e1 = DatasetLineageEvent(
            dataset_id="g" * 64,
            commit_id="5" * 64,
            committer_pubkey="c" * 64,
            commit_signature="d" * 128,
            model_id="llama-3",
            event_type="evaluation",
        )
        db_session.add(e1)
        await db_session.flush()

        e2 = DatasetLineageEvent(
            dataset_id="g" * 64,
            commit_id="6" * 64,
            committer_pubkey="c" * 64,
            commit_signature="d" * 128,
            model_id="llama-3",
            event_type="evaluation",
        )
        db_session.add(e2)
        with pytest.raises(IntegrityError):
            await db_session.flush()
        await db_session.rollback()


# ── Import test ──────────────────────────────────────────────────────────

class TestImports:
    def test_import_from_package(self):
        from api.models import DatasetArtifact as DA
        from api.models import DatasetArtifactFile as DAF
        from api.models import DatasetLineageEvent as DLE

        assert DA.__tablename__ == "dataset_artifacts"
        assert DAF.__tablename__ == "dataset_artifact_files"
        assert DLE.__tablename__ == "dataset_lineage_events"
