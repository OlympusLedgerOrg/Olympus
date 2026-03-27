"""
Tests for the DatasetArtifact ORM model.

Validates column definitions, defaults, nullable constraints, and
round-trip persistence via an in-memory SQLite database.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.models.base import Base
from api.models.dataset_artifact import DatasetArtifact


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
        "commit_id": "0x" + "b" * 62,
        "merkle_root": "c" * 64,
        "dataset_name": "test-dataset",
        "dataset_version": "1.0.0",
        "source_uri": "https://example.gov/data.csv",
        "granularity": "file",
        "license_spdx": "CC0-1.0",
        "usage_restrictions": ["no-commercial"],
        "manifest_hash": "d" * 64,
        "total_byte_size": 1024,
        "file_count": 1,
        "committer_label": "Test Org",
    }
    defaults.update(overrides)
    return DatasetArtifact(**defaults)


# ── Table structure tests ────────────────────────────────────────────────

class TestDatasetArtifactSchema:
    """Verify table name, column names, and constraints."""

    def test_tablename(self):
        assert DatasetArtifact.__tablename__ == "dataset_artifacts"

    def test_expected_columns_present(self):
        col_names = {c.name for c in DatasetArtifact.__table__.columns}
        expected = {
            "id", "dataset_id", "commit_id", "epoch_timestamp", "shard_id",
            "merkle_root", "dataset_name", "dataset_version", "source_uri",
            "granularity", "license_spdx", "license_uri", "usage_restrictions",
            "manifest_hash", "total_byte_size", "total_record_count",
            "file_count", "committer_label", "parent_dataset_id",
            "transform_description", "poseidon_hash",
        }
        assert expected == col_names

    def test_primary_key_is_id(self):
        pk_cols = [c.name for c in DatasetArtifact.__table__.primary_key.columns]
        assert pk_cols == ["id"]

    def test_commit_id_unique(self):
        col = DatasetArtifact.__table__.c.commit_id
        assert any(u for u in DatasetArtifact.__table__.indexes
                    if col in u.columns) or col.unique

    def test_dataset_id_indexed(self):
        col = DatasetArtifact.__table__.c.dataset_id
        assert any(
            idx for idx in DatasetArtifact.__table__.indexes
            if col in idx.columns
        )

    def test_nullable_optional_fields(self):
        nullable_cols = {
            "license_uri", "total_record_count", "parent_dataset_id",
            "transform_description", "poseidon_hash",
        }
        for name in nullable_cols:
            col = DatasetArtifact.__table__.c[name]
            assert col.nullable, f"{name} should be nullable"

    def test_non_nullable_required_fields(self):
        required_cols = {
            "id", "dataset_id", "commit_id", "epoch_timestamp", "shard_id",
            "merkle_root", "dataset_name", "dataset_version", "source_uri",
            "granularity", "license_spdx", "usage_restrictions",
            "manifest_hash", "total_byte_size", "file_count",
            "committer_label",
        }
        for name in required_cols:
            col = DatasetArtifact.__table__.c[name]
            assert not col.nullable, f"{name} should not be nullable"


# ── Defaults tests ───────────────────────────────────────────────────────

class TestDatasetArtifactDefaults:
    """Verify Python-side defaults (UUID, timestamp, shard_id)."""

    def test_id_auto_generated(self):
        artifact = _sample_artifact()
        assert artifact.id is not None
        uuid.UUID(artifact.id)  # validates it's a valid UUID

    def test_shard_id_default(self):
        artifact = _sample_artifact()
        assert artifact.shard_id == "0x4F3A"

    def test_epoch_timestamp_default(self):
        before = datetime.now(timezone.utc)
        artifact = _sample_artifact()
        after = datetime.now(timezone.utc)
        assert before <= artifact.epoch_timestamp <= after

    def test_usage_restrictions_default_empty_list(self):
        artifact = DatasetArtifact(
            dataset_id="a" * 64,
            commit_id="0x" + "b" * 62,
            merkle_root="c" * 64,
            dataset_name="ds",
            dataset_version="1.0.0",
            source_uri="https://example.gov",
            granularity="file",
            license_spdx="MIT",
            manifest_hash="d" * 64,
            total_byte_size=0,
            file_count=0,
            committer_label="test",
        )
        assert artifact.usage_restrictions == []


# ── Round-trip persistence ───────────────────────────────────────────────

class TestDatasetArtifactPersistence:
    """Verify insert and read via async SQLite session."""

    @pytest.mark.asyncio
    async def test_insert_and_read(self, db_session: AsyncSession):
        artifact = _sample_artifact()
        db_session.add(artifact)
        await db_session.flush()

        loaded = await db_session.get(DatasetArtifact, artifact.id)
        assert loaded is not None
        assert loaded.dataset_id == "a" * 64
        assert loaded.commit_id == "0x" + "b" * 62
        assert loaded.merkle_root == "c" * 64
        assert loaded.dataset_name == "test-dataset"
        assert loaded.dataset_version == "1.0.0"
        assert loaded.granularity == "file"
        assert loaded.license_spdx == "CC0-1.0"
        assert loaded.usage_restrictions == ["no-commercial"]
        assert loaded.manifest_hash == "d" * 64
        assert loaded.total_byte_size == 1024
        assert loaded.file_count == 1
        assert loaded.committer_label == "Test Org"
        assert loaded.shard_id == "0x4F3A"

    @pytest.mark.asyncio
    async def test_optional_fields_persist_none(self, db_session: AsyncSession):
        artifact = _sample_artifact(commit_id="0x" + "e" * 62)
        assert artifact.license_uri is None
        assert artifact.total_record_count is None
        assert artifact.parent_dataset_id is None
        assert artifact.transform_description is None
        assert artifact.poseidon_hash is None

        db_session.add(artifact)
        await db_session.flush()

        loaded = await db_session.get(DatasetArtifact, artifact.id)
        assert loaded is not None
        assert loaded.license_uri is None
        assert loaded.total_record_count is None
        assert loaded.parent_dataset_id is None
        assert loaded.transform_description is None
        assert loaded.poseidon_hash is None

    @pytest.mark.asyncio
    async def test_optional_fields_persist_values(self, db_session: AsyncSession):
        artifact = _sample_artifact(
            commit_id="0x" + "f" * 62,
            license_uri="https://example.gov/license",
            total_record_count=500,
            parent_dataset_id="p" * 64,
            transform_description="Filtered PII columns",
            poseidon_hash="h" * 64,
        )
        db_session.add(artifact)
        await db_session.flush()

        loaded = await db_session.get(DatasetArtifact, artifact.id)
        assert loaded is not None
        assert loaded.license_uri == "https://example.gov/license"
        assert loaded.total_record_count == 500
        assert loaded.parent_dataset_id == "p" * 64
        assert loaded.transform_description == "Filtered PII columns"
        assert loaded.poseidon_hash == "h" * 64


# ── Import test ──────────────────────────────────────────────────────────

class TestDatasetArtifactImport:
    """Verify DatasetArtifact is reachable through the models package."""

    def test_import_from_package(self):
        from api.models import DatasetArtifact as DA
        assert DA.__tablename__ == "dataset_artifacts"
