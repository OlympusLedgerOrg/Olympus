"""
DatasetArtifact ORM model.

Records the cryptographic commitment of an entire dataset to the Olympus
ledger.  Each row captures dataset identity, licensing, content fingerprint,
and provenance metadata alongside the standard ledger anchoring fields.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class DatasetArtifact(Base):
    """A dataset-level artifact committed to the Olympus ledger.

    Attributes:
        id: UUID primary key.
        dataset_id: BLAKE3 hex hash of the delimited dataset key.
        commit_id: ``0x``-prefixed server-generated commit identifier.
        epoch_timestamp: Server-set UTC timestamp of the commitment.
        shard_id: Ledger shard this artifact belongs to.
        merkle_root: Merkle root recomputed after commit.
        dataset_name: Human-readable name of the dataset.
        dataset_version: Semantic version of the dataset.
        source_uri: URI pointing to the dataset origin.
        granularity: Commit granularity (``"file"``, ``"record"``, or ``"shard"``).
        license_spdx: SPDX license identifier.
        license_uri: Optional URI to the full license text.
        usage_restrictions: JSON list of usage restriction strings.
        manifest_hash: BLAKE3 hex hash of the full manifest JSON.
        total_byte_size: Total size of the dataset in bytes.
        total_record_count: Optional total number of records.
        file_count: Number of files in the dataset.
        committer_label: Organisation or person name (not a public key).
        parent_dataset_id: Optional BLAKE3 hash of the parent dataset.
        transform_description: Optional description of the transformation
            applied to derive this dataset from its parent.
        poseidon_hash: Optional Poseidon hash for ZK circuit binding.
    """

    __tablename__ = "dataset_artifacts"

    # --- Ledger anchoring ---------------------------------------------------
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    dataset_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    commit_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    epoch_timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    shard_id: Mapped[str] = mapped_column(String(32), nullable=False, default="0x4F3A")
    merkle_root: Mapped[str] = mapped_column(String(64), nullable=False)

    # --- Dataset identity ---------------------------------------------------
    dataset_name: Mapped[str] = mapped_column(String(256), nullable=False)
    dataset_version: Mapped[str] = mapped_column(String(64), nullable=False)
    source_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    granularity: Mapped[str] = mapped_column(String(32), nullable=False)

    # --- Licensing ----------------------------------------------------------
    license_spdx: Mapped[str] = mapped_column(String(128), nullable=False)
    license_uri: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    usage_restrictions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # --- Content fingerprint ------------------------------------------------
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    total_byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    total_record_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_count: Mapped[int] = mapped_column(Integer, nullable=False)

    # --- Provenance ---------------------------------------------------------
    committer_label: Mapped[str] = mapped_column(String(256), nullable=False)
    parent_dataset_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    transform_description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- ZK stub ------------------------------------------------------------
    poseidon_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
