"""
Dataset provenance ORM models (ADR-0010).

Three tables:
  - ``dataset_artifacts`` — cryptographic commitment of a dataset manifest
  - ``dataset_artifact_files`` — individual file entries within a manifest
  - ``dataset_lineage_events`` — append-only records of model consumption

Design principles (see ADR-0010):
  - Deterministic commit IDs (BLAKE3 of content, not server-random)
  - Caller Ed25519 signatures prove authorship
  - Per-record RFC 3161 timestamps for legal defensibility
  - Optional external blockchain anchoring
  - Append-only; no mutations
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base


if TYPE_CHECKING:
    pass


class DatasetArtifact(Base):
    """A cryptographic commitment anchoring a dataset manifest to the ledger.

    Unlike DocCommit, dataset artifacts carry full cryptographic provenance:
    deterministic commit IDs (content-addressed, timestamp-excluded), caller
    Ed25519 signatures, per-record RFC 3161 tokens with explicit status,
    and optional external blockchain anchoring.

    Attributes:
        id: UUID primary key.
        dataset_id: Logical dataset identity (BLAKE3 of namespace+name+uri+pubkey).
        commit_id: Deterministic BLAKE3 hash of commit contents (no timestamp).
        parent_commit_id: Hash chain to previous commit (empty for genesis).
        epoch_timestamp: Server-set UTC timestamp.
        shard_id: Ledger shard this commit belongs to.
        merkle_root: Shard Merkle root after this commit.
        zk_proof: Serialised Groth16 proof stub.
        committer_pubkey: Ed25519 public key of the committer (hex).
        commit_signature: Ed25519 signature over commit_id (hex).
        committer_label: Optional human-readable committer name.
        rfc3161_tst_hex: DER-encoded RFC 3161 timestamp token (hex).
        rfc3161_tsa_url: TSA that issued the token.
        timestamp_status: ``"pending"`` | ``"verified"`` | ``"failed"``.
        anchor_tx_hash: Blockchain transaction hash (async backfill).
        anchor_network: Blockchain network name.
        anchor_block_height: Block height for independent lookup.
        dataset_name: Human-readable dataset name.
        dataset_version: Semantic version string.
        source_uri: URI pointing to the dataset origin.
        canonical_namespace: Namespace scoping dataset_id derivation.
        granularity: ``"file"`` | ``"record"`` | ``"shard"``.
        license_spdx: SPDX licence identifier.
        license_uri: Optional URI to the full licence text.
        usage_restrictions: JSON-serialised list of restriction strings.
        manifest_hash: BLAKE3 of the canonical manifest JSON.
        manifest_schema_version: Manifest format version.
        canonicalization_method: Canonicalization algorithm used.
        total_byte_size: Total dataset size in bytes.
        total_record_count: Optional number of records.
        file_count: Number of files.
        file_format: Primary file format descriptor.
        parent_dataset_id: Derived-from dataset (semantic lineage).
        transform_description: How this dataset was derived.
        proof_bundle_uri: URI to self-contained verification package.
        poseidon_hash: BN128 Poseidon hash for ZK circuit binding.
    """

    __tablename__ = "dataset_artifacts"

    __table_args__ = (
        UniqueConstraint(
            "dataset_id",
            "parent_commit_id",
            "manifest_hash",
            name="uq_dataset_commit_content",
        ),
    )

    # --- Core ledger fields -------------------------------------------------
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    dataset_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    commit_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    parent_commit_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    epoch_timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    shard_id: Mapped[str] = mapped_column(String(32), nullable=False, default="0x4F3A")
    merkle_root: Mapped[str | None] = mapped_column(String(64), nullable=True)
    zk_proof: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Cryptographic committer identity (D3) ------------------------------
    committer_pubkey: Mapped[str] = mapped_column(String(64), nullable=False)
    commit_signature: Mapped[str] = mapped_column(String(128), nullable=False)
    committer_label: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # --- Per-record RFC 3161 timestamp (D5) ---------------------------------
    rfc3161_tst_hex: Mapped[str | None] = mapped_column(Text, nullable=True)
    rfc3161_tsa_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    timestamp_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")

    # --- External anchor (D6) -----------------------------------------------
    anchor_tx_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    anchor_network: Mapped[str | None] = mapped_column(String(32), nullable=True)
    anchor_block_height: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # --- Dataset identity ---------------------------------------------------
    dataset_name: Mapped[str] = mapped_column(String(256), nullable=False)
    dataset_version: Mapped[str] = mapped_column(String(64), nullable=False)
    source_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    canonical_namespace: Mapped[str] = mapped_column(String(256), nullable=False)
    granularity: Mapped[str] = mapped_column(String(16), nullable=False)

    # --- Licensing ----------------------------------------------------------
    license_spdx: Mapped[str] = mapped_column(String(64), nullable=False)
    license_uri: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    usage_restrictions: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Content fingerprint (D7) -------------------------------------------
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_schema_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="dataset_manifest_v1"
    )
    canonicalization_method: Mapped[str] = mapped_column(
        String(32), nullable=False, default="canonical_json_v2"
    )
    total_byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    total_record_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_count: Mapped[int] = mapped_column(Integer, nullable=False)
    file_format: Mapped[str] = mapped_column(String(32), nullable=False)

    # --- Provenance chain ---------------------------------------------------
    parent_dataset_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    transform_description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Proof export (D9) --------------------------------------------------
    proof_bundle_uri: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    # --- ZK stub ------------------------------------------------------------
    poseidon_hash: Mapped[str | None] = mapped_column(String(78), nullable=True)

    # --- Relationships ------------------------------------------------------
    files: Mapped[list[DatasetArtifactFile]] = relationship(
        back_populates="artifact", cascade="all, delete-orphan"
    )


class DatasetArtifactFile(Base):
    """Individual file entry within a dataset manifest.

    Attributes:
        id: UUID primary key.
        artifact_id: FK to the parent DatasetArtifact.
        path: File path within the dataset.
        content_hash: BLAKE3 hex hash of the file content.
        byte_size: File size in bytes.
        record_count: Optional number of records in this file.
    """

    __tablename__ = "dataset_artifact_files"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    artifact_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("dataset_artifacts.id"), nullable=False, index=True
    )
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    record_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    artifact: Mapped[DatasetArtifact] = relationship(back_populates="files")


class DatasetLineageEvent(Base):
    """Records which models consumed which datasets.

    Append-only.  Each event is independently committed, signed, and
    timestamped.  The original DatasetArtifact is never mutated.

    Attributes:
        id: UUID primary key.
        dataset_id: Logical dataset identity (index).
        commit_id: Deterministic BLAKE3 hash (unique).
        parent_commit_id: Chain to the dataset commit.
        epoch_timestamp: Server-set UTC timestamp.
        shard_id: Ledger shard.
        merkle_root: Shard root after this event.
        committer_pubkey: Ed25519 public key (hex).
        commit_signature: Ed25519 signature (hex).
        model_id: Identifier of the consuming model.
        model_version: Optional model version.
        model_org: Optional organisation.
        event_type: ``"training_started"`` | ``"training_completed"`` |
            ``"evaluation"``.
    """

    __tablename__ = "dataset_lineage_events"

    __table_args__ = (
        UniqueConstraint(
            "dataset_id",
            "model_id",
            "event_type",
            "committer_pubkey",
            name="uq_lineage_event",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    dataset_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    commit_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    parent_commit_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    epoch_timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    shard_id: Mapped[str] = mapped_column(String(32), nullable=False, default="0x4F3A")
    merkle_root: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # --- Cryptographic identity ---------------------------------------------
    committer_pubkey: Mapped[str] = mapped_column(String(64), nullable=False)
    commit_signature: Mapped[str] = mapped_column(String(128), nullable=False)

    # --- Timestamp status ---------------------------------------------------
    timestamp_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")

    # --- Lineage payload ----------------------------------------------------
    model_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model_org: Mapped[str | None] = mapped_column(String(256), nullable=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
