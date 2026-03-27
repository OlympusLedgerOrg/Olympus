"""add dataset provenance tables (ADR-0010)

Revision ID: a1b2c3d4e5f6
Revises: 8398af14bd26
Create Date: 2026-03-27
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'a1b2c3d4e5f6'
down_revision: str | Sequence[str] | None = '8398af14bd26'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- dataset_artifacts ---
    op.create_table(
        'dataset_artifacts',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('dataset_id', sa.String(length=64), nullable=False),
        sa.Column('commit_id', sa.String(length=64), nullable=False),
        sa.Column('parent_commit_id', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('epoch_timestamp', sa.DateTime(), nullable=False),
        sa.Column('shard_id', sa.String(length=32), nullable=False, server_default='0x4F3A'),
        sa.Column('merkle_root', sa.String(length=64), nullable=True),
        sa.Column('zk_proof', sa.Text(), nullable=True),
        # Cryptographic identity (D3)
        sa.Column('committer_pubkey', sa.String(length=64), nullable=False),
        sa.Column('commit_signature', sa.String(length=128), nullable=False),
        sa.Column('committer_label', sa.String(length=256), nullable=True),
        # RFC 3161 (D5)
        sa.Column('rfc3161_tst_hex', sa.Text(), nullable=True),
        sa.Column('rfc3161_tsa_url', sa.String(length=512), nullable=True),
        # External anchor (D6)
        sa.Column('anchor_tx_hash', sa.String(length=128), nullable=True),
        sa.Column('anchor_network', sa.String(length=32), nullable=True),
        sa.Column('anchor_block_height', sa.Integer(), nullable=True),
        # Dataset identity
        sa.Column('dataset_name', sa.String(length=256), nullable=False),
        sa.Column('dataset_version', sa.String(length=64), nullable=False),
        sa.Column('source_uri', sa.String(length=2048), nullable=False),
        sa.Column('canonical_namespace', sa.String(length=256), nullable=False),
        sa.Column('granularity', sa.String(length=16), nullable=False),
        # Licensing
        sa.Column('license_spdx', sa.String(length=64), nullable=False),
        sa.Column('license_uri', sa.String(length=2048), nullable=True),
        sa.Column('usage_restrictions', sa.Text(), nullable=True),
        # Content fingerprint (D7)
        sa.Column('manifest_hash', sa.String(length=64), nullable=False),
        sa.Column('manifest_schema_version', sa.String(length=32), nullable=False, server_default='dataset_manifest_v1'),
        sa.Column('canonicalization_method', sa.String(length=32), nullable=False, server_default='canonical_json_v2'),
        sa.Column('total_byte_size', sa.BigInteger(), nullable=False),
        sa.Column('total_record_count', sa.Integer(), nullable=True),
        sa.Column('file_count', sa.Integer(), nullable=False),
        sa.Column('file_format', sa.String(length=32), nullable=False),
        # Provenance
        sa.Column('parent_dataset_id', sa.String(length=64), nullable=True),
        sa.Column('transform_description', sa.Text(), nullable=True),
        # Proof export (D9)
        sa.Column('proof_bundle_uri', sa.String(length=2048), nullable=True),
        # ZK stub
        sa.Column('poseidon_hash', sa.String(length=78), nullable=True),
    )
    op.create_index('ix_dataset_artifacts_dataset_id', 'dataset_artifacts', ['dataset_id'])
    op.create_index('ix_dataset_artifacts_commit_id', 'dataset_artifacts', ['commit_id'], unique=True)
    op.create_index('ix_dataset_artifacts_shard_id', 'dataset_artifacts', ['shard_id'])
    op.create_index('ix_dataset_artifacts_license_spdx', 'dataset_artifacts', ['license_spdx'])
    op.create_index('ix_dataset_artifacts_committer_pubkey', 'dataset_artifacts', ['committer_pubkey'])

    # --- dataset_artifact_files ---
    op.create_table(
        'dataset_artifact_files',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('artifact_id', sa.String(length=36), sa.ForeignKey('dataset_artifacts.id'), nullable=False),
        sa.Column('path', sa.String(length=2048), nullable=False),
        sa.Column('content_hash', sa.String(length=64), nullable=False),
        sa.Column('byte_size', sa.BigInteger(), nullable=False),
        sa.Column('record_count', sa.Integer(), nullable=True),
    )
    op.create_index('ix_dataset_artifact_files_artifact_id', 'dataset_artifact_files', ['artifact_id'])

    # --- dataset_lineage_events ---
    op.create_table(
        'dataset_lineage_events',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('dataset_id', sa.String(length=64), nullable=False),
        sa.Column('commit_id', sa.String(length=64), nullable=False),
        sa.Column('parent_commit_id', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('epoch_timestamp', sa.DateTime(), nullable=False),
        sa.Column('shard_id', sa.String(length=32), nullable=False, server_default='0x4F3A'),
        sa.Column('merkle_root', sa.String(length=64), nullable=True),
        sa.Column('committer_pubkey', sa.String(length=64), nullable=False),
        sa.Column('commit_signature', sa.String(length=128), nullable=False),
        sa.Column('model_id', sa.String(length=256), nullable=False),
        sa.Column('model_version', sa.String(length=64), nullable=True),
        sa.Column('model_org', sa.String(length=256), nullable=True),
        sa.Column('event_type', sa.String(length=32), nullable=False),
    )
    op.create_index('ix_dataset_lineage_events_dataset_id', 'dataset_lineage_events', ['dataset_id'])
    op.create_index('ix_dataset_lineage_events_model_id', 'dataset_lineage_events', ['model_id'])
    op.create_index('ix_dataset_lineage_events_commit_id', 'dataset_lineage_events', ['commit_id'], unique=True)


def downgrade() -> None:
    op.drop_table('dataset_lineage_events')
    op.drop_table('dataset_artifact_files')
    op.drop_table('dataset_artifacts')
