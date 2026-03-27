"""add dataset_artifacts table

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
    op.create_table(
        'dataset_artifacts',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('dataset_id', sa.String(length=64), nullable=False, index=True),
        sa.Column('commit_id', sa.String(length=64), nullable=False, unique=True),
        sa.Column('epoch_timestamp', sa.DateTime(), nullable=False),
        sa.Column('shard_id', sa.String(length=32), nullable=False, server_default='0x4F3A'),
        sa.Column('merkle_root', sa.String(length=64), nullable=False),
        sa.Column('dataset_name', sa.String(length=256), nullable=False),
        sa.Column('dataset_version', sa.String(length=64), nullable=False),
        sa.Column('source_uri', sa.String(length=2048), nullable=False),
        sa.Column('granularity', sa.String(length=32), nullable=False),
        sa.Column('license_spdx', sa.String(length=128), nullable=False),
        sa.Column('license_uri', sa.String(length=2048), nullable=True),
        sa.Column('usage_restrictions', sa.JSON(), nullable=False),
        sa.Column('manifest_hash', sa.String(length=64), nullable=False),
        sa.Column('total_byte_size', sa.BigInteger(), nullable=False),
        sa.Column('total_record_count', sa.Integer(), nullable=True),
        sa.Column('file_count', sa.Integer(), nullable=False),
        sa.Column('committer_label', sa.String(length=256), nullable=False),
        sa.Column('parent_dataset_id', sa.String(length=64), nullable=True),
        sa.Column('transform_description', sa.Text(), nullable=True),
        sa.Column('poseidon_hash', sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('dataset_artifacts')
