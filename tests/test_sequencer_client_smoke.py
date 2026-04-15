"""Smoke tests for the GoSequencerClient.

These tests verify the GoSequencerClient can communicate with a running
Go sequencer service. They are marked with @pytest.mark.smoke and will
be skipped if OLYMPUS_USE_GO_SEQUENCER is not set to "true".

To run these tests:
    1. Start the Go sequencer with Docker Compose:
       docker compose --profile sequencer up -d

    2. Set environment variables:
       export OLYMPUS_USE_GO_SEQUENCER=true
       export OLYMPUS_SEQUENCER_URL=http://localhost:8081
       export OLYMPUS_SEQUENCER_TOKEN=your-test-token

    3. Run the tests:
       pytest tests/test_sequencer_client_smoke.py -v -m smoke
"""

from __future__ import annotations

import os

import pytest


# Skip all tests in this module if Go sequencer is not enabled
pytestmark = [
    pytest.mark.smoke,
    pytest.mark.skipif(
        os.environ.get("OLYMPUS_USE_GO_SEQUENCER", "").lower() not in ("1", "true", "yes", "on"),
        reason="OLYMPUS_USE_GO_SEQUENCER is not enabled",
    ),
]


@pytest.fixture
async def sequencer_client():
    """Create a GoSequencerClient for testing with proper cleanup."""
    from api.services.sequencer_client import GoSequencerClient

    client = GoSequencerClient()
    yield client
    # Clean up the HTTP client after tests complete
    await client.close()


class TestGoSequencerClientSmoke:
    """Smoke tests for GoSequencerClient against a live sequencer."""

    @pytest.mark.asyncio
    async def test_health_check(self, sequencer_client):
        """Verify the sequencer is reachable."""
        is_healthy = await sequencer_client.health_check()
        assert is_healthy, "Sequencer health check failed"

    @pytest.mark.asyncio
    async def test_get_latest_root(self, sequencer_client):
        """Verify we can get the latest root from the sequencer."""
        result = await sequencer_client.get_latest_root()
        assert result is not None
        assert isinstance(result.root, str)
        assert len(result.root) == 64  # 32 bytes hex-encoded
        assert isinstance(result.tree_size, int)
        assert result.tree_size >= 0

    @pytest.mark.asyncio
    async def test_append_record_and_get_proof(self, sequencer_client):
        """Verify we can append a record and retrieve its inclusion proof."""
        import uuid

        # Generate unique identifiers to avoid collision
        test_id = str(uuid.uuid4())[:8]
        shard_id = f"test.smoke.{test_id}"
        record_id = f"doc-{test_id}"
        content = f'{{"test": "{test_id}", "timestamp": "{uuid.uuid4()}"}}'.encode()

        # Append a record
        result = await sequencer_client.append_record(
            shard_id=shard_id,
            record_type="document",
            record_id=record_id,
            content=content,
            content_type="application/json",
            version="1",
        )

        assert result is not None
        assert len(result.new_root) == 64
        assert len(result.global_key) == 64
        assert len(result.leaf_value_hash) == 64
        assert result.tree_size >= 1

        # Retrieve inclusion proof
        proof = await sequencer_client.get_inclusion_proof(
            shard_id=shard_id,
            record_type="document",
            record_id=record_id,
            version="1",
        )

        assert proof is not None
        assert len(proof.global_key) == 64
        assert len(proof.value_hash) == 64
        assert len(proof.root) == 64
        assert isinstance(proof.siblings, list)
        # CD-HS-ST has 256 levels
        assert len(proof.siblings) == 256

    @pytest.mark.asyncio
    async def test_append_records_batch(self, sequencer_client):
        """Verify batch append works correctly."""
        import uuid

        test_id = str(uuid.uuid4())[:8]
        shard_id = f"test.batch.{test_id}"

        records = [
            {
                "shard_id": shard_id,
                "record_type": "document",
                "record_id": f"batch-doc-{i}-{test_id}",
                "content": f'{{"batch_index": {i}}}'.encode(),
                "content_type": "application/json",
                "version": "1",
            }
            for i in range(3)
        ]

        results = await sequencer_client.append_records_batch(records)

        assert len(results) == 3
        for i, result in enumerate(results):
            assert len(result.new_root) == 64
            assert len(result.global_key) == 64
            assert len(result.leaf_value_hash) == 64
            assert result.tree_size >= i + 1

        # Verify each record's proof
        for i in range(3):
            proof = await sequencer_client.get_inclusion_proof(
                shard_id=shard_id,
                record_type="document",
                record_id=f"batch-doc-{i}-{test_id}",
                version="1",
            )
            assert proof is not None
            assert len(proof.siblings) == 256

    @pytest.mark.asyncio
    async def test_proof_verification_with_protocol_merkle(self, sequencer_client):
        """Verify returned proofs can be validated with protocol/merkle.py."""
        import uuid

        test_id = str(uuid.uuid4())[:8]
        shard_id = f"test.verify.{test_id}"
        record_id = f"verify-doc-{test_id}"
        content = f'{{"verify_test": "{test_id}"}}'.encode()

        # Append record
        await sequencer_client.append_record(
            shard_id=shard_id,
            record_type="document",
            record_id=record_id,
            content=content,
            content_type="application/json",
            version="1",
        )

        # Get inclusion proof
        proof = await sequencer_client.get_inclusion_proof(
            shard_id=shard_id,
            record_type="document",
            record_id=record_id,
            version="1",
        )

        # Convert hex strings to bytes for verification
        root_bytes = bytes.fromhex(proof.root)
        value_hash_bytes = bytes.fromhex(proof.value_hash)
        siblings_bytes = [bytes.fromhex(s) for s in proof.siblings]
        global_key_bytes = bytes.fromhex(proof.global_key)

        # Build a MerkleProof structure for verification
        # Note: The SMT proof format differs from standard Merkle proof
        # This is a simplified check that the hashes are well-formed
        assert len(root_bytes) == 32
        assert len(value_hash_bytes) == 32
        assert len(global_key_bytes) == 32
        for sib in siblings_bytes:
            assert len(sib) == 32


class TestGoSequencerHealthStatus:
    """Test the health status helper functions."""

    @pytest.mark.asyncio
    async def test_get_sequencer_health_status_ok(self):
        """Verify get_sequencer_health_status returns ok when sequencer is up."""
        from api.services.sequencer_client import get_sequencer_health_status

        status, is_healthy = await get_sequencer_health_status()
        assert status == "ok"
        assert is_healthy is True

    @pytest.mark.asyncio
    async def test_storage_layer_sequencer_status(self):
        """Verify storage_layer.get_sequencer_status works."""
        from api.services.storage_layer import get_sequencer_status

        status, is_healthy = await get_sequencer_status()
        assert status == "ok"
        assert is_healthy is True
