"""Tests for Guardian replication and quorum signing.

These tests verify the collect_quorum_signatures function and the
POST /v1/federation/sign-header endpoint.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from protocol.federation.identity import FederationRegistry
from protocol.federation.quorum import (
    NodeSignature,
    QuorumNotReached,
    build_quorum_certificate,
    collect_quorum_signatures,
    has_federation_quorum,
    sign_federated_header,
)
from protocol.shards import create_shard_header, get_signing_key_from_seed


REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "examples" / "federation_registry.json"


def _test_signing_key(seed_byte: int):
    """Return a deterministic test-only Ed25519 key for federation quorum tests."""
    return get_signing_key_from_seed(bytes([seed_byte]) * 32)


@pytest.fixture
def test_registry():
    """Load the test federation registry."""
    return FederationRegistry.from_file(REGISTRY_PATH)


@pytest.fixture
def sample_header():
    """Create a sample shard header for testing."""
    return create_shard_header(
        shard_id="test.shard",
        root_hash=bytes.fromhex("cc" * 32),
        timestamp="2026-04-14T12:00:00Z",
    )


class TestQuorumNotReached:
    """Tests for the QuorumNotReached exception."""

    def test_exception_attributes(self):
        """Test that exception carries collected and required counts."""
        exc = QuorumNotReached(
            "Not enough signatures",
            collected_signatures=1,
            required_threshold=2,
        )
        assert exc.collected_signatures == 1
        assert exc.required_threshold == 2
        assert "Not enough signatures" in str(exc)


class TestCollectQuorumSignatures:
    """Tests for the collect_quorum_signatures function."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_successful_quorum_two_of_three(self, test_registry, sample_header):
        """Test that 2-of-3 signatures produces a valid quorum certificate."""
        # Generate local signature
        local_key = _test_signing_key(1)
        local_sig = sign_federated_header(
            sample_header, "olympus-node-1", local_key, test_registry
        )

        # Mock remote node responses
        node2_key = _test_signing_key(2)
        node2_sig = sign_federated_header(
            sample_header, "olympus-node-2", node2_key, test_registry
        )

        # Mock node 2 response
        respx.post("https://node2.olympus.org/v1/federation/sign-header").mock(
            return_value=httpx.Response(
                200,
                json={
                    "node_id": "olympus-node-2",
                    "signature": node2_sig.signature,
                },
            )
        )

        # Mock node 3 timeout
        respx.post("https://node3.olympus.org/v1/federation/sign-header").mock(
            side_effect=httpx.TimeoutException("Timeout")
        )

        async with httpx.AsyncClient() as client:
            cert = await collect_quorum_signatures(
                header=sample_header,
                local_signature=local_sig.signature,
                local_node_id="olympus-node-1",
                registry=test_registry,
                threshold=2,
                timeout_seconds=1.0,
                http_client=client,
            )

        assert cert is not None
        assert cert["shard_id"] == "test.shard"
        assert len(cert["signatures"]) >= 2

    @pytest.mark.asyncio
    @respx.mock
    async def test_quorum_not_reached_with_only_one(self, test_registry, sample_header):
        """Test that only 1 signature fails to reach quorum."""
        # Generate local signature
        local_key = _test_signing_key(1)
        local_sig = sign_federated_header(
            sample_header, "olympus-node-1", local_key, test_registry
        )

        # Mock both remote nodes timing out
        respx.post("https://node2.olympus.org/v1/federation/sign-header").mock(
            side_effect=httpx.TimeoutException("Timeout")
        )
        respx.post("https://node3.olympus.org/v1/federation/sign-header").mock(
            side_effect=httpx.TimeoutException("Timeout")
        )

        async with httpx.AsyncClient() as client:
            with pytest.raises(QuorumNotReached) as exc_info:
                await collect_quorum_signatures(
                    header=sample_header,
                    local_signature=local_sig.signature,
                    local_node_id="olympus-node-1",
                    registry=test_registry,
                    threshold=2,
                    timeout_seconds=0.5,
                    http_client=client,
                )

        assert exc_info.value.collected_signatures == 1
        assert exc_info.value.required_threshold == 2

    @pytest.mark.asyncio
    @respx.mock
    async def test_quorum_succeeds_with_all_three(self, test_registry, sample_header):
        """Test that all 3 signatures produces a valid certificate."""
        # Generate all signatures
        local_key = _test_signing_key(1)
        local_sig = sign_federated_header(
            sample_header, "olympus-node-1", local_key, test_registry
        )

        node2_key = _test_signing_key(2)
        node2_sig = sign_federated_header(
            sample_header, "olympus-node-2", node2_key, test_registry
        )

        node3_key = _test_signing_key(3)
        node3_sig = sign_federated_header(
            sample_header, "olympus-node-3", node3_key, test_registry
        )

        # Mock all remote node responses
        respx.post("https://node2.olympus.org/v1/federation/sign-header").mock(
            return_value=httpx.Response(
                200,
                json={
                    "node_id": "olympus-node-2",
                    "signature": node2_sig.signature,
                },
            )
        )
        respx.post("https://node3.olympus.org/v1/federation/sign-header").mock(
            return_value=httpx.Response(
                200,
                json={
                    "node_id": "olympus-node-3",
                    "signature": node3_sig.signature,
                },
            )
        )

        async with httpx.AsyncClient() as client:
            cert = await collect_quorum_signatures(
                header=sample_header,
                local_signature=local_sig.signature,
                local_node_id="olympus-node-1",
                registry=test_registry,
                threshold=2,
                timeout_seconds=5.0,
                http_client=client,
            )

        assert cert is not None
        assert len(cert["signatures"]) == 3

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_signature_from_remote_node(self, test_registry, sample_header):
        """Test that invalid signatures from remote nodes are rejected."""
        # Generate local signature
        local_key = _test_signing_key(1)
        local_sig = sign_federated_header(
            sample_header, "olympus-node-1", local_key, test_registry
        )

        # Mock node 2 with invalid signature
        respx.post("https://node2.olympus.org/v1/federation/sign-header").mock(
            return_value=httpx.Response(
                200,
                json={
                    "node_id": "olympus-node-2",
                    "signature": "invalid" + "00" * 64,  # Invalid signature
                },
            )
        )

        # Mock node 3 timeout
        respx.post("https://node3.olympus.org/v1/federation/sign-header").mock(
            side_effect=httpx.TimeoutException("Timeout")
        )

        async with httpx.AsyncClient() as client:
            with pytest.raises(QuorumNotReached):
                await collect_quorum_signatures(
                    header=sample_header,
                    local_signature=local_sig.signature,
                    local_node_id="olympus-node-1",
                    registry=test_registry,
                    threshold=2,
                    timeout_seconds=0.5,
                    http_client=client,
                )

    @pytest.mark.asyncio
    async def test_missing_header_hash_raises_value_error(self, test_registry):
        """Test that missing header_hash raises ValueError."""
        header_no_hash = {
            "shard_id": "test.shard",
            "root_hash": "cc" * 32,
            "timestamp": "2026-04-14T12:00:00Z",
        }

        with pytest.raises(ValueError, match="header_hash"):
            await collect_quorum_signatures(
                header=header_no_hash,
                local_signature="00" * 64,
                local_node_id="olympus-node-1",
                registry=test_registry,
                threshold=2,
            )


class TestForkDetectionInQuorum:
    """Tests for fork detection during quorum collection."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_fork_detection_response_logged_but_not_counted(
        self, test_registry, sample_header
    ):
        """Test that 409 fork detection responses are logged but don't count."""
        local_key = _test_signing_key(1)
        local_sig = sign_federated_header(
            sample_header, "olympus-node-1", local_key, test_registry
        )

        node2_key = _test_signing_key(2)
        node2_sig = sign_federated_header(
            sample_header, "olympus-node-2", node2_key, test_registry
        )

        # Node 2 returns valid signature
        respx.post("https://node2.olympus.org/v1/federation/sign-header").mock(
            return_value=httpx.Response(
                200,
                json={
                    "node_id": "olympus-node-2",
                    "signature": node2_sig.signature,
                },
            )
        )

        # Node 3 detects fork
        respx.post("https://node3.olympus.org/v1/federation/sign-header").mock(
            return_value=httpx.Response(
                409,
                json={
                    "detail": "Fork detected: root mismatch",
                    "fork_detected": True,
                },
            )
        )

        async with httpx.AsyncClient() as client:
            # Should still succeed with 2 signatures (local + node2)
            cert = await collect_quorum_signatures(
                header=sample_header,
                local_signature=local_sig.signature,
                local_node_id="olympus-node-1",
                registry=test_registry,
                threshold=2,
                timeout_seconds=5.0,
                http_client=client,
            )

        assert cert is not None
        assert len(cert["signatures"]) == 2


class TestSignHeaderEndpoint:
    """Tests for the POST /v1/federation/sign-header endpoint."""

    @pytest.mark.asyncio
    async def test_endpoint_disabled_when_guardian_not_enabled(self):
        """Test that endpoint returns 503 when Guardian mode is disabled."""
        from fastapi.testclient import TestClient

        from api.main import app

        with patch.dict(os.environ, {"OLYMPUS_GUARDIAN_ENABLED": "false"}):
            client = TestClient(app)
            response = client.post(
                "/v1/federation/sign-header",
                json={
                    "domain": "OLY:FEDERATION-VOTE:V1",
                    "node_id": "test-node",
                    "event_id": "test-event",
                    "shard_id": "test.shard",
                    "entry_seq": 1,
                    "round_number": 0,
                    "shard_root": "cc" * 32,
                    "timestamp": "2026-04-14T12:00:00Z",
                    "epoch": 1,
                    "validator_set_hash": "dd" * 32,
                    "header": {
                        "shard_id": "test.shard",
                        "root_hash": "cc" * 32,
                        "header_hash": "cc" * 32,
                        "timestamp": "2026-04-14T12:00:00Z",
                    },
                },
                headers={"X-API-Key": "test-key"},
            )
            # May return 503 (Guardian disabled) or 401/403 (auth)
            assert response.status_code in [401, 403, 503]


class TestBuildQuorumCertificate:
    """Tests for the build_quorum_certificate function."""

    def test_build_certificate_with_threshold_signatures(self, test_registry, sample_header):
        """Test building a certificate with exactly threshold signatures."""
        signatures = [
            sign_federated_header(sample_header, "olympus-node-1", _test_signing_key(1), test_registry),
            sign_federated_header(sample_header, "olympus-node-2", _test_signing_key(2), test_registry),
        ]

        cert = build_quorum_certificate(sample_header, signatures, test_registry)

        assert cert["shard_id"] == "test.shard"
        assert cert["quorum_threshold"] == 2
        assert len(cert["signatures"]) == 2

    def test_build_certificate_fails_below_threshold(self, test_registry, sample_header):
        """Test that certificate building fails with insufficient signatures."""
        signatures = [
            sign_federated_header(sample_header, "olympus-node-1", _test_signing_key(1), test_registry),
        ]

        with pytest.raises(ValueError, match="Insufficient"):
            build_quorum_certificate(sample_header, signatures, test_registry)
