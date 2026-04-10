"""Targeted coverage-boost tests for protocol modules.

Each test covers specific lines that were previously uncovered, making
meaningful assertions about behavior — not just exercising code paths.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import nacl.signing
import pytest

from protocol.federation.identity import (
    FEDERATION_DOMAIN_TAG,
    FederationKeyHistoryEntry,
    FederationNode,
    FederationRegistry,
    _extract_round_and_height,
    _to_int,
)
from protocol.federation.quorum import (
    NodeSignature,
    build_quorum_certificate,
    quorum_certificate_hash,
    sign_federated_header,
    verify_federated_header_signatures,
    verify_quorum_certificate,
)
from protocol.shards import create_shard_header, get_signing_key_from_seed, sign_header
from protocol.ssmf import (
    EMPTY_HASHES,
    ExistenceProof,
    NonExistenceProof,
    SparseMerkleDiffEntry,
    SparseMerkleTree,
    diff_sparse_merkle_trees,
    verify_nonexistence_proof,
    verify_proof,
)
from protocol.telemetry import _NoOpSpan, _NoOpTracer, get_tracer, timed_operation
from protocol.witness_transport import (
    NodeEndpoint,
    WitnessHTTPTransport,
    _validate_endpoint_url,
    create_witness_transport,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "examples" / "federation_registry.json"


def _test_signing_key(seed_byte: int) -> nacl.signing.SigningKey:
    """Return a deterministic Ed25519 key from a single-byte seed."""
    return get_signing_key_from_seed(bytes([seed_byte]) * 32)


# ═══════════════════════════════════════════════════════════════════════
#  1. protocol/ssmf.py
# ═══════════════════════════════════════════════════════════════════════


class TestSparseMerkleDiffEntry:
    """Cover SparseMerkleDiffEntry.to_dict (line 114)."""

    def test_to_dict_with_both_values(self) -> None:
        before_val = b"\xaa" * 32
        after_val = b"\xbb" * 32
        key = b"\xcc" * 32
        entry = SparseMerkleDiffEntry(key=key, before_value_hash=before_val, after_value_hash=after_val)
        d = entry.to_dict()
        assert d["key"] == key.hex()
        assert d["before_value_hash"] == before_val.hex()
        assert d["after_value_hash"] == after_val.hex()

    def test_to_dict_with_none_values(self) -> None:
        key = b"\x01" * 32
        entry = SparseMerkleDiffEntry(key=key, before_value_hash=None, after_value_hash=None)
        d = entry.to_dict()
        assert d["before_value_hash"] is None
        assert d["after_value_hash"] is None

    def test_to_dict_added_entry(self) -> None:
        key = b"\x02" * 32
        after_val = b"\x03" * 32
        entry = SparseMerkleDiffEntry(key=key, before_value_hash=None, after_value_hash=after_val)
        d = entry.to_dict()
        assert d["before_value_hash"] is None
        assert d["after_value_hash"] == after_val.hex()


class TestSparseMerkleTreeEmpty:
    """Cover empty-tree root computation (line 150)."""

    def test_get_root_empty_tree(self) -> None:
        tree = SparseMerkleTree()
        root = tree.get_root()
        assert root == EMPTY_HASHES[256]

    def test_get_root_after_update_and_empty_fallback(self) -> None:
        """After an update, root comes from nodes[()]; empty-tree path is no longer taken."""
        tree = SparseMerkleTree()
        key = b"\x00" * 32
        val = b"\xff" * 32
        tree.update(key, val)
        root = tree.get_root()
        assert root != EMPTY_HASHES[256]
        assert len(root) == 32


class TestProveNonexistenceWrongKeyLength:
    """Cover line 256: wrong key length → ValueError."""

    def test_short_key(self) -> None:
        tree = SparseMerkleTree()
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            tree.prove_nonexistence(b"\x00" * 16)

    def test_long_key(self) -> None:
        tree = SparseMerkleTree()
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            tree.prove_nonexistence(b"\x00" * 64)


class TestSiblingPathEmptyPath:
    """Cover line 331: _sibling_path of empty tuple raises ValueError."""

    def test_empty_path_raises(self) -> None:
        tree = SparseMerkleTree()
        with pytest.raises(ValueError, match="Cannot get sibling of root"):
            tree._sibling_path(())


class TestDiffWithKeyRange:
    """Cover lines 416, 418: key_range_start / key_range_end filtering."""

    def test_key_range_filters_added(self) -> None:
        before = SparseMerkleTree()
        after = SparseMerkleTree()

        low_key = b"\x10" + b"\x00" * 31
        mid_key = b"\x50" + b"\x00" * 31
        high_key = b"\x90" + b"\x00" * 31
        val = b"\x01" * 32

        after.update(low_key, val)
        after.update(mid_key, val)
        after.update(high_key, val)

        # Only mid_key should survive the range filter
        result = diff_sparse_merkle_trees(
            before,
            after,
            key_range_start=b"\x40" + b"\x00" * 31,
            key_range_end=b"\x60" + b"\x00" * 31,
        )
        assert len(result["added"]) == 1
        assert result["added"][0].key == mid_key
        assert result["changed"] == []
        assert result["removed"] == []

    def test_key_range_filters_removed(self) -> None:
        before = SparseMerkleTree()
        after = SparseMerkleTree()

        key_in = b"\x50" + b"\x00" * 31
        key_out = b"\x10" + b"\x00" * 31
        val = b"\x01" * 32

        before.update(key_in, val)
        before.update(key_out, val)

        result = diff_sparse_merkle_trees(
            before,
            after,
            key_range_start=b"\x40" + b"\x00" * 31,
            key_range_end=b"\x60" + b"\x00" * 31,
        )
        assert len(result["removed"]) == 1
        assert result["removed"][0].key == key_in


class TestVerifyProofInvalidInputs:
    """Cover lines 460, 462, 464, 466, 471."""

    @staticmethod
    def _make_valid_proof() -> ExistenceProof:
        tree = SparseMerkleTree()
        key = b"\x00" * 32
        val = b"\x01" * 32
        tree.update(key, val)
        return tree.prove_existence(key)

    def test_key_wrong_length(self) -> None:
        proof = self._make_valid_proof()
        proof.key = b"\x00" * 16
        assert verify_proof(proof) is False

    def test_value_hash_wrong_length(self) -> None:
        proof = self._make_valid_proof()
        proof.value_hash = b"\x00" * 16
        assert verify_proof(proof) is False

    def test_siblings_wrong_count(self) -> None:
        proof = self._make_valid_proof()
        proof.siblings = proof.siblings[:10]
        assert verify_proof(proof) is False

    def test_root_hash_wrong_length(self) -> None:
        proof = self._make_valid_proof()
        proof.root_hash = b"\x00" * 16
        assert verify_proof(proof) is False

    def test_sibling_wrong_length(self) -> None:
        proof = self._make_valid_proof()
        proof.siblings[0] = b"\x00" * 10
        assert verify_proof(proof) is False


class TestVerifyNonexistenceProofInvalidInputs:
    """Cover lines 518, 520, 522, 527."""

    @staticmethod
    def _make_valid_nonexistence_proof() -> NonExistenceProof:
        tree = SparseMerkleTree()
        key = b"\x00" * 32
        return tree.prove_nonexistence(key)

    def test_key_wrong_length(self) -> None:
        proof = self._make_valid_nonexistence_proof()
        proof.key = b"\x00" * 16
        assert verify_nonexistence_proof(proof) is False

    def test_siblings_wrong_count(self) -> None:
        proof = self._make_valid_nonexistence_proof()
        proof.siblings = proof.siblings[:5]
        assert verify_nonexistence_proof(proof) is False

    def test_root_hash_wrong_length(self) -> None:
        proof = self._make_valid_nonexistence_proof()
        proof.root_hash = b"\x00" * 16
        assert verify_nonexistence_proof(proof) is False

    def test_sibling_wrong_length(self) -> None:
        proof = self._make_valid_nonexistence_proof()
        proof.siblings[128] = b"\xff" * 10
        assert verify_nonexistence_proof(proof) is False


# ═══════════════════════════════════════════════════════════════════════
#  2. protocol/telemetry.py
# ═══════════════════════════════════════════════════════════════════════


class TestNoOpSpan:
    """Cover _NoOpSpan methods and context manager protocol."""

    def test_set_attribute_is_noop(self) -> None:
        span = _NoOpSpan()
        assert span.set_attribute("key", "value") is None

    def test_set_status_is_noop(self) -> None:
        span = _NoOpSpan()
        assert span.set_status("OK") is None

    def test_record_exception_is_noop(self) -> None:
        span = _NoOpSpan()
        assert span.record_exception(RuntimeError("test")) is None

    def test_context_manager_returns_self(self) -> None:
        span = _NoOpSpan()
        with span as s:
            assert s is span


class TestNoOpTracer:
    """Cover _NoOpTracer.start_as_current_span."""

    def test_yields_noop_span(self) -> None:
        tracer = _NoOpTracer()
        with tracer.start_as_current_span("test.operation") as span:
            assert isinstance(span, _NoOpSpan)


class TestGetTracerFallback:
    """Cover get_tracer returning _NoOpTracer when OTel unavailable."""

    def test_returns_noop_tracer_when_otel_unavailable(self) -> None:
        with patch("protocol.telemetry._OTEL_AVAILABLE", False):
            tracer = get_tracer("test")
            assert isinstance(tracer, _NoOpTracer)


class TestTimedOperation:
    """Cover timed_operation happy and exception paths."""

    def test_happy_path_records_latency(self) -> None:
        with patch("protocol.telemetry._OTEL_AVAILABLE", False):
            with timed_operation("verify", shard_id="test-shard") as span:
                assert isinstance(span, _NoOpSpan)

    def test_exception_path_still_raises(self) -> None:
        with patch("protocol.telemetry._OTEL_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="boom"):
                with timed_operation("commit") as span:
                    assert isinstance(span, _NoOpSpan)
                    raise RuntimeError("boom")


# ═══════════════════════════════════════════════════════════════════════
#  3. protocol/witness_transport.py
# ═══════════════════════════════════════════════════════════════════════


class TestValidateEndpointUrl:
    """Cover _validate_endpoint_url edge cases."""

    def test_missing_hostname(self) -> None:
        with pytest.raises(ValueError, match="must include a hostname"):
            _validate_endpoint_url("https://", allow_http=True)

    def test_http_not_allowed_by_default(self) -> None:
        with pytest.raises(ValueError, match="not permitted"):
            _validate_endpoint_url("http://example.com")

    def test_https_with_hostname_passes(self) -> None:
        _validate_endpoint_url("https://example.com")


class TestWitnessHTTPTransportClose:
    """Cover WitnessHTTPTransport.close (line 112)."""

    @pytest.mark.asyncio
    async def test_close_owned_client(self) -> None:
        with patch.dict("os.environ", {"OLYMPUS_ENV": "development"}):
            ep = NodeEndpoint(node_id="n1", base_url="https://example.com")
            transport = WitnessHTTPTransport([ep])
            assert transport._owns_client is True
            await transport.close()

    @pytest.mark.asyncio
    async def test_close_external_client_skipped(self) -> None:
        import httpx

        with patch.dict("os.environ", {"OLYMPUS_ENV": "development"}):
            client = httpx.AsyncClient()
            ep = NodeEndpoint(node_id="n1", base_url="https://example.com")
            transport = WitnessHTTPTransport([ep], http_client=client)
            assert transport._owns_client is False
            await transport.close()
            await client.aclose()


class TestRequireEndpointUnknown:
    """Cover _require_endpoint unknown node (line 117)."""

    def test_unknown_node_raises(self) -> None:
        with patch.dict("os.environ", {"OLYMPUS_ENV": "development"}):
            ep = NodeEndpoint(node_id="node-a", base_url="https://example.com")
            transport = WitnessHTTPTransport([ep])
            with pytest.raises(ValueError, match="Unknown node_id: node-b"):
                transport._require_endpoint("node-b")


class TestSelectLoop:
    """Cover _select_loop loop-creation paths (lines 181-188)."""

    def test_creates_new_loop_when_none_exists(self) -> None:
        with patch.dict("os.environ", {"OLYMPUS_ENV": "development"}):
            ep = NodeEndpoint(node_id="n1", base_url="https://example.com")
            transport = WitnessHTTPTransport([ep])

            # Close the current event loop to force _select_loop to create one
            try:
                loop = asyncio.get_event_loop()
                loop.close()
            except RuntimeError:
                pass

            new_loop, owns = transport._select_loop()
            assert owns is True
            assert not new_loop.is_closed()
            new_loop.close()

    def test_reuses_existing_open_loop(self) -> None:
        with patch.dict("os.environ", {"OLYMPUS_ENV": "development"}):
            ep = NodeEndpoint(node_id="n1", base_url="https://example.com")
            transport = WitnessHTTPTransport([ep])
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                returned_loop, owns = transport._select_loop()
                assert owns is False
                assert returned_loop is loop
            finally:
                loop.close()


class TestRunSyncRunningLoop:
    """Cover _run_sync RuntimeError when loop is running (line 170)."""

    @pytest.mark.asyncio
    async def test_raises_when_loop_running(self) -> None:
        with patch.dict("os.environ", {"OLYMPUS_ENV": "development"}):
            ep = NodeEndpoint(node_id="n1", base_url="https://example.com")
            transport = WitnessHTTPTransport([ep])

            async def dummy() -> int:
                return 42

            coro = dummy()
            try:
                with pytest.raises(RuntimeError, match="Cannot use sync wrapper"):
                    transport._run_sync(coro)
            finally:
                # Ensure the coroutine is properly closed to avoid warnings
                coro.close()


class TestCreateWitnessTransportFactory:
    """Cover create_witness_transport factory (lines 235-243)."""

    def test_factory_creates_transport(self) -> None:
        with patch.dict("os.environ", {"OLYMPUS_ENV": "development"}):
            config = [
                {"node_id": "n1", "base_url": "https://a.example.com"},
                {"node_id": "n2", "base_url": "https://b.example.com", "timeout_seconds": 5.0},
            ]
            transport = create_witness_transport(config)
            assert "n1" in transport.endpoints
            assert "n2" in transport.endpoints
            assert transport.endpoints["n2"].timeout_seconds == 5.0


# ═══════════════════════════════════════════════════════════════════════
#  4. protocol/federation/quorum.py
# ═══════════════════════════════════════════════════════════════════════


def _make_test_registry(
    n: int = 3,
) -> tuple[FederationRegistry, list[nacl.signing.SigningKey]]:
    """Build a minimal N-node active registry and return the signing keys."""
    keys = [_test_signing_key(i + 1) for i in range(n)]
    nodes = [
        FederationNode(
            node_id=f"node-{i + 1}",
            pubkey=keys[i].verify_key.encode(),
            endpoint=f"https://node{i + 1}.example.com",
            operator=f"Operator {i + 1}",
            jurisdiction=f"jurisdiction-{i + 1}",
            status="active",
        )
        for i in range(n)
    ]
    return FederationRegistry(nodes=tuple(nodes)), keys


def _make_signed_header(
    registry: FederationRegistry,
    keys: list[nacl.signing.SigningKey],
    signer_indices: list[int] | None = None,
) -> tuple[dict, list[NodeSignature]]:
    """Create a signed shard header that passes header-hash commitment checks."""
    header = create_shard_header(
        shard_id="test-shard",
        root_hash=bytes.fromhex("aa" * 32),
        timestamp="2026-01-01T00:00:00Z",
        height=1,
        round_number=0,
    )
    sign_header(header, keys[0])

    if signer_indices is None:
        signer_indices = list(range(len(keys)))

    sigs = []
    for idx in signer_indices:
        node_id = f"node-{idx + 1}"
        sig = sign_federated_header(header, node_id, keys[idx], registry)
        sigs.append(sig)
    return header, sigs


class TestVerifyFederatedHeaderSignaturesMismatch:
    """Cover header_hash mismatch → empty list (line 202)."""

    def test_mismatched_header_hash_returns_empty(self) -> None:
        registry, keys = _make_test_registry(3)
        header, sigs = _make_signed_header(registry, keys)
        header["header_hash"] = "0" * 64  # break the commitment
        result = verify_federated_header_signatures(header, sigs, registry)
        assert result == []


class TestVerifyFederatedHeaderInactiveNode:
    """Cover inactive node skip (line 215-216)."""

    def test_inactive_node_signature_rejected(self) -> None:
        # Make a registry where node-2 is inactive
        keys = [_test_signing_key(i + 1) for i in range(3)]
        nodes = [
            FederationNode(
                node_id=f"node-{i + 1}",
                pubkey=keys[i].verify_key.encode(),
                endpoint=f"https://node{i + 1}.example.com",
                operator=f"Operator {i + 1}",
                jurisdiction=f"jurisdiction-{i + 1}",
                status="active" if i != 1 else "inactive",
            )
            for i in range(3)
        ]
        registry = FederationRegistry(nodes=tuple(nodes))
        header, _ = _make_signed_header(registry, keys, signer_indices=[0])

        # Sign with the inactive node
        inactive_sig = sign_federated_header(header, "node-2", keys[1], registry)
        result = verify_federated_header_signatures(header, [inactive_sig], registry)
        assert result == []


class TestBuildQuorumCertificateInsufficientSignatures:
    """Cover insufficient signatures → ValueError (line 272)."""

    def test_one_of_three_is_insufficient(self) -> None:
        registry, keys = _make_test_registry(3)
        header, sigs = _make_signed_header(registry, keys, signer_indices=[0])
        with pytest.raises(ValueError, match="Insufficient valid federation signatures"):
            build_quorum_certificate(header, sigs, registry)


class TestVerifyQuorumCertificateInvalid:
    """Cover verify_quorum_certificate failure paths."""

    def _build_valid_certificate(
        self,
    ) -> tuple[dict, dict, FederationRegistry]:
        registry, keys = _make_test_registry(3)
        header, sigs = _make_signed_header(registry, keys)
        cert = build_quorum_certificate(header, sigs, registry)
        return cert, header, registry

    def test_missing_required_fields(self) -> None:
        cert, header, registry = self._build_valid_certificate()
        del cert["signer_bitmap"]
        assert verify_quorum_certificate(cert, header, registry) is False

    def test_wrong_shard_id(self) -> None:
        cert, header, registry = self._build_valid_certificate()
        cert["shard_id"] = "wrong-shard"
        # Recompute hash to pass the hash check
        header["quorum_certificate_hash"] = quorum_certificate_hash(cert)
        assert verify_quorum_certificate(cert, header, registry) is False

    def test_wrong_header_hash(self) -> None:
        cert, header, registry = self._build_valid_certificate()
        cert["header_hash"] = "0" * 64
        header["quorum_certificate_hash"] = quorum_certificate_hash(cert)
        assert verify_quorum_certificate(cert, header, registry) is False

    def test_wrong_height(self) -> None:
        cert, header, registry = self._build_valid_certificate()
        cert["height"] = 999
        header["quorum_certificate_hash"] = quorum_certificate_hash(cert)
        assert verify_quorum_certificate(cert, header, registry) is False

    def test_wrong_validator_count(self) -> None:
        cert, header, registry = self._build_valid_certificate()
        cert["validator_count"] = 999
        header["quorum_certificate_hash"] = quorum_certificate_hash(cert)
        assert verify_quorum_certificate(cert, header, registry) is False

    def test_invalid_bitmap(self) -> None:
        cert, header, registry = self._build_valid_certificate()
        cert["signer_bitmap"] = "xyz"
        header["quorum_certificate_hash"] = quorum_certificate_hash(cert)
        assert verify_quorum_certificate(cert, header, registry) is False

    def test_missing_quorum_certificate_hash_in_header(self) -> None:
        cert, header, registry = self._build_valid_certificate()
        del header["quorum_certificate_hash"]
        assert verify_quorum_certificate(cert, header, registry) is False

    def test_non_matching_quorum_certificate_hash(self) -> None:
        cert, header, registry = self._build_valid_certificate()
        header["quorum_certificate_hash"] = "0" * 64
        assert verify_quorum_certificate(cert, header, registry) is False

    def test_wrong_round(self) -> None:
        cert, header, registry = self._build_valid_certificate()
        cert["round"] = 999
        header["quorum_certificate_hash"] = quorum_certificate_hash(cert)
        assert verify_quorum_certificate(cert, header, registry) is False

    def test_bad_federation_epoch_type(self) -> None:
        cert, header, registry = self._build_valid_certificate()
        cert["federation_epoch"] = "not-an-int"
        # Don't recompute hash — the epoch parse fails before hash check
        assert verify_quorum_certificate(cert, header, registry) is False

    def test_wrong_scheme(self) -> None:
        cert, header, registry = self._build_valid_certificate()
        cert["scheme"] = "rsa"
        header["quorum_certificate_hash"] = quorum_certificate_hash(cert)
        assert verify_quorum_certificate(cert, header, registry) is False


# ═══════════════════════════════════════════════════════════════════════
#  5. protocol/federation/identity.py
# ═══════════════════════════════════════════════════════════════════════


class TestFederationKeyHistoryEntry:
    """Cover to_dict and from_dict (lines 46, 51)."""

    def test_to_dict(self) -> None:
        entry = FederationKeyHistoryEntry(pubkey=b"\xab" * 32, valid_until="2025-01-01T00:00:00Z")
        d = entry.to_dict()
        assert d["pubkey"] == ("ab" * 32)
        assert d["valid_until"] == "2025-01-01T00:00:00Z"

    def test_from_dict(self) -> None:
        data = {"pubkey": "ab" * 32, "valid_until": "2025-06-01T00:00:00Z"}
        entry = FederationKeyHistoryEntry.from_dict(data)
        assert entry.pubkey == b"\xab" * 32
        assert entry.valid_until == "2025-06-01T00:00:00Z"

    def test_roundtrip(self) -> None:
        original = FederationKeyHistoryEntry(pubkey=b"\xcd" * 32, valid_until="2025-12-31T23:59:59Z")
        restored = FederationKeyHistoryEntry.from_dict(original.to_dict())
        assert restored == original


class TestFederationRegistryValidationErrors:
    """Cover validation errors in FederationRegistry.from_dict."""

    def _base_node(self, node_id: str, pubkey_hex: str) -> dict:
        return {
            "node_id": node_id,
            "pubkey": pubkey_hex,
            "endpoint": f"https://{node_id}.example.com",
            "operator": "Test Op",
            "jurisdiction": "test-j",
            "status": "active",
        }

    def test_empty_nodes_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one node"):
            FederationRegistry.from_dict({"nodes": []})

    def test_duplicate_node_ids(self) -> None:
        pk1 = _test_signing_key(1).verify_key.encode().hex()
        pk2 = _test_signing_key(2).verify_key.encode().hex()
        with pytest.raises(ValueError, match="node_id values must be unique"):
            FederationRegistry.from_dict(
                {
                    "nodes": [
                        self._base_node("dup", pk1),
                        self._base_node("dup", pk2),
                    ]
                }
            )

    def test_duplicate_pubkeys_across_nodes(self) -> None:
        shared_pk = _test_signing_key(1).verify_key.encode().hex()
        with pytest.raises(ValueError, match="pubkey values must be unique"):
            FederationRegistry.from_dict(
                {
                    "nodes": [
                        self._base_node("n1", shared_pk),
                        self._base_node("n2", shared_pk),
                    ]
                }
            )

    def test_duplicate_key_in_history(self) -> None:
        pk1 = _test_signing_key(1).verify_key.encode().hex()
        # current pubkey is same as a historical key
        with pytest.raises(ValueError, match="pubkey values must be unique"):
            FederationRegistry.from_dict(
                {
                    "nodes": [
                        {
                            **self._base_node("n1", pk1),
                            "key_history": [
                                {"pubkey": pk1, "valid_until": "2025-01-01T00:00:00Z"},
                            ],
                        },
                    ]
                }
            )

    def test_negative_epoch(self) -> None:
        pk = _test_signing_key(1).verify_key.encode().hex()
        with pytest.raises(ValueError, match="epoch must be non-negative"):
            FederationRegistry.from_dict(
                {"nodes": [self._base_node("n1", pk)], "epoch": -1}
            )


class TestGetSnapshotNegativeEpoch:
    """Cover get_snapshot with negative epoch (lines 220-223)."""

    def test_negative_epoch_raises(self) -> None:
        registry, _ = _make_test_registry(3)
        with pytest.raises(ValueError, match="epoch must be non-negative"):
            registry.get_snapshot(-1)

    def test_missing_epoch_raises(self) -> None:
        registry, _ = _make_test_registry(3)
        with pytest.raises(ValueError, match="No registry snapshot available"):
            registry.get_snapshot(999)


class TestRotateNodeKeyValidation:
    """Cover rotate_node_key timestamp validation (lines 287-288)."""

    def test_invalid_timestamp_raises(self) -> None:
        registry, keys = _make_test_registry(3)
        new_key = _test_signing_key(99)
        with pytest.raises(ValueError, match="Invalid rotation timestamp"):
            registry.rotate_node_key(
                node_id="node-1",
                new_pubkey=new_key.verify_key.encode(),
                rotated_at="not-a-timestamp",
            )

    def test_same_pubkey_raises(self) -> None:
        registry, keys = _make_test_registry(3)
        with pytest.raises(ValueError, match="new_pubkey must differ"):
            registry.rotate_node_key(
                node_id="node-1",
                new_pubkey=keys[0].verify_key.encode(),
                rotated_at="2025-06-01T00:00:00Z",
            )

    def test_unknown_node_raises(self) -> None:
        registry, _ = _make_test_registry(3)
        new_key = _test_signing_key(99)
        with pytest.raises(ValueError, match="Unknown federation node"):
            registry.rotate_node_key(
                node_id="nonexistent",
                new_pubkey=new_key.verify_key.encode(),
                rotated_at="2025-06-01T00:00:00Z",
            )


class TestExtractRoundAndHeight:
    """Cover _extract_round_and_height error paths (lines 356-359)."""

    def test_missing_height_raises(self) -> None:
        with pytest.raises(ValueError, match="require integer height and round"):
            _extract_round_and_height({"round": 0})

    def test_missing_round_raises(self) -> None:
        with pytest.raises(ValueError, match="require integer height and round"):
            _extract_round_and_height({"height": 0})

    def test_non_integer_height_raises(self) -> None:
        with pytest.raises(ValueError, match="require integer height and round"):
            _extract_round_and_height({"height": "abc", "round": 0})

    def test_negative_height_raises(self) -> None:
        with pytest.raises(ValueError, match="must be non-negative"):
            _extract_round_and_height({"height": -1, "round": 0})

    def test_negative_round_raises(self) -> None:
        with pytest.raises(ValueError, match="must be non-negative"):
            _extract_round_and_height({"height": 0, "round": -1})

    def test_valid_values(self) -> None:
        h, r = _extract_round_and_height({"height": 5, "round": 3})
        assert h == 5
        assert r == 3
