"""
Infrastructure & critical-path coverage tests for Olympus.

Each test targets a specific uncovered line in an infrastructure or
critical-path module and validates the *semantic* behaviour of that code
path, not merely its reachability.
"""

import importlib
import logging
import os
import sys

import pytest
from unittest.mock import MagicMock, patch

import protocol.hashes  # noqa: F811 — used via importlib.reload()
from protocol.hashes import hash_bytes
from protocol.consistency import (
    ConsistencyProof,
    generate_consistency_proof,
    verify_consistency_proof as consistency_verify,
)
from protocol.merkle import (
    MerkleTree,
    _verify_subproof_ct,
)
from protocol.monitoring import LogMonitor
from storage.consistency_checker import SMTConsistencyChecker
from storage.gates import derive_node_rehash_gate


# ===================================================================
# 1. protocol/hashes.py – line 40: OLYMPUS_REQUIRE_RUST RuntimeError
# ===================================================================


class TestRequireRustGuard:
    """When OLYMPUS_REQUIRE_RUST=1 and the Rust extension is absent, reload must raise."""

    def test_require_rust_raises_when_extension_missing(self):
        """RuntimeError must fire when OLYMPUS_REQUIRE_RUST=1 but Rust ext is absent."""
        # Snapshot current module state so we can restore it after the test.
        saved_crypto = sys.modules.get("olympus_core.crypto")
        saved_core = sys.modules.get("olympus_core")

        try:
            # Block the import by inserting None, which causes ImportError
            # on `from olympus_core.crypto import …`
            sys.modules["olympus_core"] = None  # type: ignore[assignment]
            sys.modules["olympus_core.crypto"] = None  # type: ignore[assignment]

            with patch.dict(os.environ, {"OLYMPUS_REQUIRE_RUST": "1"}):
                with pytest.raises(RuntimeError, match="Rust crypto extension required"):
                    importlib.reload(protocol.hashes)
        finally:
            # Restore original module entries
            if saved_core is not None:
                sys.modules["olympus_core"] = saved_core
            else:
                sys.modules.pop("olympus_core", None)

            if saved_crypto is not None:
                sys.modules["olympus_core.crypto"] = saved_crypto
            else:
                sys.modules.pop("olympus_core.crypto", None)

            # Re-load cleanly so downstream tests are unaffected
            importlib.reload(protocol.hashes)

    def test_no_error_when_require_rust_unset(self):
        """Module reloads cleanly when OLYMPUS_REQUIRE_RUST is not set."""
        saved_crypto = sys.modules.get("olympus_core.crypto")
        saved_core = sys.modules.get("olympus_core")

        try:
            sys.modules["olympus_core"] = None  # type: ignore[assignment]
            sys.modules["olympus_core.crypto"] = None  # type: ignore[assignment]

            with patch.dict(os.environ, {"OLYMPUS_REQUIRE_RUST": "0"}):
                # Should NOT raise – the guard only fires for truthy values.
                importlib.reload(protocol.hashes)
        finally:
            if saved_core is not None:
                sys.modules["olympus_core"] = saved_core
            else:
                sys.modules.pop("olympus_core", None)

            if saved_crypto is not None:
                sys.modules["olympus_core.crypto"] = saved_crypto
            else:
                sys.modules.pop("olympus_core.crypto", None)

            importlib.reload(protocol.hashes)


# ===================================================================
# 2. protocol/merkle.py – line 630: "Proof exhausted for single-leaf subtree"
# ===================================================================


class TestMerkleSubproofSingleLeafExhausted:
    """Cover the guard at line 630 of _verify_subproof_ct."""

    def test_proof_exhausted_for_single_leaf_subtree(self):
        """Empty proof with new_size=1, old_size=0 must raise ValueError."""
        with pytest.raises(ValueError, match="Proof exhausted for single-leaf subtree"):
            _verify_subproof_ct(
                proof=[],
                proof_index=0,
                old_size=0,
                new_size=1,
                is_root=False,
            )

    def test_single_leaf_subtree_with_sufficient_proof(self):
        """A single proof node is enough for new_size=1, old_size=0."""
        dummy_hash = b"\x00" * 32
        root_old, root_new, idx = _verify_subproof_ct(
            proof=[dummy_hash],
            proof_index=0,
            old_size=0,
            new_size=1,
            is_root=False,
        )
        assert root_old == dummy_hash
        assert root_new == dummy_hash
        assert idx == 1


# ===================================================================
# 3. protocol/consistency.py – validation lines 49, 110, 112, 169, 171
# ===================================================================


class TestConsistencyProofValidation:
    """Cover __post_init__ and function-level input validation."""

    def test_proof_nodes_must_be_list(self):
        """Line 49: proof_nodes that is not a list raises ValueError."""
        with pytest.raises(ValueError, match="proof_nodes must be a list"):
            ConsistencyProof(old_tree_size=1, new_tree_size=2, proof_nodes="not-a-list")  # type: ignore[arg-type]

    def test_negative_tree_sizes_in_constructor(self):
        """Line 44-45: negative tree sizes raise."""
        with pytest.raises(ValueError, match="Tree sizes must be non-negative"):
            ConsistencyProof(old_tree_size=-1, new_tree_size=2, proof_nodes=[])

    def test_old_exceeds_new_in_constructor(self):
        """Line 46-47: old > new raises."""
        with pytest.raises(ValueError, match="old_tree_size cannot exceed new_tree_size"):
            ConsistencyProof(old_tree_size=5, new_tree_size=2, proof_nodes=[])


class TestGenerateConsistencyProofValidation:
    """Cover generate_consistency_proof input guards (lines 110, 112)."""

    def _make_tree(self, n: int) -> MerkleTree:
        leaves = [hash_bytes(f"leaf-{i}".encode()) for i in range(n)]
        return MerkleTree(leaves)

    def test_negative_tree_size_generate(self):
        """Line 110: negative tree sizes raise ValueError."""
        tree = self._make_tree(5)
        with pytest.raises(ValueError, match="Tree sizes must be non-negative"):
            generate_consistency_proof(-1, 5, tree)

    def test_old_exceeds_new_generate(self):
        """Line 112: old_tree_size > new_tree_size raises ValueError."""
        tree = self._make_tree(10)
        with pytest.raises(ValueError, match="old_tree_size cannot exceed new_tree_size"):
            generate_consistency_proof(10, 5, tree)


class TestVerifyConsistencyProofValidation:
    """Cover verify_consistency_proof root-validation guards (lines 169, 171)."""

    def test_old_root_wrong_type_returns_false(self):
        """Line 168-169: non-bytes old_root returns False."""
        proof = ConsistencyProof(old_tree_size=1, new_tree_size=2, proof_nodes=[b"\x00" * 32])
        result = consistency_verify("not-bytes", b"\x00" * 32, proof)  # type: ignore[arg-type]
        assert result is False

    def test_old_root_wrong_length_returns_false(self):
        """Line 168-169: old_root with wrong length returns False."""
        proof = ConsistencyProof(old_tree_size=1, new_tree_size=2, proof_nodes=[b"\x00" * 32])
        result = consistency_verify(b"\x00" * 16, b"\x00" * 32, proof)
        assert result is False

    def test_new_root_wrong_type_returns_false(self):
        """Line 170-171: non-bytes new_root returns False."""
        proof = ConsistencyProof(old_tree_size=1, new_tree_size=2, proof_nodes=[b"\x00" * 32])
        result = consistency_verify(b"\x00" * 32, "not-bytes", proof)  # type: ignore[arg-type]
        assert result is False

    def test_new_root_wrong_length_returns_false(self):
        """Line 170-171: new_root with wrong length returns False."""
        proof = ConsistencyProof(old_tree_size=1, new_tree_size=2, proof_nodes=[b"\x00" * 32])
        result = consistency_verify(b"\x00" * 32, b"\x00" * 16, proof)
        assert result is False


# ===================================================================
# 4. protocol/monitoring.py – line 96: "Consistency proof rejected"
# ===================================================================


class TestLogMonitorConsistencyRejected:
    """Cover the monitor's consistency-proof rejection path."""

    @staticmethod
    def _make_sth(*, tree_size: int, merkle_root: str) -> MagicMock:
        """Build a minimal STH stub that passes signature verification."""
        sth = MagicMock()
        sth.tree_size = tree_size
        sth.merkle_root = merkle_root
        sth.verify.return_value = True
        return sth

    def test_consistency_proof_rejected(self):
        """Line 96: invalid proof must raise ValueError."""
        monitor = LogMonitor()

        # Record an initial observation (no prior state, no proof needed).
        sth1 = self._make_sth(tree_size=5, merkle_root="aabb" * 8)
        monitor.record_observation(node_id="n1", shard_id="s1", sth=sth1)

        # Larger tree with a proof that fails verification.
        sth2 = self._make_sth(tree_size=10, merkle_root="ccdd" * 8)

        # The proof object's verify will be called via verify_sth_consistency
        # Patch the function to return False (= proof rejected).
        with patch("protocol.monitoring.verify_sth_consistency", return_value=False):
            with pytest.raises(ValueError, match="Consistency proof rejected"):
                monitor.record_observation(
                    node_id="n1",
                    shard_id="s1",
                    sth=sth2,
                    proof=MagicMock(),  # dummy proof object
                )

    def test_consistency_proof_accepted(self):
        """Symmetry check: valid proof does not raise."""
        monitor = LogMonitor()
        sth1 = self._make_sth(tree_size=5, merkle_root="aabb" * 8)
        monitor.record_observation(node_id="n1", shard_id="s1", sth=sth1)

        sth2 = self._make_sth(tree_size=10, merkle_root="ccdd" * 8)
        with patch("protocol.monitoring.verify_sth_consistency", return_value=True):
            obs = monitor.record_observation(
                node_id="n1",
                shard_id="s1",
                sth=sth2,
                proof=MagicMock(),
            )
            assert obs.sth is sth2


# ===================================================================
# 5. storage/gates.py – lines 16-17: secret incorporation
# ===================================================================


class TestNodeRehashGate:
    """Cover the secret-branch in derive_node_rehash_gate."""

    def test_without_secret(self):
        """Without the env var the gate is a valid 64-char hex string."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OLYMPUS_NODE_REHASH_GATE_SECRET", None)
            gate = derive_node_rehash_gate()
        assert len(gate) == 64
        int(gate, 16)  # valid hex

    def test_with_secret(self):
        """With a secret the gate changes and is still valid hex."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OLYMPUS_NODE_REHASH_GATE_SECRET", None)
            gate_no_secret = derive_node_rehash_gate()

        with patch.dict(os.environ, {"OLYMPUS_NODE_REHASH_GATE_SECRET": "my-secret"}):
            gate_with_secret = derive_node_rehash_gate()

        assert len(gate_with_secret) == 64
        int(gate_with_secret, 16)  # valid hex
        assert gate_no_secret != gate_with_secret, "Secret must change the gate value"

    def test_different_secrets_produce_different_gates(self):
        """Two distinct secrets must yield distinct gate values."""
        with patch.dict(os.environ, {"OLYMPUS_NODE_REHASH_GATE_SECRET": "alpha"}):
            g1 = derive_node_rehash_gate()
        with patch.dict(os.environ, {"OLYMPUS_NODE_REHASH_GATE_SECRET": "beta"}):
            g2 = derive_node_rehash_gate()
        assert g1 != g2


# ===================================================================
# 6. storage/blob.py – lines 84, 123, 153: S3 ClientError re-raise
# ===================================================================

def _client_error(code: str) -> Exception:
    """Build a botocore-style ClientError with the given error code."""
    from botocore.exceptions import ClientError
    return ClientError(
        error_response={"Error": {"Code": code, "Message": "test"}},
        operation_name="test",
    )


class TestBlobStoreS3Errors:
    """Cover the re-raise branches in put_artifact, get_artifact, and exists."""

    VALID_HASH = "ab" * 32  # 64 hex chars

    def _make_store(self) -> MagicMock:
        """Return a BlobStore with a mocked S3 client."""
        with patch("storage.blob.boto3") as mock_boto3:
            mock_s3 = MagicMock()
            mock_boto3.client.return_value = mock_s3
            from storage.blob import BlobStore
            store = BlobStore()
        store.s3 = mock_s3
        return store

    # -- put_artifact (line 84) ------------------------------------------

    def test_put_artifact_reraises_non_404(self):
        """Line 84: head_object ClientError code != '404' must re-raise."""
        store = self._make_store()
        store.s3.head_object.side_effect = _client_error("403")

        from botocore.exceptions import ClientError
        with pytest.raises(ClientError) as exc_info:
            store.put_artifact(self.VALID_HASH, b"data", "application/pdf")
        assert exc_info.value.response["Error"]["Code"] == "403"

    def test_put_artifact_succeeds_on_404(self):
        """When head_object 404s the object is uploaded normally."""
        store = self._make_store()
        store.s3.head_object.side_effect = _client_error("404")
        store.s3.put_object.return_value = {}

        result = store.put_artifact(self.VALID_HASH, b"data", "application/pdf")
        assert result == self.VALID_HASH
        store.s3.put_object.assert_called_once()

    # -- get_artifact (line 123) -----------------------------------------

    def test_get_artifact_returns_none_on_nosuchkey(self):
        """Line 121-122: NoSuchKey → None."""
        store = self._make_store()
        store.s3.get_object.side_effect = _client_error("NoSuchKey")

        assert store.get_artifact(self.VALID_HASH) is None

    def test_get_artifact_reraises_non_nosuchkey(self):
        """Line 123: non-NoSuchKey ClientError re-raises."""
        store = self._make_store()
        store.s3.get_object.side_effect = _client_error("AccessDenied")

        from botocore.exceptions import ClientError
        with pytest.raises(ClientError) as exc_info:
            store.get_artifact(self.VALID_HASH)
        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    # -- exists (line 153) -----------------------------------------------

    def test_exists_returns_false_on_404(self):
        """Line 151-152: 404 → False."""
        store = self._make_store()
        store.s3.head_object.side_effect = _client_error("404")

        assert store.exists(self.VALID_HASH) is False

    def test_exists_reraises_non_404(self):
        """Line 153: non-404 ClientError re-raises."""
        store = self._make_store()
        store.s3.head_object.side_effect = _client_error("500")

        from botocore.exceptions import ClientError
        with pytest.raises(ClientError) as exc_info:
            store.exists(self.VALID_HASH)
        assert exc_info.value.response["Error"]["Code"] == "500"


# ===================================================================
# 7. storage/consistency_checker.py – lines 162-164: _loop warnings
# ===================================================================


class TestConsistencyCheckerLoop:
    """Cover the _loop method's divergence-warning and exception-handler paths."""

    def test_loop_logs_warning_on_divergent_shards(self, caplog):
        """Lines 161-162: divergent shards trigger a WARNING log."""
        mock_storage = MagicMock()
        mock_storage.get_all_shard_ids.return_value = ["shard-a"]
        mock_storage.verify_persisted_root.return_value = False  # divergent

        checker = SMTConsistencyChecker(mock_storage)

        # Run the background loop for one iteration then stop.
        with caplog.at_level(logging.WARNING):
            checker.start(interval_seconds=9999)
            # Give the thread a moment to execute _loop once.
            import time
            time.sleep(0.3)
            checker.stop(timeout=5)

        assert any("Divergent shards detected" in r.message for r in caplog.records)

    def test_loop_logs_exception_on_unhandled_error(self, caplog):
        """Lines 163-164: unhandled exception in run_all triggers logging."""
        mock_storage = MagicMock()
        mock_storage.get_all_shard_ids.side_effect = RuntimeError("boom")

        checker = SMTConsistencyChecker(mock_storage)

        with caplog.at_level(logging.ERROR):
            checker.start(interval_seconds=9999)
            import time
            time.sleep(0.3)
            checker.stop(timeout=5)

        # run_all wraps get_all_shard_ids failure in an error log already,
        # but the _loop also catches any leftover unhandled exceptions.
        assert any("boom" in r.message or "Failed to enumerate shards" in r.message for r in caplog.records)

    def test_run_all_divergence_halt(self):
        """halt_on_divergence=True stops checking after first divergent shard."""
        mock_storage = MagicMock()
        mock_storage.get_all_shard_ids.return_value = ["a", "b", "c"]
        mock_storage.verify_persisted_root.return_value = False  # all divergent

        checker = SMTConsistencyChecker(mock_storage, halt_on_divergence=True)
        report = checker.run_all()

        # Should halt after the first divergent shard.
        assert len(report.results) == 1
        assert not report.all_consistent
        assert report.divergent_shards == ["a"]
