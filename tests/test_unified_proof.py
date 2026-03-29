"""
Tests for unified proof system

This module tests the unified proof that verifies:
1. Document canonicalization
2. Merkle inclusion in ledger
3. Ledger root commitment in checkpoint

Checkpoint integrity (component 4 - federation quorum signatures) is verified
at the Python layer, not in the circuit.

Tests cover both Groth16 and Halo2 backends (when available).
"""

import pytest

from protocol.checkpoints import SignedCheckpoint
from protocol.federation import FederationNode, FederationRegistry
from protocol.halo2_backend import Halo2Verifier, is_halo2_available
from protocol.unified_proof import (
    ProofBackend,
    UnifiedProof,
    UnifiedProofGenerator,
    UnifiedProofVerifier,
    UnifiedPublicInputs,
    VerificationResult,
    verify_unified_proof,
)


class TestUnifiedProofStructure:
    """Test unified proof data structures."""

    def test_unified_public_inputs_creation(self):
        """Test creating UnifiedPublicInputs."""
        inputs = UnifiedPublicInputs(
            canonical_hash="12345",
            merkle_root="67890",
            ledger_root="11111",
        )

        assert inputs.canonical_hash == "12345"
        assert inputs.merkle_root == "67890"
        assert inputs.ledger_root == "11111"

    def test_unified_proof_creation(self):
        """Test creating UnifiedProof with all components."""
        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")

        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc123",
            previous_checkpoint_hash="",
            ledger_height=100,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def456",
            federation_quorum_certificate={},
        )

        proof = UnifiedProof(
            zk_proof={"pi_a": [], "pi_b": [], "pi_c": []},
            public_inputs=public_inputs,
            checkpoint=checkpoint,
            backend=ProofBackend.GROTH16,
        )

        assert proof.backend == ProofBackend.GROTH16
        assert proof.checkpoint.sequence == 1

    def test_unified_proof_serialization(self):
        """Test proof serialization to/from dict."""
        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")

        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc123",
            previous_checkpoint_hash="",
            ledger_height=100,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def456",
            federation_quorum_certificate={},
        )

        proof = UnifiedProof(
            zk_proof={"test": "data"},
            public_inputs=public_inputs,
            checkpoint=checkpoint,
        )

        # Serialize and deserialize
        proof_dict = proof.to_dict()
        restored = UnifiedProof.from_dict(proof_dict)

        assert restored.public_inputs.canonical_hash == "1"
        assert restored.checkpoint.sequence == 1
        assert restored.backend == ProofBackend.GROTH16


class TestVerificationResult:
    """Test VerificationResult enum."""

    def test_valid_result_is_truthy(self):
        """VALID result should be truthy."""
        result = VerificationResult.VALID
        assert result.is_valid
        assert bool(result)

    def test_invalid_results_are_falsy(self):
        """Invalid results should be falsy."""
        invalid_results = [
            VerificationResult.INVALID_ZK_PROOF,
            VerificationResult.INVALID_CHECKPOINT,
            VerificationResult.INVALID_QUORUM,
            VerificationResult.UNABLE_TO_VERIFY,
        ]

        for result in invalid_results:
            assert not result.is_valid
            assert not bool(result)


class TestUnifiedProofVerifier:
    """Test UnifiedProofVerifier logic."""

    def test_verifier_initialization(self):
        """Test verifier can be initialized."""
        verifier = UnifiedProofVerifier()
        assert verifier.registry is None

    def test_verifier_with_registry(self):
        """Test verifier with federation registry."""
        nodes = [
            FederationNode(
                node_id="node1",
                pubkey=b"x" * 32,
                endpoint="http://node1",
                operator="operator1",
                jurisdiction="US",
            )
        ]
        registry = FederationRegistry(nodes=nodes, epoch=1)

        verifier = UnifiedProofVerifier(registry=registry)
        assert verifier.registry is not None
        assert verifier.registry.epoch == 1

    def test_verify_missing_artifacts_returns_error(self):
        """Test verification fails gracefully when artifacts missing."""
        verifier = UnifiedProofVerifier()

        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")

        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def",
            federation_quorum_certificate={},
        )

        proof = UnifiedProof(
            zk_proof={},  # Empty proof
            public_inputs=public_inputs,
            checkpoint=checkpoint,
        )

        # Should fail verification (no actual proof)
        result = verifier.verify(proof)
        assert not result.is_valid

    def test_verify_checks_checkpoint_structure(self):
        """Test verifier validates checkpoint structure."""
        verifier = UnifiedProofVerifier()

        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")

        # Checkpoint with empty hash (invalid)
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="",  # Invalid: empty
            federation_quorum_certificate={},
        )

        proof = UnifiedProof(
            zk_proof={},
            public_inputs=public_inputs,
            checkpoint=checkpoint,
        )

        result = verifier._verify_checkpoint_structure(proof)
        assert not result


class TestUnifiedProofGenerator:
    """Test UnifiedProofGenerator."""

    def test_generate_returns_witness_backed_proof(self):
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc123",
            previous_checkpoint_hash="",
            ledger_height=100,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def456",
            federation_quorum_certificate={},
        )

        generator = UnifiedProofGenerator()
        proof = generator.generate(
            ["section 0", "section 1"], merkle_proof={}, checkpoint=checkpoint
        )

        assert proof.backend == ProofBackend.GROTH16
        assert proof.checkpoint == checkpoint
        assert proof.public_inputs.merkle_root == proof.public_inputs.ledger_root
        assert proof.zk_proof["witness"]["root"] == proof.public_inputs.merkle_root


class TestProofBackendSelection:
    """Test proof backend selection (Groth16 vs Halo2)."""

    def test_groth16_backend_default(self):
        """Groth16 should be the default backend."""
        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")

        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def",
            federation_quorum_certificate={},
        )

        proof = UnifiedProof(
            zk_proof={},
            public_inputs=public_inputs,
            checkpoint=checkpoint,
        )

        assert proof.backend == ProofBackend.GROTH16

    def test_halo2_backend_selection(self):
        """Can explicitly select Halo2 backend."""
        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")

        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def",
            federation_quorum_certificate={},
        )

        proof = UnifiedProof(
            zk_proof={},
            public_inputs=public_inputs,
            checkpoint=checkpoint,
            backend=ProofBackend.HALO2,
        )

        assert proof.backend == ProofBackend.HALO2

    @pytest.mark.skipif(is_halo2_available(), reason="Halo2 not yet implemented")
    def test_halo2_verification_not_implemented(self):
        """Halo2 verification should raise NotImplementedError."""
        verifier = Halo2Verifier()

        from protocol.halo2_backend import Halo2Proof

        proof = Halo2Proof(
            proof=b"dummy",
            public_inputs=["1", "2", "3", "4"],
            circuit="unified_canonicalization_inclusion_root_sign",
        )

        with pytest.raises(NotImplementedError):
            verifier.verify(proof)


class TestConvenienceFunctions:
    """Test convenience functions for unified proofs."""

    def test_verify_unified_proof_function(self):
        """Test the verify_unified_proof convenience function."""
        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")

        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def",
            federation_quorum_certificate={},
        )

        proof = UnifiedProof(
            zk_proof={},
            public_inputs=public_inputs,
            checkpoint=checkpoint,
        )

        result = verify_unified_proof(proof)
        assert isinstance(result, VerificationResult)


class TestIntegrationScenarios:
    """Test end-to-end integration scenarios."""

    def test_full_verification_flow_without_zk_proof(self):
        """Test verification flow without actual ZK proof (structure only)."""
        # Create a minimal federation registry
        nodes = [
            FederationNode(
                node_id=f"node{i}",
                pubkey=bytes([i] * 32),
                endpoint=f"http://node{i}",
                operator=f"operator{i}",
                jurisdiction="US",
            )
            for i in range(3)
        ]
        registry = FederationRegistry(nodes=nodes, epoch=1)

        # Create proof structure
        public_inputs = UnifiedPublicInputs(
            canonical_hash="1000000",
            merkle_root="2000000",
            ledger_root="3000000",
        )

        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc123",
            previous_checkpoint_hash="",
            ledger_height=100,
            shard_roots={"shard1": "root123"},
            consistency_proof=["proof1", "proof2"],
            checkpoint_hash="checkpoint123",
            federation_quorum_certificate={
                "signatures": [],
                "quorum_threshold": 2,
            },
        )

        proof = UnifiedProof(
            zk_proof={},
            public_inputs=public_inputs,
            checkpoint=checkpoint,
        )

        verifier = UnifiedProofVerifier(registry=registry)
        result = verifier.verify(proof)

        # Should fail ZK proof check (no actual proof provided)
        assert not result.is_valid

    def test_documentation_example(self):
        """Test example from module docstring works."""
        # This tests the example usage pattern from the docstring
        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")

        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def",
            federation_quorum_certificate={},
        )

        proof = UnifiedProof(
            zk_proof={},
            public_inputs=public_inputs,
            checkpoint=checkpoint,
        )

        verifier = UnifiedProofVerifier()
        result = verifier.verify(proof)

        # Verify returns a VerificationResult
        assert isinstance(result, VerificationResult)


# ---------------------------------------------------------------------------
# Extended tests (Step 2i)
# ---------------------------------------------------------------------------


class TestGetBackend:
    """Test backend retrieval."""

    def test_get_groth16_backend(self):
        verifier = UnifiedProofVerifier()
        backend = verifier.get_backend(ProofBackend.GROTH16)
        assert backend is verifier._groth16_backend

    def test_get_halo2_backend(self):
        verifier = UnifiedProofVerifier()
        backend = verifier.get_backend(ProofBackend.HALO2)
        assert backend is verifier._halo2_backend


class TestVerifyViaBackendPaths:
    """Test _verify_via_backend error paths."""

    def test_backend_not_available_returns_false(self):
        from unittest.mock import MagicMock

        verifier = UnifiedProofVerifier()
        mock_backend = MagicMock()
        mock_backend.is_available.return_value = False

        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def",
            federation_quorum_certificate={},
        )
        proof = UnifiedProof(zk_proof={}, public_inputs=public_inputs, checkpoint=checkpoint)

        result = verifier._verify_via_backend(proof, mock_backend)
        assert result is False

    def test_backend_exception_returns_false(self):
        from unittest.mock import MagicMock

        verifier = UnifiedProofVerifier()
        mock_backend = MagicMock()
        mock_backend.is_available.return_value = True
        mock_backend.verify.side_effect = ValueError("boom")

        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def",
            federation_quorum_certificate={},
        )
        proof = UnifiedProof(zk_proof={}, public_inputs=public_inputs, checkpoint=checkpoint)

        result = verifier._verify_via_backend(proof, mock_backend)
        assert result is False


class TestCheckpointStructureValidation:
    """Extended checkpoint structure tests."""

    def test_valid_checkpoint_passes(self):
        verifier = UnifiedProofVerifier()
        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="valid-hash",
            federation_quorum_certificate={},
        )
        proof = UnifiedProof(zk_proof={}, public_inputs=public_inputs, checkpoint=checkpoint)
        assert verifier._verify_checkpoint_structure(proof) is True

    def test_empty_checkpoint_hash_fails(self):
        verifier = UnifiedProofVerifier()
        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="",
            federation_quorum_certificate={},
        )
        proof = UnifiedProof(zk_proof={}, public_inputs=public_inputs, checkpoint=checkpoint)
        assert verifier._verify_checkpoint_structure(proof) is False


class TestQuorumCertificateVerification:
    """Extended quorum certificate checks."""

    def test_no_registry_skips_quorum_check(self):
        verifier = UnifiedProofVerifier(registry=None)
        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def",
            federation_quorum_certificate={},
        )
        proof = UnifiedProof(zk_proof={}, public_inputs=public_inputs, checkpoint=checkpoint)
        # _verify_quorum_certificate returns True when no registry
        assert verifier._verify_quorum_certificate(proof) is True

    def test_with_registry_and_invalid_cert_fails(self):
        nodes = [
            FederationNode(
                node_id="node1",
                pubkey=b"x" * 32,
                endpoint="http://node1",
                operator="op",
                jurisdiction="US",
            )
        ]
        registry = FederationRegistry(nodes=nodes, epoch=1)
        verifier = UnifiedProofVerifier(registry=registry)

        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def",
            federation_quorum_certificate={"signatures": [], "quorum_threshold": 2},
        )
        proof = UnifiedProof(zk_proof={}, public_inputs=public_inputs, checkpoint=checkpoint)
        result = verifier._verify_quorum_certificate(proof)
        assert result is False


class TestVerifyUnifiedProofConvenience:
    """Test verify_unified_proof convenience function with backend override."""

    def test_backend_override(self):
        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def",
            federation_quorum_certificate={},
        )
        proof = UnifiedProof(
            zk_proof={},
            public_inputs=public_inputs,
            checkpoint=checkpoint,
            backend=ProofBackend.GROTH16,
        )

        result = verify_unified_proof(proof, backend=ProofBackend.HALO2)
        assert isinstance(result, VerificationResult)
        # Backend should have been overridden
        assert proof.backend == ProofBackend.HALO2

    def test_with_registry(self):
        nodes = [
            FederationNode(
                node_id="node1",
                pubkey=b"x" * 32,
                endpoint="http://node1",
                operator="op",
                jurisdiction="US",
            )
        ]
        registry = FederationRegistry(nodes=nodes, epoch=1)

        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def",
            federation_quorum_certificate={},
        )
        proof = UnifiedProof(zk_proof={}, public_inputs=public_inputs, checkpoint=checkpoint)
        result = verify_unified_proof(proof, registry=registry)
        assert isinstance(result, VerificationResult)


class TestMissingArtifacts:
    """Test MISSING_ARTIFACTS result."""

    def test_missing_artifacts_detection(self):
        result = VerificationResult.MISSING_ARTIFACTS
        assert not result.is_valid
        assert not bool(result)
        assert result.value == "missing_artifacts"


class TestGeneratorEdgeCases:
    """Test UnifiedProofGenerator edge cases."""

    def test_empty_sections_raises(self):
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc123",
            previous_checkpoint_hash="",
            ledger_height=100,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def456",
            federation_quorum_certificate={},
        )
        generator = UnifiedProofGenerator()
        with pytest.raises(ValueError, match="at least one section"):
            generator.generate([], merkle_proof={}, checkpoint=checkpoint)

    def test_single_section(self):
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc123",
            previous_checkpoint_hash="",
            ledger_height=100,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def456",
            federation_quorum_certificate={},
        )
        generator = UnifiedProofGenerator()
        proof = generator.generate(["single section"], merkle_proof={}, checkpoint=checkpoint)
        assert proof.backend == ProofBackend.GROTH16
        assert proof.public_inputs.canonical_hash

    def test_halo2_backend_generator(self):
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc123",
            previous_checkpoint_hash="",
            ledger_height=100,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def456",
            federation_quorum_certificate={},
        )
        generator = UnifiedProofGenerator(backend=ProofBackend.HALO2)
        proof = generator.generate(["section"], merkle_proof={}, checkpoint=checkpoint)
        assert proof.backend == ProofBackend.HALO2


class TestVerifyZKProofRouting:
    """Test ZK proof routing."""

    def test_halo2_proof_routing(self):
        """Halo2 backend routing returns False when not available."""
        verifier = UnifiedProofVerifier()
        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="def",
            federation_quorum_certificate={},
        )
        proof = UnifiedProof(
            zk_proof={},
            public_inputs=public_inputs,
            checkpoint=checkpoint,
            backend=ProofBackend.HALO2,
        )
        result = verifier.verify(proof)
        assert result == VerificationResult.INVALID_ZK_PROOF

    def test_full_verification_chain_with_zk_pass(self):
        """When ZK and checkpoint pass but quorum fails, result is INVALID_QUORUM."""
        from unittest.mock import MagicMock

        mock_groth16 = MagicMock()
        mock_groth16.is_available.return_value = True
        mock_groth16.verify.return_value = True

        nodes = [
            FederationNode(
                node_id="node1",
                pubkey=b"x" * 32,
                endpoint="http://node1",
                operator="op",
                jurisdiction="US",
            )
        ]
        registry = FederationRegistry(nodes=nodes, epoch=1)

        verifier = UnifiedProofVerifier(
            registry=registry,
            groth16_backend=mock_groth16,
        )

        public_inputs = UnifiedPublicInputs(canonical_hash="1", merkle_root="2", ledger_root="3")
        checkpoint = SignedCheckpoint(
            sequence=1,
            timestamp="2026-03-12T18:00:00Z",
            ledger_head_hash="abc",
            previous_checkpoint_hash="",
            ledger_height=1,
            shard_roots={},
            consistency_proof=[],
            checkpoint_hash="valid-hash",
            federation_quorum_certificate={"signatures": []},
        )
        proof = UnifiedProof(
            zk_proof={"pi_a": []}, public_inputs=public_inputs, checkpoint=checkpoint
        )
        result = verifier.verify(proof)
        assert result == VerificationResult.INVALID_QUORUM
