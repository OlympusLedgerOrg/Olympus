"""
Tests for the proof system interface (protocol boundary).

This module tests:
- ProofBackendProtocol contract
- Statement, Witness, and Proof data structures
- Groth16Backend implementation
- Halo2Backend implementation (placeholder)
- Interface contract enforcement
"""

import pytest

from protocol.groth16_backend import Groth16Backend
from protocol.halo2_backend import Halo2Backend, is_halo2_available
from protocol.proof_interface import (
    BackendNotAvailableError,
    Proof,
    ProofBackendProtocol,
    ProofGenerationError,
    ProofSystemType,
    ProofVerificationError,
    Statement,
    Witness,
)


class TestStatement:
    """Test Statement data structure."""

    def test_statement_creation(self):
        """Test creating a Statement."""
        stmt = Statement(
            circuit="document_existence",
            public_inputs={"root": "123", "leaf": "456"},
        )

        assert stmt.circuit == "document_existence"
        assert stmt.public_inputs["root"] == "123"
        assert stmt.version == "1.0.0"

    def test_statement_to_list_is_sorted(self):
        """Test public inputs are converted to sorted list."""
        stmt = Statement(
            circuit="test",
            public_inputs={"zebra": "3", "apple": "1", "banana": "2"},
        )

        result = stmt.to_list()
        # Keys sorted: apple, banana, zebra -> values: 1, 2, 3
        assert result == ["1", "2", "3"]

    def test_statement_serialization(self):
        """Test Statement serialization roundtrip."""
        original = Statement(
            circuit="document_existence",
            public_inputs={"root": "123", "leaf": "456"},
            version="2.0.0",
        )

        data = original.to_dict()
        restored = Statement.from_dict(data)

        assert restored.circuit == original.circuit
        assert restored.public_inputs == original.public_inputs
        assert restored.version == original.version

    def test_statement_immutable(self):
        """Test that Statement is immutable (frozen dataclass)."""
        stmt = Statement(circuit="test", public_inputs={"a": "1"})

        with pytest.raises(AttributeError):
            stmt.circuit = "modified"


class TestWitness:
    """Test Witness data structure."""

    def test_witness_creation(self):
        """Test creating a Witness."""
        witness = Witness(
            private_inputs={"secret": "hidden_value"},
            auxiliary={"path": "/tmp/witness.json"},
        )

        assert witness.private_inputs["secret"] == "hidden_value"
        assert witness.auxiliary["path"] == "/tmp/witness.json"

    def test_witness_default_auxiliary(self):
        """Test Witness has empty auxiliary by default."""
        witness = Witness(private_inputs={"a": "1"})
        assert witness.auxiliary == {}

    def test_witness_serialization(self):
        """Test Witness serialization roundtrip."""
        original = Witness(
            private_inputs={"secret": "123"},
            auxiliary={"path": "/tmp"},
        )

        data = original.to_dict()
        restored = Witness.from_dict(data)

        assert restored.private_inputs == original.private_inputs
        assert restored.auxiliary == original.auxiliary


class TestProof:
    """Test Proof data structure."""

    def test_proof_creation_with_dict_data(self):
        """Test creating a Proof with dict proof data."""
        proof = Proof(
            proof_data={"pi_a": [1, 2], "pi_b": [[1, 2], [3, 4]], "pi_c": [5, 6]},
            proof_system=ProofSystemType.GROTH16,
            circuit="document_existence",
            public_signals=["123", "456"],
        )

        assert proof.proof_system == ProofSystemType.GROTH16
        assert proof.circuit == "document_existence"
        assert len(proof.public_signals) == 2

    def test_proof_creation_with_bytes_data(self):
        """Test creating a Proof with bytes proof data (Halo2)."""
        proof = Proof(
            proof_data=b"\x00\x01\x02\x03",
            proof_system=ProofSystemType.HALO2,
            circuit="unified",
            public_signals=["1", "2"],
        )

        assert proof.proof_system == ProofSystemType.HALO2
        assert isinstance(proof.proof_data, bytes)

    def test_proof_serialization_groth16(self):
        """Test Proof serialization for Groth16."""
        original = Proof(
            proof_data={"pi_a": [1, 2]},
            proof_system=ProofSystemType.GROTH16,
            circuit="test",
            public_signals=["100"],
            metadata={"prover": "snarkjs"},
        )

        data = original.to_dict()
        restored = Proof.from_dict(data)

        assert restored.proof_system == original.proof_system
        assert restored.circuit == original.circuit
        assert restored.public_signals == original.public_signals

    def test_proof_serialization_halo2_bytes(self):
        """Test Proof serialization for Halo2 (bytes data)."""
        original = Proof(
            proof_data=b"\xde\xad\xbe\xef",
            proof_system=ProofSystemType.HALO2,
            circuit="test",
            public_signals=["1"],
        )

        data = original.to_dict()
        # Bytes should be hex-encoded
        assert data["proof_data"] == "deadbeef"

        restored = Proof.from_dict(data)
        assert restored.proof_data == b"\xde\xad\xbe\xef"


class TestProofSystemType:
    """Test ProofSystemType enum."""

    def test_groth16_type(self):
        """Test Groth16 type value."""
        assert ProofSystemType.GROTH16.value == "groth16"

    def test_halo2_type(self):
        """Test Halo2 type value."""
        assert ProofSystemType.HALO2.value == "halo2"

    def test_reserved_types(self):
        """Test reserved proof system types exist."""
        assert ProofSystemType.PLONKY2.value == "plonky2"
        assert ProofSystemType.STARK.value == "stark"


class TestGroth16Backend:
    """Test Groth16Backend implementation."""

    def test_backend_creation(self):
        """Test creating Groth16Backend."""
        backend = Groth16Backend()
        assert backend.proof_system_type == ProofSystemType.GROTH16

    def test_backend_implements_protocol(self):
        """Test that Groth16Backend implements ProofBackendProtocol."""
        backend = Groth16Backend()
        assert isinstance(backend, ProofBackendProtocol)

    def test_is_available_checks_snarkjs(self):
        """Test is_available checks for snarkjs."""
        backend = Groth16Backend()
        # Result depends on whether snarkjs is installed
        result = backend.is_available()
        assert isinstance(result, bool)

    def test_verify_rejects_wrong_proof_system(self):
        """Test verify rejects proofs from wrong backend."""
        backend = Groth16Backend()

        statement = Statement(circuit="test", public_inputs={"a": "1"})
        proof = Proof(
            proof_data=b"halo2_proof",
            proof_system=ProofSystemType.HALO2,  # Wrong type
            circuit="test",
        )

        # Should raise or return False due to wrong proof type
        # Behavior depends on whether snarkjs is available
        if backend.is_available():
            with pytest.raises(ProofVerificationError) as exc_info:
                backend.verify(statement, proof)
            assert "Expected Groth16" in str(exc_info.value)

    def test_generate_requires_snarkjs(self):
        """Test generate raises if snarkjs unavailable."""
        backend = Groth16Backend(snarkjs_bin="nonexistent_binary")

        statement = Statement(circuit="test", public_inputs={})
        witness = Witness(private_inputs={})

        with pytest.raises(BackendNotAvailableError):
            backend.generate(statement, witness)


class TestHalo2Backend:
    """Test Halo2Backend implementation."""

    def test_backend_creation(self):
        """Test creating Halo2Backend."""
        backend = Halo2Backend()
        assert backend.proof_system_type == ProofSystemType.HALO2

    def test_backend_implements_protocol(self):
        """Test that Halo2Backend implements ProofBackendProtocol."""
        backend = Halo2Backend()
        assert isinstance(backend, ProofBackendProtocol)

    def test_is_available_returns_false(self):
        """Test is_available returns False (not implemented)."""
        backend = Halo2Backend()
        assert backend.is_available() is False

    def test_generate_raises_not_available(self):
        """Test generate raises BackendNotAvailableError."""
        backend = Halo2Backend()

        statement = Statement(circuit="test", public_inputs={})
        witness = Witness(private_inputs={})

        with pytest.raises(BackendNotAvailableError) as exc_info:
            backend.generate(statement, witness)

        assert "Phase 1+" in str(exc_info.value)

    def test_verify_raises_not_available(self):
        """Test verify raises BackendNotAvailableError."""
        backend = Halo2Backend()

        statement = Statement(circuit="test", public_inputs={})
        proof = Proof(
            proof_data=b"dummy",
            proof_system=ProofSystemType.HALO2,
            circuit="test",
        )

        with pytest.raises(BackendNotAvailableError) as exc_info:
            backend.verify(statement, proof)

        assert "Phase 1+" in str(exc_info.value)


class TestIsHalo2Available:
    """Test is_halo2_available utility."""

    def test_returns_false(self):
        """Test is_halo2_available returns False in v1.0."""
        assert is_halo2_available() is False


class TestProofBackendProtocol:
    """Test ProofBackendProtocol contract."""

    def test_protocol_is_runtime_checkable(self):
        """Test that protocol is runtime checkable."""

        class ValidBackend:
            def generate(self, statement: Statement, witness: Witness) -> Proof:
                pass

            def verify(self, statement: Statement, proof: Proof) -> bool:
                return True

            @property
            def proof_system_type(self) -> ProofSystemType:
                return ProofSystemType.GROTH16

            def is_available(self) -> bool:
                return True

        backend = ValidBackend()
        assert isinstance(backend, ProofBackendProtocol)

    def test_groth16_backend_is_protocol_instance(self):
        """Test Groth16Backend is recognized as protocol instance."""
        backend = Groth16Backend()
        assert isinstance(backend, ProofBackendProtocol)

    def test_halo2_backend_is_protocol_instance(self):
        """Test Halo2Backend is recognized as protocol instance."""
        backend = Halo2Backend()
        assert isinstance(backend, ProofBackendProtocol)


class TestExceptions:
    """Test proof backend exceptions."""

    def test_backend_not_available_error(self):
        """Test BackendNotAvailableError."""
        with pytest.raises(BackendNotAvailableError):
            raise BackendNotAvailableError("Test error")

    def test_proof_generation_error(self):
        """Test ProofGenerationError."""
        with pytest.raises(ProofGenerationError):
            raise ProofGenerationError("Generation failed")

    def test_proof_verification_error(self):
        """Test ProofVerificationError."""
        with pytest.raises(ProofVerificationError):
            raise ProofVerificationError("Verification failed")


class TestBackendSwappability:
    """Test that backends are swappable via the protocol interface."""

    def test_backends_have_same_interface(self):
        """Test Groth16 and Halo2 backends have identical interface."""
        groth16 = Groth16Backend()
        halo2 = Halo2Backend()

        # Both should have the same methods
        assert hasattr(groth16, "generate")
        assert hasattr(groth16, "verify")
        assert hasattr(groth16, "proof_system_type")
        assert hasattr(groth16, "is_available")

        assert hasattr(halo2, "generate")
        assert hasattr(halo2, "verify")
        assert hasattr(halo2, "proof_system_type")
        assert hasattr(halo2, "is_available")

    def test_function_accepting_protocol(self):
        """Test function can accept any ProofBackendProtocol."""

        def verify_with_backend(
            backend: ProofBackendProtocol,
            statement: Statement,
            proof: Proof,
        ) -> bool | None:
            """Verify using any backend."""
            if not backend.is_available():
                return None
            try:
                return backend.verify(statement, proof)
            except (ProofVerificationError, ProofGenerationError):
                # Expected if circuit doesn't exist
                return None

        # Both backends should work with the function
        groth16 = Groth16Backend()
        halo2 = Halo2Backend()

        statement = Statement(circuit="test", public_inputs={})
        proof = Proof(
            proof_data={},
            proof_system=ProofSystemType.GROTH16,
            circuit="test",
        )

        # Halo2 returns None (not available)
        result = verify_with_backend(halo2, statement, proof)
        assert result is None

        # Groth16 may return None or bool depending on snarkjs availability
        # and circuit existence
        result = verify_with_backend(groth16, statement, proof)
        # Just verify it doesn't raise unexpected errors
        assert result is None or isinstance(result, bool)
