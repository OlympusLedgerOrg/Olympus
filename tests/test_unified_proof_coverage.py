"""Targeted coverage tests for protocol/unified_proof.py — error/rejection paths.

Covers:
- get_backend unknown type (line 239)
- verify() — INVALID_CHECKPOINT path (line 264)
- verify() — VALID path with no registry (line 272)
- _verify_zk_proof unknown backend → False (line 291)
- _verify_groth16 legacy — vkey missing / error paths (lines 356-392)
- _verify_halo2 stub → False (line 409)
- _verify_checkpoint_structure exception → False (lines 436-437)
- _verify_quorum_certificate exception → False (lines 453-454)
"""

from unittest.mock import MagicMock, patch

import pytest

from protocol.checkpoints import SignedCheckpoint
from protocol.unified_proof import (
    ProofBackend,
    UnifiedProof,
    UnifiedProofVerifier,
    UnifiedPublicInputs,
    VerificationResult,
)


def _make_checkpoint(**overrides) -> SignedCheckpoint:
    defaults = dict(
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
    defaults.update(overrides)
    return SignedCheckpoint(**defaults)


def _make_proof(backend: ProofBackend = ProofBackend.GROTH16, **cp_overrides) -> UnifiedProof:
    return UnifiedProof(
        zk_proof={"pi_a": [], "pi_b": [], "pi_c": []},
        public_inputs=UnifiedPublicInputs(
            canonical_hash="1",
            merkle_root="2",
            ledger_root="3",
        ),
        checkpoint=_make_checkpoint(**cp_overrides),
        backend=backend,
    )


# ---------------------------------------------------------------------------
# get_backend — unknown type (line 239)
# ---------------------------------------------------------------------------


class TestGetBackend:
    def test_unknown_backend_raises(self):
        """get_backend raises ValueError for unknown backend types."""
        verifier = UnifiedProofVerifier()
        with pytest.raises(ValueError, match="Unknown backend"):
            verifier.get_backend("not_a_backend")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# verify() — branches (lines 264, 272)
# ---------------------------------------------------------------------------


class TestVerifyBranches:
    def test_invalid_checkpoint_path(self):
        """verify returns INVALID_CHECKPOINT when checkpoint check fails."""
        verifier = UnifiedProofVerifier()
        proof = _make_proof(checkpoint_hash="")

        # Mock _verify_zk_proof to pass so we reach checkpoint check
        with patch.object(verifier, "_verify_zk_proof", return_value=True):
            result = verifier.verify(proof)
        assert result == VerificationResult.INVALID_CHECKPOINT

    def test_valid_without_registry(self):
        """verify returns VALID when ZK + checkpoint pass and no registry set."""
        verifier = UnifiedProofVerifier()
        assert verifier.registry is None  # default: no registry
        proof = _make_proof()

        with (
            patch.object(verifier, "_verify_zk_proof", return_value=True),
            patch.object(verifier, "_verify_checkpoint_structure", return_value=True),
        ):
            result = verifier.verify(proof)
        assert result == VerificationResult.VALID


# ---------------------------------------------------------------------------
# _verify_zk_proof — unknown backend returns False (line 291)
# ---------------------------------------------------------------------------


class TestVerifyZkProof:
    def test_unknown_backend_returns_false(self):
        """_verify_zk_proof returns False for unknown proof backend."""
        verifier = UnifiedProofVerifier()
        proof = _make_proof()
        # Force an invalid backend enum value
        proof.backend = "BOGUS"  # type: ignore[assignment]
        assert verifier._verify_zk_proof(proof) is False


# ---------------------------------------------------------------------------
# _verify_groth16 legacy (lines 356-392)
# ---------------------------------------------------------------------------


class TestVerifyGroth16Legacy:
    def test_groth16_no_vkey_file(self, tmp_path):
        """_verify_groth16 returns False when verification key doesn't exist."""
        verifier = UnifiedProofVerifier(circuits_dir=tmp_path / "circuits")
        proof = _make_proof()
        assert verifier._verify_groth16(proof) is False

    def test_groth16_vkey_in_keys_dir(self, tmp_path):
        """_verify_groth16 tries keys/verification_keys/ first."""
        keys_dir = tmp_path / "keys" / "verification_keys"
        keys_dir.mkdir(parents=True)
        vkey_path = keys_dir / "unified_canonicalization_inclusion_root_sign_vkey.json"
        vkey_path.write_text("{}")

        # circuits_dir.parent = tmp_path, so keys_dir should be found
        verifier = UnifiedProofVerifier(circuits_dir=tmp_path / "circuits")
        # Even with a valid key path, verification will fail due to bad proof data
        assert verifier._verify_groth16(proof=_make_proof()) is False

    def test_groth16_vkey_in_build_dir(self, tmp_path):
        """_verify_groth16 falls back to build/ directory."""
        build_dir = tmp_path / "build"
        build_dir.mkdir(parents=True)
        vkey_path = build_dir / "unified_canonicalization_inclusion_root_sign_vkey.json"
        vkey_path.write_text("{}")

        verifier = UnifiedProofVerifier(circuits_dir=tmp_path / "circuits")
        assert verifier._verify_groth16(proof=_make_proof()) is False

    def test_groth16_value_error_returns_false(self):
        """_verify_groth16 catches ValueError and returns False."""
        verifier = UnifiedProofVerifier()
        bad_proof = _make_proof()
        bad_proof.zk_proof = None  # type: ignore[assignment]
        assert verifier._verify_groth16(bad_proof) is False


# ---------------------------------------------------------------------------
# _verify_halo2 stub (line 409)
# ---------------------------------------------------------------------------


class TestVerifyHalo2:
    def test_halo2_returns_false(self):
        """_verify_halo2 always returns False (not yet implemented)."""
        verifier = UnifiedProofVerifier()
        assert verifier._verify_halo2(_make_proof(backend=ProofBackend.HALO2)) is False


# ---------------------------------------------------------------------------
# _verify_checkpoint_structure — exception path (lines 436-437)
# ---------------------------------------------------------------------------


class TestVerifyCheckpointStructure:
    def test_exception_returns_false(self):
        """Checkpoint structure check returns False on AttributeError."""
        verifier = UnifiedProofVerifier()
        proof = _make_proof()
        # Replace checkpoint with something that raises AttributeError
        proof.checkpoint = None  # type: ignore[assignment]
        assert verifier._verify_checkpoint_structure(proof) is False


# ---------------------------------------------------------------------------
# _verify_quorum_certificate — exception path (lines 453-454)
# ---------------------------------------------------------------------------


class TestVerifyQuorumCertificate:
    def test_exception_returns_false(self):
        """Quorum certificate check returns False on exception."""
        mock_registry = MagicMock()
        verifier = UnifiedProofVerifier(registry=mock_registry)

        # Make verify_checkpoint_quorum_certificate raise
        with patch(
            "protocol.unified_proof.verify_checkpoint_quorum_certificate",
            side_effect=AttributeError("boom"),
        ):
            result = verifier._verify_quorum_certificate(_make_proof())
        assert result is False

    def test_no_registry_returns_true(self):
        """No registry set → skip quorum check → True."""
        verifier = UnifiedProofVerifier(registry=None)
        assert verifier._verify_quorum_certificate(_make_proof()) is True
