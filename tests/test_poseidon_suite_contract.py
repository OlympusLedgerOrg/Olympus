"""
Tests that the poseidon-bn254-v1 suite contract is locked down per ADR-0009.

These tests are the machine-readable enforcement of ADR-0009.
If any of these fail, it means someone changed the hash suite parameters,
which would silently break proof verification for existing proof bundles.
"""

from __future__ import annotations

import importlib

import pytest


# ---------------------------------------------------------------------------
# Skip guard: skip the whole module when olympus_core is absent.
# HASH_SUITE_VERSION and POSEIDON_PARAMS are pure Python constants, but they
# live in protocol.poseidon which performs a top-level import from olympus_core.
# Build the extension with `maturin develop` to enable these tests locally.
# ---------------------------------------------------------------------------

try:
    importlib.import_module("olympus_core.poseidon")
    _RUST_AVAILABLE = True
except ModuleNotFoundError as exc:
    if exc.name not in {"olympus_core", "olympus_core.poseidon"}:
        raise
    _RUST_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _RUST_AVAILABLE,
    reason="olympus_core Rust extension not built — run `maturin develop` to enable",
)


class TestPoseidonSuiteContract:
    """Pin the poseidon-bn254-v1 parameters per ADR-0009."""

    def test_hash_suite_version_is_locked(self) -> None:
        """HASH_SUITE_VERSION must equal 'poseidon-bn254-v1'. Do not change."""
        from protocol.poseidon import HASH_SUITE_VERSION

        assert HASH_SUITE_VERSION == "poseidon-bn254-v1"

    def test_field_modulus_is_bn254(self) -> None:
        """Field modulus must be the BN254 scalar field prime."""
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["field_modulus"] == (
            21888242871839275222246405745257275088548364400416034343698204186575808495617
        )

    def test_arity_is_two(self) -> None:
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["arity"] == 2

    def test_width_is_three(self) -> None:
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["width"] == 3

    def test_full_rounds_is_eight(self) -> None:
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["n_rounds_f"] == 8

    def test_partial_rounds_is_57(self) -> None:
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["n_rounds_p"] == 57

    def test_sbox_exponent_is_five(self) -> None:
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["sbox_exponent"] == 5

    def test_domain_tag_leaf_is_zero(self) -> None:
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["domain_tag_leaf"] == 0

    def test_domain_tag_node_is_one(self) -> None:
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["domain_tag_node"] == 1

    def test_constants_source_is_circomlibjs(self) -> None:
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["constants_source"] == (
            "circomlibjs/src/poseidon_constants.json"
        )
