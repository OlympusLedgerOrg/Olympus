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
# Skip guard for Rust-dependent tests.
# HASH_SUITE_VERSION and POSEIDON_PARAMS live in protocol.poseidon which
# performs a top-level import from olympus_core.  Tests in TestPoseidonSuiteContract
# are gated on this flag.  Tests in TestAttachPoseidonHashSuite are pure Python
# (api.ingest only) and run in every environment.
# ---------------------------------------------------------------------------

try:
    importlib.import_module("olympus_core.poseidon")
    _RUST_AVAILABLE = True
except ModuleNotFoundError as exc:
    if exc.name not in {"olympus_core", "olympus_core.poseidon"}:
        raise
    _RUST_AVAILABLE = False

_skip_without_rust = pytest.mark.skipif(
    not _RUST_AVAILABLE,
    reason="olympus_core Rust extension not built — run `maturin develop` to enable",
)


@_skip_without_rust
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
        """Arity must equal 2 (two inputs per hash call) per ADR-0009. Do not change."""
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["arity"] == 2

    def test_width_is_three(self) -> None:
        """Width must equal 3 (t=3: capacity=1, rate=2) per ADR-0009. Do not change."""
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["width"] == 3

    def test_full_rounds_is_eight(self) -> None:
        """Full rounds must equal 8 (4 before + 4 after partial) per ADR-0009. Do not change."""
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["n_rounds_f"] == 8

    def test_partial_rounds_is_57(self) -> None:
        """Partial rounds must equal 57 per ADR-0009. Do not change."""
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["n_rounds_p"] == 57

    def test_sbox_exponent_is_five(self) -> None:
        """S-box exponent must equal 5 (x^5 mod p) per ADR-0009. Do not change."""
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["sbox_exponent"] == 5

    def test_domain_tag_leaf_is_zero(self) -> None:
        """Domain tag for Merkle leaf hashes must equal 0 per ADR-0009. Do not change."""
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["domain_tag_leaf"] == 0

    def test_domain_tag_node_is_one(self) -> None:
        """Domain tag for Merkle internal node hashes must equal 1 per ADR-0009. Do not change."""
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["domain_tag_node"] == 1

    def test_constants_source_is_circomlibjs(self) -> None:
        """Round constants source must match the circomlibjs path per ADR-0009. Do not change."""
        from protocol.poseidon import POSEIDON_PARAMS

        assert POSEIDON_PARAMS["constants_source"] == (
            "circomlibjs/src/poseidon_constants.json"
        )

    def test_poseidon_params_uses_snark_scalar_field(self) -> None:
        """POSEIDON_PARAMS['field_modulus'] must equal SNARK_SCALAR_FIELD (no duplicate literal)."""
        from protocol.poseidon import POSEIDON_PARAMS, SNARK_SCALAR_FIELD

        assert POSEIDON_PARAMS["field_modulus"] == SNARK_SCALAR_FIELD

    def test_poseidon_params_uses_domain_constants(self) -> None:
        """Domain tags in POSEIDON_PARAMS must equal POSEIDON_DOMAIN_LEAF/NODE (no drift)."""
        from protocol.poseidon import (
            POSEIDON_DOMAIN_LEAF,
            POSEIDON_DOMAIN_NODE,
            POSEIDON_PARAMS,
        )

        assert POSEIDON_PARAMS["domain_tag_leaf"] == POSEIDON_DOMAIN_LEAF
        assert POSEIDON_PARAMS["domain_tag_node"] == POSEIDON_DOMAIN_NODE

    def test_poseidon_params_is_immutable(self) -> None:
        """POSEIDON_PARAMS must be immutable (MappingProxyType) per ADR-0009."""
        from types import MappingProxyType

        from protocol.poseidon import POSEIDON_PARAMS

        assert isinstance(POSEIDON_PARAMS, MappingProxyType), (
            "POSEIDON_PARAMS must be a MappingProxyType, not a plain dict"
        )
        with pytest.raises(TypeError):
            POSEIDON_PARAMS["n_rounds_f"] = 99  # type: ignore[index]


# ---------------------------------------------------------------------------
# These tests do NOT require the Rust extension — the helper lives in api.ingest
# which is pure Python.  They run in every environment.
# ---------------------------------------------------------------------------


class TestAttachPoseidonHashSuite:
    """Central helper _attach_poseidon_hash_suite enforces ADR-0009 invariant."""

    def test_attaches_when_poseidon_root_present(self) -> None:
        """hash_suite is added when poseidon_root is a non-None value."""
        from api.ingest import _HASH_SUITE_VERSION, _attach_poseidon_hash_suite

        bundle: dict = {"poseidon_root": "1234abcd", "content_hash": "aabbcc"}
        _attach_poseidon_hash_suite(bundle)
        assert bundle["hash_suite"] == _HASH_SUITE_VERSION

    def test_does_not_attach_when_poseidon_root_absent(self) -> None:
        """hash_suite is not added when poseidon_root is not in the bundle."""
        from api.ingest import _attach_poseidon_hash_suite

        bundle: dict = {"content_hash": "aabbcc"}
        _attach_poseidon_hash_suite(bundle)
        assert "hash_suite" not in bundle

    def test_does_not_attach_when_poseidon_root_is_none(self) -> None:
        """hash_suite is not added when poseidon_root is explicitly None."""
        from api.ingest import _attach_poseidon_hash_suite

        bundle: dict = {"poseidon_root": None, "content_hash": "aabbcc"}
        _attach_poseidon_hash_suite(bundle)
        assert "hash_suite" not in bundle

    def test_does_not_overwrite_existing_hash_suite(self) -> None:
        """setdefault semantics: an already-set hash_suite is not overwritten."""
        from api.ingest import _attach_poseidon_hash_suite

        bundle: dict = {"poseidon_root": "abc", "hash_suite": "future-suite"}
        _attach_poseidon_hash_suite(bundle)
        assert bundle["hash_suite"] == "future-suite"

    def test_returns_same_dict(self) -> None:
        """Helper returns the bundle dict for convenience chaining."""
        from api.ingest import _attach_poseidon_hash_suite

        bundle: dict = {"poseidon_root": "abc"}
        result = _attach_poseidon_hash_suite(bundle)
        assert result is bundle

    def test_hash_suite_version_matches_adr_constant(self) -> None:
        """_HASH_SUITE_VERSION in api.ingest must equal the ADR-0009 value."""
        from api.ingest import _HASH_SUITE_VERSION

        assert _HASH_SUITE_VERSION == "poseidon-bn254-v1"
