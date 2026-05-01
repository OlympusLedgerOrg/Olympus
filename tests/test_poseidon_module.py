"""Tests for protocol.poseidon — Rust-backed Poseidon hash bindings.

All tests in this module are skipped automatically when ``olympus_core`` has
not been built, because ``protocol.poseidon`` performs a top-level import
from ``olympus_core.poseidon``.  Build the extension with::

    maturin develop          # editable install into the current venv
    # or
    pip install -e .         # same effect via PEP 517

``resolved_poseidon_root`` is a pure-Python helper inside the same module; its
tests are included here for completeness and are skipped alongside the rest
when the extension is absent.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Skip guard: skip the whole module when olympus_core is absent
# ---------------------------------------------------------------------------

try:
    import olympus_core.poseidon  # noqa: F401

    _RUST_AVAILABLE = True
except ImportError:
    _RUST_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _RUST_AVAILABLE,
    reason="olympus_core Rust extension not built — run `maturin develop` to enable",
)


# ---------------------------------------------------------------------------
# Pure-Python helpers (skipped when Rust extension is unavailable)
# ---------------------------------------------------------------------------


class TestResolvedPoseidonRoot:
    """protocol.poseidon.resolved_poseidon_root is pure Python; no Rust needed."""

    def test_returns_persisted_when_not_none(self) -> None:
        from protocol.poseidon import resolved_poseidon_root

        assert resolved_poseidon_root("persisted-value", "fallback") == "persisted-value"

    def test_returns_fallback_when_none(self) -> None:
        from protocol.poseidon import resolved_poseidon_root

        assert resolved_poseidon_root(None, "fallback-value") == "fallback-value"

    def test_returns_persisted_empty_string_not_fallback(self) -> None:
        from protocol.poseidon import resolved_poseidon_root

        # Empty string is a valid persisted value, not None
        assert resolved_poseidon_root("", "fallback") == ""

    def test_persisted_zero_string(self) -> None:
        from protocol.poseidon import resolved_poseidon_root

        assert resolved_poseidon_root("0", "fallback") == "0"


# ---------------------------------------------------------------------------
# Rust backend is active
# ---------------------------------------------------------------------------


class TestRustBackendIsActive:
    """Assert the Rust extension is genuinely loaded, not shadowed or bypassed."""

    def test_olympus_core_poseidon_in_sys_modules(self) -> None:
        import sys

        assert "olympus_core.poseidon" in sys.modules, (
            "olympus_core.poseidon not found in sys.modules — "
            "Rust extension is not loaded"
        )

    def test_internal_hash_fn_is_rust_object(self) -> None:
        import olympus_core.poseidon as _oc
        import protocol.poseidon as _proto

        assert _proto._poseidon_hash_bigint is _oc.poseidon_hash_bn254_bigint, (
            "protocol.poseidon._poseidon_hash_bigint is not the Rust function"
        )
        assert _proto._poseidon_leaf_hash is _oc.poseidon_leaf_hash_bn254
        assert _proto._poseidon_node_hash is _oc.poseidon_node_hash_bn254

    def test_rust_fn_module_attribute(self) -> None:
        import protocol.poseidon as _proto

        # PyO3-exported functions carry __module__ == the Rust crate's module path.
        assert "olympus_core" in (_proto._poseidon_hash_bigint.__module__ or ""), (
            f"Expected __module__ to contain 'olympus_core', "
            f"got {_proto._poseidon_hash_bigint.__module__!r}"
        )


# ---------------------------------------------------------------------------
# Rust-backed Poseidon hash tests
# ---------------------------------------------------------------------------



class TestSnarkScalarField:
    def test_field_is_positive_integer(self) -> None:
        from protocol.poseidon import SNARK_SCALAR_FIELD

        assert isinstance(SNARK_SCALAR_FIELD, int)
        assert SNARK_SCALAR_FIELD > 0

    def test_field_matches_bn254_prime(self) -> None:
        """BN254 scalar field prime is a known constant."""
        from protocol.poseidon import SNARK_SCALAR_FIELD

        # BN254 / BN128 scalar field prime
        expected = 21888242871839275222246405745257275088548364400416034343698204186575808495617
        assert SNARK_SCALAR_FIELD == expected



class TestPoseidonHash:
    def test_basic(self) -> None:
        from protocol.poseidon import poseidon_hash

        result = poseidon_hash(1, 2)
        assert isinstance(result, int)
        assert result > 0

    def test_deterministic(self) -> None:
        from protocol.poseidon import poseidon_hash

        assert poseidon_hash(5, 10) == poseidon_hash(5, 10)

    def test_not_commutative(self) -> None:
        """Poseidon is not commutative: H(a, b) ≠ H(b, a) in general."""
        from protocol.poseidon import poseidon_hash

        assert poseidon_hash(1, 2) != poseidon_hash(2, 1)

    def test_zero_inputs(self) -> None:
        from protocol.poseidon import poseidon_hash

        result = poseidon_hash(0, 0)
        assert isinstance(result, int)
        assert result >= 0

    def test_result_within_scalar_field(self) -> None:
        from protocol.poseidon import SNARK_SCALAR_FIELD, poseidon_hash

        result = poseidon_hash(12345, 67890)
        assert 0 <= result < SNARK_SCALAR_FIELD

    def test_bn128_alias_matches(self) -> None:
        from protocol.poseidon import poseidon_hash, poseidon_hash_bn128

        assert poseidon_hash(7, 13) == poseidon_hash_bn128(7, 13)

    def test_large_field_elements(self) -> None:
        from protocol.poseidon import SNARK_SCALAR_FIELD, poseidon_hash

        a = SNARK_SCALAR_FIELD - 1
        b = SNARK_SCALAR_FIELD - 2
        result = poseidon_hash(a, b)
        assert 0 <= result < SNARK_SCALAR_FIELD



class TestPoseidonLeafHash:
    def test_basic(self) -> None:
        from protocol.poseidon import poseidon_leaf_hash

        result = poseidon_leaf_hash(1, 2)
        assert isinstance(result, int)
        assert result > 0

    def test_deterministic(self) -> None:
        from protocol.poseidon import poseidon_leaf_hash

        assert poseidon_leaf_hash(100, 200) == poseidon_leaf_hash(100, 200)

    def test_differs_from_plain_hash(self) -> None:
        """Domain-separated leaf hash must differ from plain poseidon_hash."""
        from protocol.poseidon import poseidon_hash, poseidon_leaf_hash

        a, b = 42, 99
        assert poseidon_leaf_hash(a, b) != poseidon_hash(a, b)

    def test_result_within_scalar_field(self) -> None:
        from protocol.poseidon import SNARK_SCALAR_FIELD, poseidon_leaf_hash

        result = poseidon_leaf_hash(1, 1)
        assert 0 <= result < SNARK_SCALAR_FIELD



class TestPoseidonNodeHash:
    def test_basic(self) -> None:
        from protocol.poseidon import poseidon_node_hash

        result = poseidon_node_hash(1, 2)
        assert isinstance(result, int)
        assert result > 0

    def test_deterministic(self) -> None:
        from protocol.poseidon import poseidon_node_hash

        assert poseidon_node_hash(7, 8) == poseidon_node_hash(7, 8)

    def test_not_commutative(self) -> None:
        from protocol.poseidon import poseidon_node_hash

        assert poseidon_node_hash(1, 2) != poseidon_node_hash(2, 1)

    def test_differs_from_leaf_hash(self) -> None:
        """Domain-separated node hash must differ from leaf hash."""
        from protocol.poseidon import poseidon_leaf_hash, poseidon_node_hash

        a, b = 42, 99
        assert poseidon_node_hash(a, b) != poseidon_leaf_hash(a, b)

    def test_result_within_scalar_field(self) -> None:
        from protocol.poseidon import SNARK_SCALAR_FIELD, poseidon_node_hash

        result = poseidon_node_hash(0, 0)
        assert 0 <= result < SNARK_SCALAR_FIELD



class TestValueHashToField:
    def test_basic_32_bytes(self) -> None:
        from protocol.poseidon import value_hash_to_field

        data = bytes(range(32))
        result = value_hash_to_field(data)
        assert isinstance(result, int)
        assert result >= 0

    def test_result_within_scalar_field(self) -> None:
        from protocol.poseidon import SNARK_SCALAR_FIELD, value_hash_to_field

        data = bytes([0xFF] * 32)
        result = value_hash_to_field(data)
        assert result < SNARK_SCALAR_FIELD

    def test_deterministic(self) -> None:
        from protocol.poseidon import value_hash_to_field

        data = bytes(range(32))
        assert value_hash_to_field(data) == value_hash_to_field(data)

    def test_different_inputs_different_outputs(self) -> None:
        from protocol.poseidon import value_hash_to_field

        a = bytes(range(32))
        b = bytes([0] * 31 + [1])
        assert value_hash_to_field(a) != value_hash_to_field(b)

    def test_rejects_wrong_length(self) -> None:
        from protocol.poseidon import value_hash_to_field

        with pytest.raises(ValueError, match="32 bytes"):
            value_hash_to_field(bytes(16))

        with pytest.raises(ValueError, match="32 bytes"):
            value_hash_to_field(bytes(33))

    def test_alias_matches(self) -> None:
        from protocol.poseidon import value_hash_to_field, value_hash_to_poseidon_field

        data = bytes(range(32))
        assert value_hash_to_field(data) == value_hash_to_poseidon_field(data)
