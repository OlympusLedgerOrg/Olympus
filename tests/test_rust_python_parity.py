"""
Cross-language parity tests: Rust olympus_core vs pure-Python implementations.

All tests in this module are skipped automatically when the Rust extension
(``olympus_core``) has not been built.  Build it with::

    maturin develop          # editable install into the current venv
    # or
    pip install -e .         # same effect via PEP 517

To run only these tests::

    pytest tests/test_rust_python_parity.py -v

To run the slow golden-vector test explicitly::

    pytest tests/test_rust_python_parity.py -v -m slow
"""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import blake3 as _blake3
import pytest

from protocol.canonical_json import (
    _encode_value,
    _normalize_for_canonical_json,
)
from protocol.hashes import _GLOBAL_SMT_KEY_CONTEXT


# ---------------------------------------------------------------------------
# Skip-guard: all tests in this module require the Rust extension.
# ---------------------------------------------------------------------------

try:
    import olympus_core.canonical as _rust_canonical
    import olympus_core.crypto as _rust_crypto

    _RUST_AVAILABLE = True
except ImportError:
    _RUST_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _RUST_AVAILABLE,
    reason="olympus_core Rust extension not built — run `maturin develop` to enable",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_KEY_PREFIX = b"OLY:KEY:V1"
_LEAF_PREFIX = b"OLY:LEAF:V1"
_NODE_PREFIX = b"OLY:NODE:V1"
_SEP = b"|"


def _py_blake3_hash(parts: list[bytes]) -> bytes:
    return _blake3.blake3(b"".join(parts)).digest()


def _py_record_key(record_type: str, record_id: str, version: int) -> bytes:
    def lp(data: bytes) -> bytes:
        return len(data).to_bytes(4, "big") + data

    key_data = b"".join(
        [
            _KEY_PREFIX,
            lp(record_type.encode("utf-8")),
            lp(record_id.encode("utf-8")),
            version.to_bytes(8, "big"),
        ]
    )
    return _blake3.blake3(key_data).digest()


def _py_global_key(shard_id: str, record_key_bytes: bytes) -> bytes:
    def lp(data: bytes) -> bytes:
        return len(data).to_bytes(4, "big") + data

    key_material = lp(shard_id.encode("utf-8")) + lp(record_key_bytes)
    return _blake3.blake3(
        key_material,
        derive_key_context=_GLOBAL_SMT_KEY_CONTEXT,
    ).digest()


def _py_leaf_hash(
    key: bytes,
    value_hash: bytes,
    parser_id: str,
    canonical_parser_version: str,
) -> bytes:
    pid = parser_id.encode("utf-8")
    cpv = canonical_parser_version.encode("utf-8")
    return _py_blake3_hash(
        [
            _LEAF_PREFIX,
            _SEP,
            key,
            _SEP,
            value_hash,
            _SEP,
            len(pid).to_bytes(4, "big") + pid,
            _SEP,
            len(cpv).to_bytes(4, "big") + cpv,
        ]
    )


def _py_node_hash(left: bytes, right: bytes) -> bytes:
    return _py_blake3_hash([_NODE_PREFIX, _SEP, left, _SEP, right])


def _py_canonical_json_encode(obj: object) -> str:
    return _encode_value(_normalize_for_canonical_json(obj))


# ---------------------------------------------------------------------------
# Phase 1A: crypto parity tests
# ---------------------------------------------------------------------------


class TestBlake3HashParity:
    def test_empty_list(self) -> None:
        assert _rust_crypto.blake3_hash([]) == _py_blake3_hash([])

    def test_single_part(self) -> None:
        data = b"hello world"
        assert _rust_crypto.blake3_hash([data]) == _py_blake3_hash([data])

    def test_multiple_parts(self) -> None:
        parts = [b"foo", b"bar", b"baz"]
        assert _rust_crypto.blake3_hash(parts) == _py_blake3_hash(parts)

    def test_empty_bytes_in_list(self) -> None:
        parts = [b"", b"x", b""]
        assert _rust_crypto.blake3_hash(parts) == _py_blake3_hash(parts)

    def test_binary_data(self) -> None:
        parts = [bytes(range(256))]
        assert _rust_crypto.blake3_hash(parts) == _py_blake3_hash(parts)

    def test_output_is_32_bytes(self) -> None:
        result = _rust_crypto.blake3_hash([b"test"])
        assert isinstance(result, bytes)
        assert len(result) == 32


class TestRecordKeyParity:
    def test_basic(self) -> None:
        assert _rust_crypto.record_key("doc", "id1", 1) == _py_record_key("doc", "id1", 1)

    def test_version_zero(self) -> None:
        assert _rust_crypto.record_key("t", "i", 0) == _py_record_key("t", "i", 0)

    def test_max_version(self) -> None:
        v = 0xFFFFFFFFFFFFFFFF
        assert _rust_crypto.record_key("t", "i", v) == _py_record_key("t", "i", v)

    def test_unicode_fields(self) -> None:
        assert _rust_crypto.record_key("doc\u00e9", "id\u4e2d", 5) == _py_record_key(
            "doc\u00e9", "id\u4e2d", 5
        )

    def test_output_is_32_bytes(self) -> None:
        result = _rust_crypto.record_key("doc", "id", 0)
        assert isinstance(result, bytes)
        assert len(result) == 32


class TestGlobalKeyParity:
    def test_basic(self) -> None:
        rk = _py_record_key("document", "doc123", 1)
        assert _rust_crypto.global_key("watauga:2025:budget", rk) == _py_global_key(
            "watauga:2025:budget", rk
        )

    def test_empty_shard(self) -> None:
        rk = bytes(32)
        assert _rust_crypto.global_key("", rk) == _py_global_key("", rk)

    def test_shard_with_separator_char(self) -> None:
        rk = bytes(32)
        # Shard IDs that contain | must not collide with other shards
        assert _rust_crypto.global_key("a|b", rk) == _py_global_key("a|b", rk)

    def test_output_is_32_bytes(self) -> None:
        result = _rust_crypto.global_key("s", bytes(32))
        assert isinstance(result, bytes)
        assert len(result) == 32


class TestLeafHashParity:
    def test_basic(self) -> None:
        key = bytes(range(32))
        value = bytes(range(32, 64))
        assert _rust_crypto.leaf_hash(key, value, "docling@2.3.1", "v1") == _py_leaf_hash(
            key, value, "docling@2.3.1", "v1"
        )

    def test_output_is_32_bytes(self) -> None:
        result = _rust_crypto.leaf_hash(bytes(32), bytes(32), "docling@2.3.1", "v1")
        assert isinstance(result, bytes)
        assert len(result) == 32


class TestNodeHashParity:
    def test_basic(self) -> None:
        left = bytes(range(32))
        right = bytes(range(32, 64))
        assert _rust_crypto.node_hash(left, right) == _py_node_hash(left, right)

    def test_asymmetric(self) -> None:
        a = bytes(32)
        b = bytes([1] * 32)
        assert _rust_crypto.node_hash(a, b) != _rust_crypto.node_hash(b, a)

    def test_output_is_32_bytes(self) -> None:
        result = _rust_crypto.node_hash(bytes(32), bytes(32))
        assert isinstance(result, bytes)
        assert len(result) == 32


# ---------------------------------------------------------------------------
# Phase 1B: canonical JSON parity tests
# ---------------------------------------------------------------------------


class TestCanonicalJsonParity:
    """Verify that the Rust canonical_json_encode output matches Python exactly."""

    def _assert_parity(self, obj: object) -> None:
        py_result = _py_canonical_json_encode(obj)
        rust_result = _rust_canonical.canonical_json_encode(obj)
        assert rust_result == py_result, (
            f"Mismatch for {obj!r}:\n  Python: {py_result!r}\n  Rust:   {rust_result!r}"
        )

    def test_null(self) -> None:
        self._assert_parity(None)

    def test_true(self) -> None:
        self._assert_parity(True)

    def test_false(self) -> None:
        self._assert_parity(False)

    def test_integer_zero(self) -> None:
        self._assert_parity(0)

    def test_integer_positive(self) -> None:
        self._assert_parity(42)

    def test_integer_negative(self) -> None:
        self._assert_parity(-7)

    def test_large_integer(self) -> None:
        self._assert_parity(10**30)

    def test_decimal_simple(self) -> None:
        self._assert_parity(Decimal("3.14"))

    def test_decimal_zero(self) -> None:
        self._assert_parity(Decimal("0"))

    def test_decimal_negative_zero(self) -> None:
        self._assert_parity(Decimal("-0"))

    def test_decimal_trailing_zeros_stripped(self) -> None:
        self._assert_parity(Decimal("1.10"))

    def test_decimal_scientific_large(self) -> None:
        self._assert_parity(Decimal("1.5e21"))

    def test_decimal_scientific_small(self) -> None:
        self._assert_parity(Decimal("1.5e-7"))

    def test_string_ascii(self) -> None:
        self._assert_parity("hello world")

    def test_string_non_ascii(self) -> None:
        # Non-ASCII characters are emitted as raw UTF-8 (JCS), not \uXXXX.
        result = _rust_canonical.canonical_json_encode("caf\u00e9")
        assert result == '"café"'
        self._assert_parity("caf\u00e9")

    def test_string_nfc_normalization(self) -> None:
        # e + combining acute = precomposed é; must NFC-normalize to U+00E9
        result = _rust_canonical.canonical_json_encode("e\u0301")
        assert result == '"é"'
        self._assert_parity("e\u0301")

    def test_string_emoji_raw_utf8(self) -> None:
        # U+1F600 GRINNING FACE — JCS emits raw UTF-8, not surrogate pairs.
        result = _rust_canonical.canonical_json_encode("\U0001f600")
        assert result == '"\U0001f600"'
        self._assert_parity("\U0001f600")

    def test_string_control_chars(self) -> None:
        self._assert_parity("a\nb\tc\rd")

    def test_empty_string(self) -> None:
        self._assert_parity("")

    def test_empty_list(self) -> None:
        self._assert_parity([])

    def test_list_of_integers(self) -> None:
        self._assert_parity([1, 2, 3])

    def test_nested_list(self) -> None:
        self._assert_parity([[1, [2]], [3]])

    def test_empty_dict(self) -> None:
        self._assert_parity({})

    def test_dict_sorted_keys(self) -> None:
        self._assert_parity({"z": 1, "a": 2, "m": 3})

    def test_nested_dict(self) -> None:
        self._assert_parity({"outer": {"inner": True}, "z": None})

    def test_mixed_types(self) -> None:
        obj = {
            "b": False,
            "d": Decimal("1.5"),
            "i": 99,
            "l": [1, None, True],
            "n": None,
            "s": "hi",
            "t": True,
        }
        self._assert_parity(obj)

    def test_float_rejected(self) -> None:
        with pytest.raises((ValueError, TypeError)):
            _rust_canonical.canonical_json_encode(3.14)

    def test_nan_rejected(self) -> None:
        with pytest.raises(ValueError):
            _rust_canonical.canonical_json_encode(float("nan"))

    def test_infinity_rejected(self) -> None:
        with pytest.raises(ValueError):
            _rust_canonical.canonical_json_encode(float("inf"))

    def test_decimal_nan_rejected(self) -> None:
        with pytest.raises(ValueError):
            _rust_canonical.canonical_json_encode(Decimal("nan"))

    def test_decimal_infinity_rejected(self) -> None:
        with pytest.raises(ValueError):
            _rust_canonical.canonical_json_encode(Decimal("inf"))


# ---------------------------------------------------------------------------
# Phase 1D: golden vector test (marked slow — run explicitly with -m slow)
# ---------------------------------------------------------------------------

_VECTORS_PATH = (
    Path(__file__).resolve().parent.parent
    / "verifiers"
    / "test_vectors"
    / "canonicalizer_vectors.tsv"
)


@pytest.mark.slow
def test_rust_canonical_golden_vectors() -> None:
    """
    Run every positive vector from canonicalizer_vectors.tsv through both the
    Rust and Python ``canonical_json_encode`` implementations and assert:

    1. Both produce byte-for-byte identical output (Rust ↔ Python parity).
    2. Both match the pre-computed ``canonical_hex`` column from the TSV
       (Rust/Python ↔ JCS reference parity).

    This is possible because the encoder now emits raw UTF-8 for non-ASCII
    characters (RFC 8785 / JCS), matching the golden vectors exactly.

    The file is streamed line-by-line to avoid loading it all into memory.
    """
    if not _VECTORS_PATH.exists():
        pytest.skip(f"Test vectors not found at {_VECTORS_PATH}")

    mismatches: list[str] = []
    total = 0

    with _VECTORS_PATH.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue

            parts = line.split("\t")
            if len(parts) != 4:
                continue

            group_id, input_hex, canonical_hex, _hash_hex = parts
            input_bytes = bytes.fromhex(input_hex)
            expected_bytes = bytes.fromhex(canonical_hex)

            # Parse the input JSON into a Python object
            try:
                obj = json.loads(input_bytes.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue  # skip malformed vectors

            # Python reference
            try:
                py_bytes = _py_canonical_json_encode(obj).encode("utf-8")
            except Exception:
                continue  # if Python rejects it, skip this vector

            # Rust
            try:
                rust_bytes = _rust_canonical.canonical_json_encode(obj).encode("utf-8")
            except Exception as exc:
                mismatches.append(f"Vector {group_id!r}: Rust raised {type(exc).__name__}: {exc}")
                total += 1
                continue

            # Both must match each other
            if rust_bytes != py_bytes:
                mismatches.append(
                    f"Vector {group_id!r} Rust≠Python:\n"
                    f"  python: {py_bytes!r}\n"
                    f"  rust:   {rust_bytes!r}"
                )
            # Both must match the golden TSV column
            if rust_bytes != expected_bytes:
                mismatches.append(
                    f"Vector {group_id!r} Rust≠golden:\n"
                    f"  expected: {expected_bytes!r}\n"
                    f"  rust got: {rust_bytes!r}"
                )
            total += 1

    assert total > 0, "No vectors were processed"
    assert not mismatches, f"{len(mismatches)}/{total} vector(s) failed:\n" + "\n".join(
        mismatches[:10]
    )
