"""
Unit tests for the RFC 3161 trusted timestamping module.

Network calls to the TSA are mocked so that these tests run fully offline.
"""

import hashlib
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from protocol.rfc3161 import (
    DEFAULT_TSA_URL,
    TimestampToken,
    _sha256_of_hash,
    build_timestamp_request,
    request_timestamp,
    verify_timestamp_token,
)


# ---------------------------------------------------------------------------
# _sha256_of_hash
# ---------------------------------------------------------------------------


def test_sha256_of_hash_returns_32_bytes():
    hash_hex = "a" * 64  # 32-byte hex-encoded hash
    result = _sha256_of_hash(hash_hex)
    assert isinstance(result, bytes)
    assert len(result) == 32


def test_sha256_of_hash_deterministic():
    hash_hex = "deadbeef" * 8
    assert _sha256_of_hash(hash_hex) == _sha256_of_hash(hash_hex)


def test_sha256_of_hash_matches_manual_computation():
    hash_hex = "deadbeef" * 8
    expected = hashlib.sha256(bytes.fromhex(hash_hex)).digest()
    assert _sha256_of_hash(hash_hex) == expected


def test_sha256_of_hash_rejects_invalid_hex():
    with pytest.raises(ValueError, match="Invalid hash_hex"):
        _sha256_of_hash("not-valid-hex!")


def test_sha256_of_hash_rejects_odd_length():
    with pytest.raises(ValueError, match="Invalid hash_hex"):
        _sha256_of_hash("abc")  # odd-length hex string


# ---------------------------------------------------------------------------
# build_timestamp_request
# ---------------------------------------------------------------------------


def test_build_timestamp_request_returns_der_bytes():
    hash_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    der = build_timestamp_request(hash_hex)
    assert isinstance(der, bytes)
    assert len(der) > 0


def test_build_timestamp_request_starts_with_sequence_tag():
    """DER-encoded SEQUENCE starts with byte 0x30."""
    hash_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    der = build_timestamp_request(hash_hex)
    assert der[0] == 0x30


def test_build_timestamp_request_deterministic_for_same_hash():
    hash_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert build_timestamp_request(hash_hex) == build_timestamp_request(hash_hex)


def test_build_timestamp_request_different_hashes_differ():
    hex1 = "a" * 64
    hex2 = "b" * 64
    assert build_timestamp_request(hex1) != build_timestamp_request(hex2)


def test_build_timestamp_request_rejects_invalid_hex():
    with pytest.raises(ValueError, match="Invalid hash_hex"):
        build_timestamp_request("not-hex!")


# ---------------------------------------------------------------------------
# TimestampToken dataclass
# ---------------------------------------------------------------------------


def _make_token() -> TimestampToken:
    return TimestampToken(
        hash_hex="deadbeef" * 8,
        tsa_url="https://freetsa.org/tsr",
        tst_bytes=b"\x30\x01\x00",
        timestamp="2026-02-21T02:28:25Z",
    )


def test_timestamp_token_to_dict_keys():
    token = _make_token()
    d = token.to_dict()
    assert set(d.keys()) == {"hash_hex", "tsa_url", "tst_hex", "timestamp"}


def test_timestamp_token_to_dict_tst_is_hex():
    token = _make_token()
    d = token.to_dict()
    # tst_bytes b"\x30\x01\x00" should be hex "300100"
    assert d["tst_hex"] == token.tst_bytes.hex()
    assert isinstance(d["tst_hex"], str)


def test_timestamp_token_roundtrip():
    token = _make_token()
    restored = TimestampToken.from_dict(token.to_dict())
    assert restored == token


def test_timestamp_token_from_dict_decodes_tst_bytes():
    token = _make_token()
    d = token.to_dict()
    restored = TimestampToken.from_dict(d)
    assert restored.tst_bytes == token.tst_bytes


def test_timestamp_token_all_fields_preserved_in_roundtrip():
    token = _make_token()
    d = token.to_dict()
    restored = TimestampToken.from_dict(d)
    assert restored.hash_hex == token.hash_hex
    assert restored.tsa_url == token.tsa_url
    assert restored.timestamp == token.timestamp


# ---------------------------------------------------------------------------
# request_timestamp (network mocked)
# ---------------------------------------------------------------------------


def _build_mock_tst_bytes(hash_hex: str) -> bytes:
    """Build a minimal fake TST bytes object for mocking purposes."""
    import rfc3161ng

    digest = _sha256_of_hash(hash_hex)
    req = rfc3161ng.make_timestamp_request(
        digest=digest,
        hashname="sha256",
        include_tsa_certificate=True,
    )
    # We return the TSQ bytes as a stand-in; the real test mocks get_timestamp too
    return rfc3161ng.encode_timestamp_request(req)


def test_request_timestamp_returns_timestamp_token():
    hash_hex = "a" * 64
    fake_tst_bytes = b"\x30\x82\x01\x00" + b"\x00" * 256
    fake_ts = datetime(2026, 2, 21, 2, 28, 25, tzinfo=UTC)

    stamper_mock = MagicMock(return_value=fake_tst_bytes)
    with (
        patch("protocol.rfc3161.rfc3161ng.RemoteTimestamper", return_value=stamper_mock),
        patch("protocol.rfc3161.rfc3161ng.get_timestamp", return_value=fake_ts),
    ):
        token = request_timestamp(hash_hex, tsa_url="https://example-tsa.test/tsr")

    assert isinstance(token, TimestampToken)
    assert token.hash_hex == hash_hex
    assert token.tsa_url == "https://example-tsa.test/tsr"
    assert token.tst_bytes == fake_tst_bytes
    assert token.timestamp == "2026-02-21T02:28:25Z"


def test_request_timestamp_uses_default_tsa_when_no_url_given():
    hash_hex = "b" * 64
    fake_tst_bytes = b"\x30\x00"
    fake_ts = datetime(2026, 1, 1, tzinfo=UTC)

    stamper_mock = MagicMock(return_value=fake_tst_bytes)
    with (
        patch(
            "protocol.rfc3161.rfc3161ng.RemoteTimestamper", return_value=stamper_mock
        ) as cls_mock,
        patch("protocol.rfc3161.rfc3161ng.get_timestamp", return_value=fake_ts),
    ):
        request_timestamp(hash_hex)

    # First positional arg to RemoteTimestamper should be DEFAULT_TSA_URL
    cls_mock.assert_called_once_with(
        DEFAULT_TSA_URL, hashname="sha256", include_tsa_certificate=True
    )


def test_request_timestamp_passes_digest_to_stamper():
    hash_hex = "c" * 64
    expected_digest = _sha256_of_hash(hash_hex)
    fake_tst_bytes = b"\x30\x00"
    fake_ts = datetime(2026, 1, 1, tzinfo=UTC)

    stamper_mock = MagicMock(return_value=fake_tst_bytes)
    with (
        patch("protocol.rfc3161.rfc3161ng.RemoteTimestamper", return_value=stamper_mock),
        patch("protocol.rfc3161.rfc3161ng.get_timestamp", return_value=fake_ts),
    ):
        request_timestamp(hash_hex)

    stamper_mock.assert_called_once_with(digest=expected_digest, return_tsr=False)


def test_request_timestamp_rejects_invalid_hash_hex():
    with pytest.raises(ValueError, match="Invalid hash_hex"):
        request_timestamp("not-valid-hex!!")


def test_request_timestamp_timestamp_uses_z_suffix():
    hash_hex = "d" * 64
    fake_tst_bytes = b"\x30\x00"
    fake_ts = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)

    stamper_mock = MagicMock(return_value=fake_tst_bytes)
    with (
        patch("protocol.rfc3161.rfc3161ng.RemoteTimestamper", return_value=stamper_mock),
        patch("protocol.rfc3161.rfc3161ng.get_timestamp", return_value=fake_ts),
    ):
        token = request_timestamp(hash_hex)

    assert token.timestamp.endswith("Z")
    assert "+00:00" not in token.timestamp


# ---------------------------------------------------------------------------
# verify_timestamp_token (rfc3161ng.check_timestamp mocked)
# ---------------------------------------------------------------------------


def test_verify_timestamp_token_returns_true_on_valid_token():
    hash_hex = "e" * 64
    fake_tst_bytes = b"\x30\x00"

    with patch("protocol.rfc3161.rfc3161ng.check_timestamp", return_value=True) as mock_check:
        result = verify_timestamp_token(fake_tst_bytes, hash_hex)

    assert result is True
    mock_check.assert_called_once_with(
        fake_tst_bytes,
        certificate=None,
        digest=_sha256_of_hash(hash_hex),
        hashname="sha256",
    )


def test_verify_timestamp_token_passes_certificate_when_provided():
    hash_hex = "f" * 64
    fake_tst_bytes = b"\x30\x00"
    fake_cert = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"

    with patch("protocol.rfc3161.rfc3161ng.check_timestamp", return_value=True) as mock_check:
        verify_timestamp_token(fake_tst_bytes, hash_hex, certificate=fake_cert)

    mock_check.assert_called_once_with(
        fake_tst_bytes,
        certificate=fake_cert,
        digest=_sha256_of_hash(hash_hex),
        hashname="sha256",
    )


def test_verify_timestamp_token_propagates_value_error_from_check():
    hash_hex = "a" * 64
    fake_tst_bytes = b"\x30\x00"

    with patch(
        "protocol.rfc3161.rfc3161ng.check_timestamp",
        side_effect=ValueError("Message imprint mismatch"),
    ):
        with pytest.raises(ValueError, match="Message imprint mismatch"):
            verify_timestamp_token(fake_tst_bytes, hash_hex)


def test_verify_timestamp_token_rejects_invalid_hash_hex():
    with pytest.raises(ValueError, match="Invalid hash_hex"):
        verify_timestamp_token(b"\x30\x00", "not-hex!!")
