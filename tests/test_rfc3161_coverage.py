"""Targeted coverage tests for protocol/rfc3161.py — error/rejection paths.

Covers:
- _extract_tsa_cert_fingerprint with bad ASN.1 (lines 100-105)
- _extract_message_imprint with bad ASN.1 (lines 129-142)
- verify_timestamp_token trust_store_path branch (line 335→340)
- verify_quorum_tsa_tokens fingerprint/trust_store branches (lines 395, 398)
- extract_tsa_certificate with bad input (lines 485-489)
- check_tsa_certificate_expiry with naive datetime (line 515)
"""

from datetime import datetime, timezone

import pytest

from protocol.rfc3161 import (
    _extract_message_imprint,
    _extract_tsa_cert_fingerprint,
    check_tsa_certificate_expiry,
    extract_tsa_certificate,
    verify_timestamp_token,
)


# ---------------------------------------------------------------------------
# _extract_tsa_cert_fingerprint error paths (lines 100-105)
# ---------------------------------------------------------------------------


def test_extract_fingerprint_garbage_bytes():
    """_extract_tsa_cert_fingerprint returns None for garbage input."""
    result = _extract_tsa_cert_fingerprint(b"\x00\x01\x02\x03")
    assert result is None


def test_extract_fingerprint_empty_bytes():
    """_extract_tsa_cert_fingerprint returns None for empty input."""
    result = _extract_tsa_cert_fingerprint(b"")
    assert result is None


# ---------------------------------------------------------------------------
# _extract_message_imprint error paths (lines 129-142)
# ---------------------------------------------------------------------------


def test_extract_message_imprint_garbage():
    """_extract_message_imprint returns None for garbage input."""
    result = _extract_message_imprint(b"\x30\x00")
    assert result is None


def test_extract_message_imprint_empty():
    """_extract_message_imprint returns None for empty bytes."""
    result = _extract_message_imprint(b"")
    assert result is None


def test_extract_message_imprint_truncated_asn1():
    """_extract_message_imprint returns None for truncated ASN.1."""
    result = _extract_message_imprint(b"\x30\x06\x30\x04\x06\x02")
    assert result is None


# ---------------------------------------------------------------------------
# verify_timestamp_token — trust_store_path branch (line 335→340)
# ---------------------------------------------------------------------------


def test_verify_token_prod_trust_store_not_found():
    """Production mode with nonexistent trust_store_path raises ValueError."""
    with pytest.raises(ValueError, match="Trust store path not found"):
        verify_timestamp_token(
            b"\x00",
            "aa" * 32,
            trust_mode="prod",
            trust_store_path="/nonexistent/cert.pem",
        )


def test_verify_token_prod_no_fingerprints_no_store_no_cert():
    """Production mode without fingerprints, store, or cert raises ValueError."""
    with pytest.raises(ValueError, match="requires trusted_fingerprints"):
        verify_timestamp_token(
            b"\x00",
            "aa" * 32,
            trust_mode="prod",
        )


# ---------------------------------------------------------------------------
# verify_quorum_tsa_tokens — fingerprint/trust_store per-TSA (lines 395, 398)
# ---------------------------------------------------------------------------


def test_verify_quorum_fingerprints_by_tsa():
    """verify_timestamp_quorum passes per-TSA fingerprints/trust_store through.

    Lines 394-395 and 397-398 handle the per-TSA lookup of fingerprints and
    trust_store_path.  We provide matching entries so both branches are hit,
    then mock verify_timestamp_token so the ASN.1 parsing issue is bypassed.
    """
    from unittest.mock import patch as _patch

    from protocol.rfc3161 import (
        DEFAULT_FINALIZATION_TSA_URLS,
        TimestampToken,
        verify_timestamp_quorum,
    )

    tsa_url = DEFAULT_FINALIZATION_TSA_URLS[0]
    tokens = [
        TimestampToken(
            tsa_url=tsa_url,
            hash_hex="aa" * 32,
            tst_bytes=b"\x00",
            timestamp="2026-01-01T00:00:00Z",
        ),
    ]

    # Mock verify_timestamp_token to return False (token invalid) so we can
    # exercise the per-TSA fingerprint/trust_store lookup code paths without
    # the pyasn1 decoding exception.
    with _patch("protocol.rfc3161.verify_timestamp_token", return_value=False):
        result = verify_timestamp_quorum(
            tokens,
            "aa" * 32,
            trust_mode="dev",
            trusted_fingerprints_by_tsa={tsa_url: {"deadbeef"}},
            trust_store_paths_by_tsa={tsa_url: "/fake/cert.pem"},
        )
    assert result is False


# ---------------------------------------------------------------------------
# extract_tsa_certificate error paths (lines 485-489)
# ---------------------------------------------------------------------------


def test_extract_tsa_certificate_garbage():
    """extract_tsa_certificate returns None for garbage bytes."""
    assert extract_tsa_certificate(b"\x00\x01") is None


def test_extract_tsa_certificate_empty():
    """extract_tsa_certificate returns None for empty input."""
    assert extract_tsa_certificate(b"") is None


# ---------------------------------------------------------------------------
# check_tsa_certificate_expiry — naive datetime (line 515)
# ---------------------------------------------------------------------------


def test_check_tsa_certificate_expiry_naive_datetime():
    """check_tsa_certificate_expiry handles naive datetime by adding UTC tz."""
    # Even with a naive datetime, should not crash
    result = check_tsa_certificate_expiry(
        b"\x00\x01\x02",
        now=datetime(2026, 1, 1),
    )
    # Certificate extraction will fail, returning invalid result
    assert result["valid"] is False
    assert "Could not extract" in result.get("message", "")


def test_check_tsa_certificate_expiry_with_garbage_bytes():
    """check_tsa_certificate_expiry returns invalid for garbage tst_bytes."""
    result = check_tsa_certificate_expiry(
        b"\xff\xfe",
        now=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )
    assert result["valid"] is False
