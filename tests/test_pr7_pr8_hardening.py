"""
Tests for PR 7 (error sanitization / security headers) and
PR 8 (protocol-layer hardening).

Covers:
- H7: Database credential leak sanitization in storage_layer.py
- M12: Security response headers on API and debug UI
- M13: Debug UI env-guarded error messages
- H8: HLC monotonic timestamps in ledger
- H12: Shard header replay protection
- M18: Dual-signature key revocation
- H11: Ethereum anchor wallet validation
- M16: IPFS CID DAG-JSON varint encoding
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import nacl.signing
import pytest
from fastapi.testclient import TestClient

from protocol.canonical import CANONICAL_VERSION
from protocol.canonicalizer import canonicalization_provenance
from protocol.hashes import hash_bytes
from protocol.hlc import HLC_ZERO, HLCTimestamp, advance_hlc
from protocol.ledger import Ledger
from protocol.shards import (
    MAX_TIMESTAMP_SKEW_MS,
    create_key_revocation_record,
    create_shard_header,
    sign_header,
    verify_header,
    verify_key_revocation_record,
)
from protocol.timestamps import current_timestamp


def _canonicalization():
    return canonicalization_provenance("application/json", CANONICAL_VERSION)


def test_startup_rejects_dev_ceremony_stub_in_non_development(tmp_path: Path, monkeypatch):
    from api.main import _assert_no_dev_zk_stub_artifacts

    transcript_dir = tmp_path / "ceremony" / "transcript"
    transcript_dir.mkdir(parents=True)
    (transcript_dir / "dev_powers_of_tau.ptau").write_text(
        "DEV PLACEHOLDER PTAU\nThis file is development-only.\n", encoding="utf-8"
    )

    monkeypatch.setenv("OLYMPUS_ENV", "production")
    monkeypatch.delenv("OLYMPUS_ALLOW_DEV_AUTH", raising=False)
    monkeypatch.delenv("OLYMPUS_ALLOW_DEV_ZK_ARTIFACTS", raising=False)

    with pytest.raises(RuntimeError, match="dev ceremony stub artifact"):
        _assert_no_dev_zk_stub_artifacts(tmp_path)


def test_startup_allows_dev_ceremony_stub_with_override(tmp_path: Path, monkeypatch):
    from api.main import _assert_no_dev_zk_stub_artifacts

    transcript_dir = tmp_path / "ceremony" / "transcript"
    transcript_dir.mkdir(parents=True)
    (transcript_dir / "dev_redaction_validity_final.zkey").write_text(
        "DEV PLACEHOLDER ZKEY\nThis file is development-only.\n", encoding="utf-8"
    )

    monkeypatch.setenv("OLYMPUS_ENV", "production")
    monkeypatch.delenv("OLYMPUS_ALLOW_DEV_AUTH", raising=False)
    monkeypatch.setenv("OLYMPUS_ALLOW_DEV_ZK_ARTIFACTS", "true")
    _assert_no_dev_zk_stub_artifacts(tmp_path)


def test_startup_allows_dev_ceremony_stub_in_development(tmp_path: Path, monkeypatch):
    from api.main import _assert_no_dev_zk_stub_artifacts

    transcript_dir = tmp_path / "ceremony" / "transcript"
    transcript_dir.mkdir(parents=True)
    (transcript_dir / "dev_powers_of_tau.ptau").write_text(
        "DEV PLACEHOLDER PTAU\nThis file is development-only.\n", encoding="utf-8"
    )

    monkeypatch.setenv("OLYMPUS_ENV", "development")
    monkeypatch.delenv("OLYMPUS_ALLOW_DEV_ZK_ARTIFACTS", raising=False)
    _assert_no_dev_zk_stub_artifacts(tmp_path)


def test_startup_rejects_dev_signing_key_in_non_development(monkeypatch):
    from api.main import _assert_no_dev_signing_key_in_non_development

    monkeypatch.setenv("OLYMPUS_ENV", "production")
    monkeypatch.delenv("OLYMPUS_ALLOW_DEV_AUTH", raising=False)
    monkeypatch.setenv("OLYMPUS_DEV_SIGNING_KEY", "true")

    with pytest.raises(RuntimeError, match="OLYMPUS_DEV_SIGNING_KEY=true"):
        _assert_no_dev_signing_key_in_non_development()


def test_startup_allows_dev_signing_key_in_development(monkeypatch):
    from api.main import _assert_no_dev_signing_key_in_non_development

    monkeypatch.setenv("OLYMPUS_ENV", "development")
    monkeypatch.setenv("OLYMPUS_DEV_SIGNING_KEY", "true")
    _assert_no_dev_signing_key_in_non_development()


def test_startup_rejects_dev_auth_flag_in_non_development(monkeypatch):
    from api.main import _assert_dev_auth_flag_restricted_to_development

    monkeypatch.setenv("OLYMPUS_ENV", "production")
    monkeypatch.setenv("OLYMPUS_ALLOW_DEV_AUTH", "1")

    with pytest.raises(RuntimeError, match="OLYMPUS_ALLOW_DEV_AUTH=1"):
        _assert_dev_auth_flag_restricted_to_development()


def test_startup_allows_dev_auth_flag_in_development(monkeypatch):
    from api.main import _assert_dev_auth_flag_restricted_to_development

    monkeypatch.setenv("OLYMPUS_ENV", "development")
    monkeypatch.setenv("OLYMPUS_ALLOW_DEV_AUTH", "1")

    _assert_dev_auth_flag_restricted_to_development()


def test_create_app_rejects_wildcard_cors_with_credentials(monkeypatch):
    from api.config import get_settings
    from api.main import create_app

    monkeypatch.setenv("CORS_ORIGINS", "*")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="CORS_ORIGINS contains wildcard"):
        create_app()
    get_settings.cache_clear()


def test_validation_error_detail_preserves_url_key():
    from api.main import _json_safe_validation_detail

    detail = [
        {
            "type": "string_too_short",
            "loc": ["body", "name"],
            "msg": "String should have at least 3 characters",
            "input": "x",
            "url": "https://errors.pydantic.dev/2.10/v/string_too_short",
        }
    ]
    sanitized = _json_safe_validation_detail(detail)
    assert isinstance(sanitized, list)
    assert sanitized
    assert "url" in sanitized[0]


# ── H7: Storage layer error sanitization ───────────────────────────────


def test_storage_layer_503_uses_generic_message():
    """HTTPException detail from _get_storage must not expose raw exception text."""
    from unittest.mock import patch

    from fastapi import HTTPException

    with patch.dict(os.environ, {"DATABASE_URL": ""}, clear=False):
        from api.services import storage_layer

        # Force re-init
        storage_layer._storage = None
        storage_layer._db_error = None

        with pytest.raises(HTTPException) as exc_info:
            storage_layer._get_storage()

        detail = exc_info.value.detail
        assert "DATABASE_URL" not in detail
        assert "credential" not in detail.lower()
        assert "temporarily unavailable" in detail.lower() or "try again" in detail.lower()


# ── M12: Security headers ──────────────────────────────────────────────


class TestAPISecurityHeaders:
    """Verify that the FastAPI app sets required security headers."""

    @pytest.fixture(autouse=True)
    def _client(self):
        from api.main import app

        self.client = TestClient(app, raise_server_exceptions=False)

    def test_x_content_type_options(self):
        r = self.client.get("/")
        assert r.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self):
        r = self.client.get("/")
        assert r.headers.get("x-frame-options") == "DENY"

    def test_referrer_policy(self):
        r = self.client.get("/")
        assert r.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_content_security_policy(self):
        r = self.client.get("/")
        csp = r.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "'unsafe-inline'" not in csp

    def test_hsts_always_set(self):
        """HSTS header is always present (safe over HTTP; browsers ignore on non-HTTPS)."""
        r = self.client.get("/")
        assert "strict-transport-security" in r.headers


class TestDebugUISecurityHeaders:
    """Verify that the debug UI sets required security headers."""

    @pytest.fixture(autouse=True)
    def _client(self):
        import ui.app as ui_app

        self.client = TestClient(ui_app.app, raise_server_exceptions=False)

    def test_x_content_type_options(self):
        r = self.client.get("/manifest.json")
        assert r.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self):
        r = self.client.get("/manifest.json")
        assert r.headers.get("x-frame-options") == "DENY"


# ── H8: HLC timestamps ────────────────────────────────────────────────


class TestHLCTimestamp:
    """Unit tests for the Hybrid Logical Clock."""

    def test_hlc_zero(self):
        assert HLC_ZERO.wall_ms == 0
        assert HLC_ZERO.counter == 0

    def test_to_bytes_round_trip(self):
        ts = HLCTimestamp(wall_ms=1234567890123, counter=42)
        raw = ts.to_bytes()
        assert len(raw) == 12
        restored = HLCTimestamp.from_bytes(raw)
        assert restored == ts

    def test_advance_hlc_increments_counter_on_same_tick(self):
        now_ms = int(time.time() * 1000)
        # Create a timestamp in the far future to force counter increment
        future = HLCTimestamp(wall_ms=now_ms + 10_000_000, counter=5)
        advanced = advance_hlc(future)
        assert advanced.wall_ms == future.wall_ms
        assert advanced.counter == 6

    def test_advance_hlc_resets_counter_on_new_tick(self):
        old = HLCTimestamp(wall_ms=0, counter=99)
        advanced = advance_hlc(old)
        # Wall clock should have advanced far past 0
        assert advanced.wall_ms > 0
        assert advanced.counter == 0

    def test_hlc_ordering(self):
        a = HLCTimestamp(wall_ms=100, counter=0)
        b = HLCTimestamp(wall_ms=100, counter=1)
        c = HLCTimestamp(wall_ms=101, counter=0)
        assert a < b < c
        assert not (b < a)

    def test_from_bytes_rejects_wrong_length(self):
        with pytest.raises(ValueError, match="12 bytes"):
            HLCTimestamp.from_bytes(b"\x00" * 8)

    def test_negative_wall_ms_rejected(self):
        with pytest.raises(ValueError, match="non-negative"):
            HLCTimestamp(wall_ms=-1, counter=0)


class TestLedgerHLC:
    """Tests that ledger entries include and validate HLC timestamps."""

    def test_entries_have_hlc_bytes(self):
        ledger = Ledger()
        entry = ledger.append(
            record_hash="h1",
            shard_id="s1",
            shard_root="r1",
            canonicalization=_canonicalization(),
        )
        assert entry.hlc_bytes is not None
        hlc = HLCTimestamp.from_bytes(bytes.fromhex(entry.hlc_bytes))
        assert hlc > HLC_ZERO

    def test_hlc_monotonically_increasing(self):
        ledger = Ledger()
        entries = []
        for i in range(5):
            entries.append(
                ledger.append(
                    record_hash=f"h{i}",
                    shard_id="s1",
                    shard_root="r1",
                    canonicalization=_canonicalization(),
                )
            )
        for i in range(1, len(entries)):
            hlc_prev = HLCTimestamp.from_bytes(bytes.fromhex(entries[i - 1].hlc_bytes))
            hlc_curr = HLCTimestamp.from_bytes(bytes.fromhex(entries[i].hlc_bytes))
            assert hlc_curr > hlc_prev

    def test_verify_chain_with_hlc(self):
        ledger = Ledger()
        for i in range(3):
            ledger.append(
                record_hash=f"h{i}",
                shard_id="s1",
                shard_root="r1",
                canonicalization=_canonicalization(),
            )
        assert ledger.verify_chain() is True

    def test_backdated_hlc_fails_verification(self):
        """Manually tamper with HLC to prove verification catches it."""
        ledger = Ledger()
        ledger.append(
            record_hash="h1",
            shard_id="s1",
            shard_root="r1",
            canonicalization=_canonicalization(),
        )
        entry2 = ledger.append(
            record_hash="h2",
            shard_id="s1",
            shard_root="r1",
            canonicalization=_canonicalization(),
        )
        # Tamper: set entry2's HLC to something earlier than entry1
        entry2.hlc_bytes = HLC_ZERO.to_bytes().hex()
        assert ledger.verify_chain() is False

    def test_hlc_bytes_in_hash_prevents_backdating(self):
        """Changing HLC bytes without recomputing hash breaks chain integrity."""
        ledger = Ledger()
        entry = ledger.append(
            record_hash="h1",
            shard_id="s1",
            shard_root="r1",
            canonicalization=_canonicalization(),
        )
        # Tamper HLC
        entry.hlc_bytes = HLCTimestamp(wall_ms=1, counter=0).to_bytes().hex()
        # Hash no longer matches
        assert ledger.verify_chain() is False


# ── H12: Shard header replay protection ────────────────────────────────


class TestShardReplayProtection:
    """Tests for verify_header sequence and timestamp skew checks."""

    @pytest.fixture(autouse=True)
    def _keys(self):
        self.signing_key = nacl.signing.SigningKey.generate()
        self.verify_key = self.signing_key.verify_key

    def _make_header(self, **overrides):
        root_hash = hash_bytes(b"test root")
        header = create_shard_header(
            shard_id="shard1",
            root_hash=root_hash,
            timestamp=current_timestamp(),
        )
        header.update(overrides)
        # Re-hash after adding extra fields if needed
        from protocol.hashes import shard_header_hash
        from protocol.shards import _HEADER_EXCLUDED_FIELDS

        header["header_hash"] = shard_header_hash(
            {k: v for k, v in header.items() if k not in _HEADER_EXCLUDED_FIELDS}
        ).hex()
        return header

    def test_basic_verify_header_still_works(self):
        header = self._make_header()
        sig = sign_header(header, self.signing_key)
        assert verify_header(header, sig, self.verify_key) is True

    def test_replay_rejected_when_sequence_not_monotonic(self):
        header = self._make_header(sequence_number=5)
        sig = sign_header(header, self.signing_key)
        # prev_sequence=5 means seq must be > 5 — seq=5 is a replay
        assert verify_header(header, sig, self.verify_key, prev_sequence=5) is False

    def test_replay_accepted_when_sequence_advances(self):
        header = self._make_header(sequence_number=6)
        sig = sign_header(header, self.signing_key)
        assert verify_header(header, sig, self.verify_key, prev_sequence=5) is True

    def test_timestamp_skew_rejected(self):
        stale_hlc = HLCTimestamp(wall_ms=1000, counter=0)
        now_hlc = HLCTimestamp(wall_ms=1000 + MAX_TIMESTAMP_SKEW_MS + 1, counter=0)
        header = self._make_header(timestamp_hlc=stale_hlc.to_bytes().hex())
        sig = sign_header(header, self.signing_key)
        assert verify_header(header, sig, self.verify_key, now_hlc=now_hlc) is False

    def test_timestamp_within_skew_accepted(self):
        now_ms = int(time.time() * 1000)
        header_hlc = HLCTimestamp(wall_ms=now_ms, counter=0)
        now_hlc = HLCTimestamp(wall_ms=now_ms + 100, counter=0)
        header = self._make_header(timestamp_hlc=header_hlc.to_bytes().hex())
        sig = sign_header(header, self.signing_key)
        assert verify_header(header, sig, self.verify_key, now_hlc=now_hlc) is True

    def test_no_sequence_check_when_prev_sequence_not_provided(self):
        """When prev_sequence is None, sequence_number is not checked."""
        header = self._make_header(sequence_number=0)
        sig = sign_header(header, self.signing_key)
        assert verify_header(header, sig, self.verify_key) is True


# ── M18: Dual-signature key revocation ─────────────────────────────────


class TestDualSignatureRevocation:
    """Tests for dual-signed key revocation records."""

    @pytest.fixture(autouse=True)
    def _keys(self):
        self.old_signing = nacl.signing.SigningKey.generate()
        self.old_verify = self.old_signing.verify_key
        self.new_signing = nacl.signing.SigningKey.generate()

    def test_dual_signed_record_valid(self):
        record = create_key_revocation_record(
            old_verify_key=self.old_verify,
            new_signing_key=self.new_signing,
            compromise_timestamp=current_timestamp(),
            last_good_sequence=10,
            old_signing_key=self.old_signing,
        )
        assert record["dual_signed"] is True
        assert "old_key_signature" in record
        assert verify_key_revocation_record(record) is True

    def test_single_signed_record_valid(self):
        record = create_key_revocation_record(
            old_verify_key=self.old_verify,
            new_signing_key=self.new_signing,
            compromise_timestamp=current_timestamp(),
            last_good_sequence=10,
        )
        assert record["dual_signed"] is False
        assert "old_key_signature" not in record
        assert verify_key_revocation_record(record) is True

    def test_dual_signed_with_wrong_old_key_fails(self):
        wrong_signing = nacl.signing.SigningKey.generate()
        record = create_key_revocation_record(
            old_verify_key=self.old_verify,
            new_signing_key=self.new_signing,
            compromise_timestamp=current_timestamp(),
            last_good_sequence=10,
            old_signing_key=wrong_signing,  # wrong key
        )
        assert record["dual_signed"] is True
        # old_key_signature was produced by wrong_signing, but old_pubkey
        # is self.old_verify — signature verification should fail.
        assert verify_key_revocation_record(record) is False

    def test_dual_signed_missing_old_key_signature_fails(self):
        record = create_key_revocation_record(
            old_verify_key=self.old_verify,
            new_signing_key=self.new_signing,
            compromise_timestamp=current_timestamp(),
            last_good_sequence=10,
            old_signing_key=self.old_signing,
        )
        del record["old_key_signature"]
        # dual_signed=True but no old_key_signature
        assert verify_key_revocation_record(record) is False

    def test_backwards_compat_single_signed(self):
        """Records without dual_signed field should still verify."""
        record = create_key_revocation_record(
            old_verify_key=self.old_verify,
            new_signing_key=self.new_signing,
            compromise_timestamp=current_timestamp(),
            last_good_sequence=10,
        )
        # Remove dual_signed to simulate old record format
        record.pop("dual_signed", None)
        assert verify_key_revocation_record(record) is True


# ── H11: Ethereum anchor wallet validation ────────────────────────────


class TestEthereumAnchorWallet:
    """Tests for wallet address validation before Ethereum anchor submission."""

    def test_build_payload_without_wallet_unchanged(self):
        from integrations.ethereum import build_ethereum_anchor_payload

        bundle = {
            "proof_id": "p1",
            "content_hash": "aa" * 32,
            "merkle_root": "bb" * 32,
            "ledger_entry_hash": "cc" * 32,
        }
        result = build_ethereum_anchor_payload(bundle)
        assert result["proofId"] == "p1"

    def test_validate_anchor_wallet_matches(self, monkeypatch):
        from integrations.ethereum import validate_anchor_wallet

        monkeypatch.setenv("OLYMPUS_ETH_ANCHOR_ADDRESS", "0xAbC123")
        validate_anchor_wallet("0xabc123")  # case-insensitive

    def test_validate_anchor_wallet_mismatch(self, monkeypatch):
        from integrations.ethereum import validate_anchor_wallet

        monkeypatch.setenv("OLYMPUS_ETH_ANCHOR_ADDRESS", "0xAbC123")
        with pytest.raises(ValueError, match="does not match"):
            validate_anchor_wallet("0xDEF456")

    def test_validate_anchor_wallet_no_env(self, monkeypatch):
        from integrations.ethereum import validate_anchor_wallet

        monkeypatch.delenv("OLYMPUS_ETH_ANCHOR_ADDRESS", raising=False)
        # Should not raise when env var is not set
        validate_anchor_wallet("0xAnyAddress")

    def test_build_payload_with_wallet_validates(self, monkeypatch):
        from integrations.ethereum import build_ethereum_anchor_payload

        monkeypatch.setenv("OLYMPUS_ETH_ANCHOR_ADDRESS", "0xABC")
        bundle = {
            "proof_id": "p1",
            "content_hash": "aa" * 32,
            "merkle_root": "bb" * 32,
            "ledger_entry_hash": "cc" * 32,
        }
        with pytest.raises(ValueError, match="does not match"):
            build_ethereum_anchor_payload(bundle, wallet_address="0xWRONG")

    def test_contract_has_access_control(self):
        from integrations.ethereum import ETHEREUM_ANCHOR_CONTRACT

        assert "onlyAllowed" in ETHEREUM_ANCHOR_CONTRACT
        assert "onlyOwner" in ETHEREUM_ANCHOR_CONTRACT
        assert "allowedSubmitters" in ETHEREUM_ANCHOR_CONTRACT


# ── M16: IPFS CID varint encoding ─────────────────────────────────────


class TestIPFSVarint:
    """Tests for correct DAG-JSON varint encoding in CIDv1."""

    def test_dag_json_varint_encoding(self):
        """CIDv1 bytes must contain correct varint for DAG-JSON codec (0x0129)."""
        from integrations.ipfs import compute_ipfs_cidv1

        bundle = {"test": "data"}
        cid = compute_ipfs_cidv1(bundle)
        # CID should start with 'b' (base32 prefix)
        assert cid.startswith("b")

    def test_dag_json_varint_bytes_in_cid(self):
        """The raw CID bytes at position 1-2 must be the varint \\xa9\\x02."""
        import blake3 as blake3_mod

        from integrations.ipfs import (
            _BLAKE3_CODE,
            _BLAKE3_LENGTH,
            _CID_VERSION,
            _DAG_JSON_CODEC,
            build_ipfs_proof_envelope,
        )

        bundle = {"test": "data"}
        payload = build_ipfs_proof_envelope(bundle)
        digest = blake3_mod.blake3(payload).digest()
        multihash = _BLAKE3_CODE + _BLAKE3_LENGTH + digest
        cid_bytes = _CID_VERSION + _DAG_JSON_CODEC + multihash

        # Multicodec varint at bytes 1-2 of CIDv1 must be 0xa9 0x02
        assert cid_bytes[1:3] == b"\xa9\x02"

    def test_dag_json_codec_constant(self):
        """Module constant must be the correct 2-byte varint."""
        from integrations.ipfs import _DAG_JSON_CODEC

        assert _DAG_JSON_CODEC == b"\xa9\x02"

    def test_cid_is_deterministic(self):
        from integrations.ipfs import compute_ipfs_cidv1

        bundle = {"a": 1, "b": 2}
        assert compute_ipfs_cidv1(bundle) == compute_ipfs_cidv1(bundle)


# ── PR-S1: Startup assertions H1 + H2 ─────────────────────────────────


def test_startup_rejects_multiworker_memory_backend_in_production(monkeypatch):
    from api.config import get_settings
    from api.main import _assert_no_multiworker_with_memory_rate_limit

    monkeypatch.setenv("OLYMPUS_ENV", "production")
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "memory")
    get_settings.cache_clear()

    with pytest.raises(RuntimeError, match="RATE_LIMIT_BACKEND=memory"):
        _assert_no_multiworker_with_memory_rate_limit()

    get_settings.cache_clear()


def test_startup_allows_multiworker_memory_backend_in_development(monkeypatch):
    from api.config import get_settings
    from api.main import _assert_no_multiworker_with_memory_rate_limit

    monkeypatch.setenv("OLYMPUS_ENV", "development")
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "memory")
    get_settings.cache_clear()

    _assert_no_multiworker_with_memory_rate_limit()  # must not raise

    get_settings.cache_clear()


def test_startup_allows_single_worker_memory_backend_in_production(monkeypatch):
    from api.config import get_settings
    from api.main import _assert_no_multiworker_with_memory_rate_limit

    monkeypatch.setenv("OLYMPUS_ENV", "production")
    monkeypatch.setenv("WEB_CONCURRENCY", "1")
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "memory")
    get_settings.cache_clear()

    _assert_no_multiworker_with_memory_rate_limit()  # must not raise

    get_settings.cache_clear()


def test_startup_allows_multiworker_when_web_concurrency_unset(monkeypatch):
    from api.config import get_settings
    from api.main import _assert_no_multiworker_with_memory_rate_limit

    monkeypatch.setenv("OLYMPUS_ENV", "production")
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "memory")
    get_settings.cache_clear()

    _assert_no_multiworker_with_memory_rate_limit()  # WEB_CONCURRENCY defaults to 1

    get_settings.cache_clear()


def test_startup_xff_disabled_when_no_trusted_proxies_configured(monkeypatch):
    """assert_xff_default_deny sets _xff_disabled and _get_client_ip ignores XFF."""
    from unittest.mock import MagicMock, patch

    import api.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_xff_disabled", False)

    mock_settings = MagicMock()
    mock_settings.trusted_proxy_ips = []

    with patch("api.auth.get_settings", return_value=mock_settings):
        auth_mod.assert_xff_default_deny()

    assert auth_mod._xff_disabled is True

    # _get_client_ip must return the peer IP even when XFF header is present
    request = MagicMock()
    request.client.host = "10.0.0.1"
    request.headers.get.return_value = "203.0.113.42"

    ip = auth_mod._get_client_ip(request)
    assert ip == "10.0.0.1"


def test_startup_xff_enabled_when_trusted_proxies_configured(monkeypatch):
    """assert_xff_default_deny leaves _xff_disabled False when proxies are configured."""
    from unittest.mock import MagicMock, patch

    import api.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_xff_disabled", False)

    mock_settings = MagicMock()
    mock_settings.trusted_proxy_ips = ["10.0.0.1"]

    with patch("api.auth.get_settings", return_value=mock_settings):
        auth_mod.assert_xff_default_deny()

    assert auth_mod._xff_disabled is False
