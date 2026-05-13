"""
Tests for api/routers/sbt_metadata.py  (GET /sbt/metadata/{credential_id})
and the evm_status computation helper in api/routers/keys.py.

Covers:
  - 404 for unknown credential_id
  - Returned JSON shape (name, description, image, external_url, attributes)
  - Active credential: Status attribute = "Active", no Revoked At attribute
  - Revoked credential: Status attribute = "Revoked", Revoked At attribute present
  - evm_minted event adds On-Chain Commit ID attribute
  - OLYMPUS_BASE_URL and OLYMPUS_SBT_IMAGE_URI env overrides
  - _compute_evm_status: no ops → "none"
  - _compute_evm_status: pending/submitted mint → "pending"
  - _compute_evm_status: confirmed mint → "anchored"
  - _compute_evm_status: confirmed burn → "revoked" (overrides confirmed mint)
  - _compute_evm_status: failed mint → "failed"
  - _compute_evm_status: skipped mint → "none"
  - GET /key/credential/{id}: evm_status reflected in CredentialResponse
  - GET /key/credential/{id}: 404 for unknown credential
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_db() -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.add = MagicMock()
    return db


def _scalar_none(db: MagicMock) -> None:
    """Configure db.execute() to return scalar_one_or_none() → None."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db.execute.return_value = result


def _scalar_value(db: MagicMock, value) -> None:
    """Configure db.execute() to return scalar_one_or_none() → value."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = value
    db.execute.return_value = result


def _scalars_sequence(db: MagicMock, *values) -> None:
    """Configure consecutive db.execute() calls to return different scalars."""
    results = []
    for v in values:
        r = MagicMock()
        r.scalar_one_or_none.return_value = v
        results.append(r)
    db.execute.side_effect = results


def _make_credential(
    *,
    id: str = "cred-abc",
    holder_key: str = "aa" * 32,
    credential_type: str = "journalist",
    issuer: str = "Tribune News",
    burn_authorization: str = "issuer_only",
    issued_at: datetime | None = None,
    revoked_at: datetime | None = None,
    commit_id: str = "0x" + "ab" * 32,
    sbt_nontransferable: bool = True,
    holder_account_id: str | None = "user-1",
    consent_id: str | None = None,
    revocation_commit_id: str | None = None,
):
    cred = MagicMock()
    cred.id = id
    cred.holder_key = holder_key
    cred.holder_account_id = holder_account_id
    cred.credential_type = credential_type
    cred.issuer = issuer
    cred.burn_authorization = burn_authorization
    cred.issued_at = issued_at or datetime(2024, 1, 1, tzinfo=timezone.utc)
    cred.revoked_at = revoked_at
    cred.commit_id = commit_id
    cred.sbt_nontransferable = sbt_nontransferable
    cred.consent_id = consent_id
    cred.revocation_commit_id = revocation_commit_id
    return cred


def _make_evm_op(
    *,
    op_type: str = "mint",
    status: str = "confirmed",
    credential_id: str = "cred-abc",
    queued_at: datetime | None = None,
):
    op = MagicMock()
    op.op_type = op_type
    op.status = status
    op.credential_id = credential_id
    op.queued_at = queued_at or datetime(2024, 6, 1, tzinfo=timezone.utc)
    return op


# ─── Tests: _compute_evm_status ───────────────────────────────────────────────


class TestComputeEvmStatus:
    @pytest.mark.asyncio
    async def test_no_ops_returns_none(self):
        from api.routers.keys import _compute_evm_status

        db = _make_db()
        # First call (burn check) → None; second call (mint) → None
        _scalars_sequence(db, None, None)

        result = await _compute_evm_status("cred-abc", db)
        assert result == "none"

    @pytest.mark.asyncio
    async def test_confirmed_burn_returns_revoked(self):
        from api.routers.keys import _compute_evm_status

        db = _make_db()
        # First call: confirmed burn found → short-circuit
        burn_op = _make_evm_op(op_type="burn", status="confirmed")
        _scalar_value(db, burn_op)

        result = await _compute_evm_status("cred-abc", db)
        assert result == "revoked"
        # Should stop after the burn query
        assert db.execute.call_count == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize("mint_status", ["pending", "submitted"])
    async def test_pending_or_submitted_mint_returns_pending(self, mint_status: str):
        from api.routers.keys import _compute_evm_status

        db = _make_db()
        mint_op = _make_evm_op(op_type="mint", status=mint_status)
        _scalars_sequence(db, None, mint_op)

        result = await _compute_evm_status("cred-abc", db)
        assert result == "pending"

    @pytest.mark.asyncio
    async def test_confirmed_mint_no_burn_returns_anchored(self):
        from api.routers.keys import _compute_evm_status

        db = _make_db()
        mint_op = _make_evm_op(op_type="mint", status="confirmed")
        _scalars_sequence(db, None, mint_op)

        result = await _compute_evm_status("cred-abc", db)
        assert result == "anchored"

    @pytest.mark.asyncio
    async def test_failed_mint_returns_failed(self):
        from api.routers.keys import _compute_evm_status

        db = _make_db()
        mint_op = _make_evm_op(op_type="mint", status="failed")
        _scalars_sequence(db, None, mint_op)

        result = await _compute_evm_status("cred-abc", db)
        assert result == "failed"

    @pytest.mark.asyncio
    async def test_skipped_mint_returns_none(self):
        from api.routers.keys import _compute_evm_status

        db = _make_db()
        mint_op = _make_evm_op(op_type="mint", status="skipped")
        _scalars_sequence(db, None, mint_op)

        result = await _compute_evm_status("cred-abc", db)
        assert result == "none"

    @pytest.mark.asyncio
    async def test_confirmed_burn_wins_over_confirmed_mint(self):
        """Confirmed burn must return 'revoked' regardless of mint state."""
        from api.routers.keys import _compute_evm_status

        db = _make_db()
        # Burn query returns a row → return "revoked" immediately
        burn_op = _make_evm_op(op_type="burn", status="confirmed")
        _scalar_value(db, burn_op)

        result = await _compute_evm_status("cred-abc", db)
        assert result == "revoked"


# ─── Tests: GET /key/credential/{credential_id} ───────────────────────────────


class TestGetCredential:
    @pytest.mark.asyncio
    async def test_returns_credential_with_evm_status(self):
        from api.routers.keys import get_credential

        db = _make_db()
        cred = _make_credential()

        # Sequence: cred lookup → burn check → mint lookup
        cred_result = MagicMock()
        cred_result.scalar_one_or_none.return_value = cred

        burn_result = MagicMock()
        burn_result.scalar_one_or_none.return_value = None

        mint_op = _make_evm_op(status="confirmed")
        mint_result = MagicMock()
        mint_result.scalar_one_or_none.return_value = mint_op

        db.execute.side_effect = [cred_result, burn_result, mint_result]

        mock_api_key = MagicMock()
        mock_api_key.key_id = "test-key"

        response = await get_credential(
            credential_id="cred-abc",
            db=db,
            api_key=mock_api_key,
            _rl=None,
        )

        assert response.id == "cred-abc"
        assert response.evm_status == "anchored"

    @pytest.mark.asyncio
    async def test_evm_status_none_when_no_ops(self):
        from api.routers.keys import get_credential

        db = _make_db()
        cred = _make_credential()

        cred_result = MagicMock()
        cred_result.scalar_one_or_none.return_value = cred

        no_op = MagicMock()
        no_op.scalar_one_or_none.return_value = None

        db.execute.side_effect = [cred_result, no_op, no_op]

        mock_api_key = MagicMock()
        mock_api_key.key_id = "test-key"

        response = await get_credential(
            credential_id="cred-abc",
            db=db,
            api_key=mock_api_key,
            _rl=None,
        )

        assert response.evm_status == "none"

    @pytest.mark.asyncio
    async def test_404_for_missing_credential(self):
        from fastapi import HTTPException

        from api.routers.keys import get_credential

        db = _make_db()
        _scalar_none(db)

        mock_api_key = MagicMock()
        mock_api_key.key_id = "test-key"

        with pytest.raises(HTTPException) as exc_info:
            await get_credential(
                credential_id="no-such-id",
                db=db,
                api_key=mock_api_key,
                _rl=None,
            )

        assert exc_info.value.status_code == 404
        assert exc_info.value.detail["code"] == "CREDENTIAL_NOT_FOUND"


# ─── Tests: GET /sbt/metadata/{credential_id} ─────────────────────────────────


class TestSbtMetadataEndpoint:
    @pytest.mark.asyncio
    async def test_404_for_missing_credential(self):
        from fastapi import HTTPException

        from api.routers.sbt_metadata import get_sbt_metadata

        db = _make_db()
        _scalar_none(db)

        with pytest.raises(HTTPException) as exc_info:
            await get_sbt_metadata(credential_id="no-such-id", db=db)

        assert exc_info.value.status_code == 404
        assert exc_info.value.detail["code"] == "CREDENTIAL_NOT_FOUND"

    @pytest.mark.asyncio
    async def test_active_credential_metadata_shape(self):
        from api.routers.sbt_metadata import get_sbt_metadata

        db = _make_db()
        cred = _make_credential(
            id="cred-abc",
            credential_type="journalist",
            issuer="Tribune News",
            burn_authorization="issuer_only",
            issued_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )

        cred_result = MagicMock()
        cred_result.scalar_one_or_none.return_value = cred

        evm_result = MagicMock()
        evm_result.scalar_one_or_none.return_value = None  # no evm_minted event

        db.execute.side_effect = [cred_result, evm_result]

        response = await get_sbt_metadata(credential_id="cred-abc", db=db)
        body = response.body
        import json

        data = json.loads(body)

        assert data["name"] == "Olympus Credential — journalist"
        assert "journalist" in data["description"]
        assert "Tribune News" in data["description"]
        assert data["external_url"].endswith("/sbt/metadata/cred-abc")

        trait_map = {a["trait_type"]: a["value"] for a in data["attributes"]}
        assert trait_map["Credential Type"] == "journalist"
        assert trait_map["Issuer"] == "Tribune News"
        assert trait_map["Status"] == "Active"
        assert trait_map["Burn Authorization"] == "issuer_only"
        assert "Revoked At" not in trait_map
        assert "On-Chain Commit ID" not in trait_map

    @pytest.mark.asyncio
    async def test_revoked_credential_adds_revoked_at_attribute(self):
        from api.routers.sbt_metadata import get_sbt_metadata

        db = _make_db()
        cred = _make_credential(
            revoked_at=datetime(2024, 6, 1, tzinfo=timezone.utc),
        )

        cred_result = MagicMock()
        cred_result.scalar_one_or_none.return_value = cred

        evm_result = MagicMock()
        evm_result.scalar_one_or_none.return_value = None

        db.execute.side_effect = [cred_result, evm_result]

        import json

        response = await get_sbt_metadata(credential_id="cred-abc", db=db)
        data = json.loads(response.body)

        trait_map = {a["trait_type"]: a["value"] for a in data["attributes"]}
        assert trait_map["Status"] == "Revoked"
        assert "Revoked At" in trait_map
        assert isinstance(trait_map["Revoked At"], int)

    @pytest.mark.asyncio
    async def test_evm_minted_event_adds_onchain_commit_attribute(self):
        from api.routers.sbt_metadata import get_sbt_metadata

        db = _make_db()
        cred = _make_credential()

        evm_event = MagicMock()
        evm_event.ledger_commit_id = "0x" + "cc" * 32

        cred_result = MagicMock()
        cred_result.scalar_one_or_none.return_value = cred

        evm_result = MagicMock()
        evm_result.scalar_one_or_none.return_value = evm_event

        db.execute.side_effect = [cred_result, evm_result]

        import json

        response = await get_sbt_metadata(credential_id="cred-abc", db=db)
        data = json.loads(response.body)

        trait_map = {a["trait_type"]: a["value"] for a in data["attributes"]}
        assert trait_map["On-Chain Commit ID"] == "0x" + "cc" * 32

    @pytest.mark.asyncio
    async def test_base_url_env_override(self, monkeypatch):
        from api.routers.sbt_metadata import get_sbt_metadata

        monkeypatch.setenv("OLYMPUS_BASE_URL", "https://olympus.example.com")

        db = _make_db()
        cred = _make_credential(id="cred-xyz")

        cred_result = MagicMock()
        cred_result.scalar_one_or_none.return_value = cred

        evm_result = MagicMock()
        evm_result.scalar_one_or_none.return_value = None

        db.execute.side_effect = [cred_result, evm_result]

        import json

        response = await get_sbt_metadata(credential_id="cred-xyz", db=db)
        data = json.loads(response.body)

        assert data["external_url"] == "https://olympus.example.com/sbt/metadata/cred-xyz"
        assert data["image"].startswith("https://olympus.example.com/")

    @pytest.mark.asyncio
    async def test_image_uri_env_override(self, monkeypatch):
        from api.routers.sbt_metadata import get_sbt_metadata

        monkeypatch.setenv("OLYMPUS_SBT_IMAGE_URI", "ipfs://QmTestImageHash")

        db = _make_db()
        cred = _make_credential()

        cred_result = MagicMock()
        cred_result.scalar_one_or_none.return_value = cred

        evm_result = MagicMock()
        evm_result.scalar_one_or_none.return_value = None

        db.execute.side_effect = [cred_result, evm_result]

        import json

        response = await get_sbt_metadata(credential_id="cred-abc", db=db)
        data = json.loads(response.body)

        assert data["image"] == "ipfs://QmTestImageHash"

    @pytest.mark.asyncio
    async def test_issued_at_attribute_is_unix_timestamp(self):
        from api.routers.sbt_metadata import get_sbt_metadata

        db = _make_db()
        issued = datetime(2024, 3, 15, 12, 0, 0, tzinfo=timezone.utc)
        cred = _make_credential(issued_at=issued)

        cred_result = MagicMock()
        cred_result.scalar_one_or_none.return_value = cred

        evm_result = MagicMock()
        evm_result.scalar_one_or_none.return_value = None

        db.execute.side_effect = [cred_result, evm_result]

        import json

        response = await get_sbt_metadata(credential_id="cred-abc", db=db)
        data = json.loads(response.body)

        issued_attr = next((a for a in data["attributes"] if a["trait_type"] == "Issued At"), None)
        assert issued_attr is not None
        assert issued_attr["display_type"] == "date"
        assert issued_attr["value"] == int(issued.timestamp())

    @pytest.mark.asyncio
    async def test_ledger_commit_id_in_attributes(self):
        from api.routers.sbt_metadata import get_sbt_metadata

        db = _make_db()
        commit = "0x" + "ab" * 32
        cred = _make_credential(commit_id=commit)

        cred_result = MagicMock()
        cred_result.scalar_one_or_none.return_value = cred

        evm_result = MagicMock()
        evm_result.scalar_one_or_none.return_value = None

        db.execute.side_effect = [cred_result, evm_result]

        import json

        response = await get_sbt_metadata(credential_id="cred-abc", db=db)
        data = json.loads(response.body)

        trait_map = {a["trait_type"]: a["value"] for a in data["attributes"]}
        assert trait_map["Ledger Commit ID"] == commit
