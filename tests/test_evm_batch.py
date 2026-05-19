"""
Tests for api/services/evm_batch.py and api/services/evm_mint.py

Covers:
  - queue_mint / queue_burn helpers
  - queue_burn idempotency
  - BurnAuth filtering (owner_only / neither never queued)
  - flush grouping by (chain_id, contract_address)
  - pre-flight ownerOf check marks already-burned tokens as skipped
  - pre-flight wallet-binding check: revoked binding → op skipped, rest proceed
  - pre-flight wallet-binding check: unverified binding → op skipped
  - pre-flight wallet-binding check: null wallet_address → op skipped
  - pre-flight wallet-binding check: all revoked → no tx broadcast
  - mintBatch argument construction (keyIds, burn_auths, etc.)
  - CredentialLedgerEvent creation after confirmation
  - All-or-nothing failure marks ops as failed (skipped ops not overwritten)
  - check_submitted_ops crash-recovery reset
  - holder_key_to_bytes32 helper
  - _evm_event_commit_id determinism
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.models.credential_event import CredentialLedgerEvent
from api.models.evm_pending_op import EvmPendingOp
from api.services import evm_batch
from api.services.evm_mint import holder_key_to_bytes32


# `_precheck_burns` narrowly catches web3's contract-revert exceptions so
# that transient RPC errors propagate.  Use the real type in tests instead
# of a bare `Exception` so the mock matches production semantics.
try:
    from web3.exceptions import ContractLogicError as _ERC721NoToken
except ImportError:  # pragma: no cover — web3 absent only on smoke env
    _ERC721NoToken = Exception  # type: ignore[assignment,misc]


# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _make_db() -> MagicMock:
    """Return a mock async SQLAlchemy session."""
    db = MagicMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.add = MagicMock()
    return db


def _make_result(rows: list) -> MagicMock:
    """Wrap a list of ORM rows in a mock execute() result."""
    result = MagicMock()
    result.scalars.return_value.all.return_value = rows
    result.scalar_one_or_none.return_value = rows[0] if rows else None
    return result


def _pending_mint(
    *,
    credential_id: str = "cred-1",
    ledger_commit_id: str = "0x" + "a" * 64,
    wallet_address: str = "0x" + "1" * 40,
    burn_authorization: str = "issuer_only",
    credential_type: str = "journalist",
    holder_key_id: str | None = "a" * 64,
    token_uri: str = "",
    chain_id: int = 31337,
    contract_address: str = "0x" + "c" * 40,
) -> EvmPendingOp:
    op = EvmPendingOp(
        op_type="mint",
        credential_id=credential_id,
        ledger_commit_id=ledger_commit_id,
        token_id="12345",
        wallet_address=wallet_address,
        holder_key_id=holder_key_id,
        burn_authorization=burn_authorization,
        credential_type=credential_type,
        token_uri=token_uri,
        status="pending",
        queued_at=datetime.now(timezone.utc),
        chain_id=chain_id,
        contract_address=contract_address,
    )
    op.id = "op-mint-1"
    return op


def _pending_burn(
    *,
    credential_id: str = "cred-2",
    ledger_commit_id: str = "0x" + "b" * 64,
    burn_authorization: str = "issuer_only",
    chain_id: int = 31337,
    contract_address: str = "0x" + "c" * 40,
) -> EvmPendingOp:
    op = EvmPendingOp(
        op_type="burn",
        credential_id=credential_id,
        ledger_commit_id=ledger_commit_id,
        token_id="99999",
        burn_authorization=burn_authorization,
        status="pending",
        queued_at=datetime.now(timezone.utc),
        chain_id=chain_id,
        contract_address=contract_address,
    )
    op.id = "op-burn-1"
    return op


# ─── holder_key_to_bytes32 ────────────────────────────────────────────────────


class TestHolderKeyToBytes32:
    def test_none_returns_zero_bytes(self):
        assert holder_key_to_bytes32(None) == b"\x00" * 32

    def test_empty_string_returns_zero_bytes(self):
        assert holder_key_to_bytes32("") == b"\x00" * 32

    def test_32_byte_hex_roundtrips(self):
        raw = bytes(range(32))
        result = holder_key_to_bytes32(raw.hex())
        assert result == raw

    def test_short_key_is_left_padded(self):
        result = holder_key_to_bytes32("aabb")
        assert len(result) == 32
        assert result[-2:] == bytes.fromhex("aabb")
        assert result[:-2] == b"\x00" * 30

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="33 bytes"):
            holder_key_to_bytes32("aa" * 33)


# ─── _evm_event_commit_id ─────────────────────────────────────────────────────


class TestEvmEventCommitId:
    def test_format(self):
        cid = evm_batch._evm_event_commit_id("mint", "0xtxhash", "12345")
        assert cid.startswith("0x")
        assert len(cid) == 66  # "0x" + 64 hex chars

    def test_deterministic(self):
        a = evm_batch._evm_event_commit_id("burn", "0xabc", "999")
        b = evm_batch._evm_event_commit_id("burn", "0xabc", "999")
        assert a == b

    def test_different_inputs_differ(self):
        a = evm_batch._evm_event_commit_id("mint", "0xtx1", "1")
        b = evm_batch._evm_event_commit_id("mint", "0xtx1", "2")
        assert a != b


# ─── queue_mint ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestQueueMint:
    async def test_creates_op_with_correct_fields(self):
        db = _make_db()
        op = await evm_batch.queue_mint(
            db=db,
            credential_id="cred-abc",
            ledger_commit_id="0x" + "a" * 64,
            wallet_address="0x" + "1" * 40,
            burn_authorization="issuer_only",
            credential_type="researcher",
            holder_key_id="f0" * 32,
            token_uri="ipfs://test",
            chain_id=31337,
            contract_address="0xCONTRACT",
        )
        db.add.assert_called_once_with(op)
        assert op.op_type == "mint"
        assert op.status == "pending"
        assert op.holder_key_id == "f0" * 32
        assert op.chain_id == 31337
        assert op.contract_address == "0xCONTRACT"
        assert op.credential_type == "researcher"

    async def test_empty_holder_key_stored_as_none(self):
        db = _make_db()
        op = await evm_batch.queue_mint(
            db=db,
            credential_id="cred-xyz",
            ledger_commit_id="0x" + "b" * 64,
            wallet_address="0x" + "2" * 40,
            burn_authorization="both",
            credential_type="journalist",
            holder_key_id="",
        )
        assert op.holder_key_id is None

    async def test_defaults_chain_and_contract_from_env(self, monkeypatch):
        monkeypatch.setenv("OLYMPUS_EVM_CHAIN_ID", "11155111")
        monkeypatch.setenv("OLYMPUS_EVM_CONTRACT_ADDRESS", "0xDEAD")
        db = _make_db()
        op = await evm_batch.queue_mint(
            db=db,
            credential_id="cred-env",
            ledger_commit_id="0x" + "c" * 64,
            wallet_address="0x" + "3" * 40,
            burn_authorization="issuer_only",
            credential_type="auditor",
        )
        assert op.chain_id == 11155111
        assert op.contract_address == "0xDEAD"


# ─── queue_burn ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestQueueBurn:
    async def test_owner_only_returns_none(self):
        db = _make_db()
        result = await evm_batch.queue_burn(
            db=db,
            credential_id="cred-1",
            ledger_commit_id="0x" + "a" * 64,
            burn_authorization="owner_only",
        )
        assert result is None
        db.add.assert_not_called()

    async def test_neither_returns_none(self):
        db = _make_db()
        result = await evm_batch.queue_burn(
            db=db,
            credential_id="cred-1",
            ledger_commit_id="0x" + "a" * 64,
            burn_authorization="neither",
        )
        assert result is None
        db.add.assert_not_called()

    async def test_issuer_only_creates_op(self):
        db = _make_db()
        db.execute.return_value = _make_result([])  # no existing op

        op = await evm_batch.queue_burn(
            db=db,
            credential_id="cred-2",
            ledger_commit_id="0x" + "b" * 64,
            burn_authorization="issuer_only",
            chain_id=31337,
            contract_address="0xABCD",
        )
        assert op is not None
        db.add.assert_called_once_with(op)
        assert op.op_type == "burn"
        assert op.status == "pending"

    async def test_idempotent_returns_existing_pending(self):
        db = _make_db()
        existing = _pending_burn()
        db.execute.return_value = _make_result([existing])

        result = await evm_batch.queue_burn(
            db=db,
            credential_id=existing.credential_id,
            ledger_commit_id=existing.ledger_commit_id,
            burn_authorization="issuer_only",
        )
        assert result is existing
        db.add.assert_not_called()

    async def test_idempotent_returns_existing_confirmed(self):
        db = _make_db()
        existing = _pending_burn()
        existing.status = "confirmed"
        db.execute.return_value = _make_result([existing])

        result = await evm_batch.queue_burn(
            db=db,
            credential_id=existing.credential_id,
            ledger_commit_id=existing.ledger_commit_id,
            burn_authorization="both",
        )
        assert result is existing
        db.add.assert_not_called()

    async def test_failed_ops_allow_requeuuing(self):
        """A failed burn op must NOT block a new one (it is retried as a fresh row)."""
        db = _make_db()
        # No non-failed existing op.
        db.execute.return_value = _make_result([])

        op = await evm_batch.queue_burn(
            db=db,
            credential_id="cred-failed",
            ledger_commit_id="0x" + "d" * 64,
            burn_authorization="issuer_only",
        )
        assert op is not None
        db.add.assert_called_once()


# ─── flush_pending_burns — empty queue ───────────────────────────────────────


@pytest.mark.asyncio
async def test_flush_pending_burns_empty_queue():
    db = _make_db()
    db.execute.return_value = _make_result([])

    result = await evm_batch.flush_pending_burns(db)

    assert result["submitted"] == 0
    assert result["confirmed"] == 0
    assert result["tx_hash"] is None


# ─── flush_pending_mints — empty queue ────────────────────────────────────────


@pytest.mark.asyncio
async def test_flush_pending_mints_empty_queue():
    db = _make_db()
    db.execute.return_value = _make_result([])

    result = await evm_batch.flush_pending_mints(db)

    assert result["submitted"] == 0
    assert result["confirmed"] == 0
    assert result["tx_hash"] is None


# ─── _make_ledger_events ──────────────────────────────────────────────────────


class TestMakeLedgerEvents:
    def test_mint_creates_evm_minted_events(self):
        ops = [_pending_mint(), _pending_mint(credential_id="cred-2")]
        now = datetime.now(timezone.utc)
        events = evm_batch._make_ledger_events(ops, "mint", "0xtxhash", now)
        assert len(events) == 2
        assert all(e.event_type == "evm_minted" for e in events)
        assert all(e.ledger_commit_id.startswith("0x") for e in events)

    def test_burn_creates_evm_burned_events(self):
        ops = [_pending_burn()]
        now = datetime.now(timezone.utc)
        events = evm_batch._make_ledger_events(ops, "burn", "0xtxhash2", now)
        assert len(events) == 1
        assert events[0].event_type == "evm_burned"

    def test_commit_ids_are_unique_per_op(self):
        op1 = _pending_mint(credential_id="c1")
        op1.token_id = "111"
        op2 = _pending_mint(credential_id="c2")
        op2.token_id = "222"
        now = datetime.now(timezone.utc)
        events = evm_batch._make_ledger_events([op1, op2], "mint", "0xtx", now)
        assert events[0].ledger_commit_id != events[1].ledger_commit_id

    def test_credential_id_matches_op(self):
        op = _pending_mint(credential_id="my-cred")
        events = evm_batch._make_ledger_events([op], "mint", "0xtx", datetime.now(timezone.utc))
        assert events[0].credential_id == "my-cred"


# ─── flush_pending_mints — successful tx (mocked web3) ────────────────────────


@pytest.mark.asyncio
async def test_flush_pending_mints_success_creates_ledger_events():
    """
    Full flush_pending_mints() path:
    - One pending mint op
    - mintBatch tx confirms successfully
    - One CredentialLedgerEvent must be db.add()'d
    - Op status advances to "confirmed"
    """
    op = _pending_mint()
    db = _make_db()
    # Execute sequence:
    #   1. SELECT pending ops
    #   2. UPDATE → submitted  (optimistic lock)
    #   3. SELECT AccountWalletBinding  (_precheck_wallet_bindings)
    #   4. UPDATE → confirmed
    select_result = _make_result([op])
    wallet_ok = _binding_result([op.wallet_address])
    db.execute.side_effect = [select_result, MagicMock(), wallet_ok, MagicMock()]

    fake_receipt = {"status": 1}
    fake_tx_hash = b"\xde\xad\xbe\xef" + b"\x00" * 28  # 32 bytes

    with (
        patch("api.services.evm_batch._get_web3") as mock_w3_factory,
        patch("api.services.evm_batch._build_account_and_contract") as mock_build,
    ):
        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.side_effect = lambda x: x
        mock_w3.eth.get_transaction_count.return_value = 1
        mock_w3.eth.send_raw_transaction.return_value = fake_tx_hash
        mock_w3.eth.wait_for_transaction_receipt.return_value = fake_receipt
        mock_w3_factory.return_value = mock_w3

        mock_account = MagicMock()
        mock_account.address = "0x" + "a" * 40
        mock_account.sign_transaction.return_value = MagicMock(raw_transaction=b"raw")
        mock_contract = MagicMock()
        mock_contract.functions.mintBatch.return_value.build_transaction.return_value = {}
        mock_build.return_value = (mock_account, mock_contract)

        result = await evm_batch.flush_pending_mints(db)

    assert result["confirmed"] == 1
    assert result["failed"] == 0

    # db.add must have been called with a CredentialLedgerEvent.
    added_types = [type(c.args[0]) for c in db.add.call_args_list]
    assert CredentialLedgerEvent in added_types, (
        "Expected a CredentialLedgerEvent to be added after confirmation"
    )
    event = next(
        c.args[0] for c in db.add.call_args_list if isinstance(c.args[0], CredentialLedgerEvent)
    )
    assert event.credential_id == op.credential_id
    assert event.event_type == "evm_minted"
    assert event.ledger_commit_id.startswith("0x")


@pytest.mark.asyncio
async def test_flush_pending_mints_failure_marks_ops_failed():
    """If mintBatch() raises, all ops in the group must be marked failed."""
    op = _pending_mint()
    db = _make_db()
    # Execute sequence:
    #   1. SELECT pending ops
    #   2. UPDATE → submitted
    #   3. SELECT AccountWalletBinding  (_precheck_wallet_bindings — op passes)
    #   4. UPDATE → failed  (exception handler after RPC failure)
    select_result = _make_result([op])
    wallet_ok = _binding_result([op.wallet_address])
    db.execute.side_effect = [select_result, MagicMock(), wallet_ok, MagicMock()]

    with (
        patch("api.services.evm_batch._get_web3") as mock_w3_factory,
        patch("api.services.evm_batch._build_account_and_contract") as mock_build,
    ):
        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.side_effect = lambda x: x
        mock_w3.eth.get_transaction_count.return_value = 1
        mock_w3.eth.send_raw_transaction.side_effect = RuntimeError("RPC down")
        mock_w3_factory.return_value = mock_w3
        mock_build.return_value = (MagicMock(), MagicMock())

        result = await evm_batch.flush_pending_mints(db)

    assert result["failed"] == 1
    assert result["confirmed"] == 0
    # No ledger events should have been added.
    added_types = [type(c.args[0]) for c in db.add.call_args_list]
    assert CredentialLedgerEvent not in added_types


# ─── flush_pending_burns — successful tx (mocked web3) ────────────────────────


@pytest.mark.asyncio
async def test_flush_pending_burns_success_creates_ledger_events():
    """burnBatch() succeeds → CredentialLedgerEvent per confirmed op."""
    op = _pending_burn()
    db = _make_db()
    select_result = _make_result([op])
    db.execute.side_effect = [select_result, MagicMock(), MagicMock(), MagicMock()]

    fake_tx_hash = b"\xca\xfe" + b"\x00" * 30
    fake_receipt = {"status": 1}

    with (
        patch("api.services.evm_batch._get_web3") as mock_w3_factory,
        patch("api.services.evm_batch._build_account_and_contract") as mock_build,
    ):
        mock_w3 = MagicMock()
        mock_contract = MagicMock()
        # Pre-flight ownerOf call — token still exists.
        mock_contract.functions.ownerOf.return_value.call.return_value = "0x" + "a" * 40
        mock_w3.eth.get_transaction_count.return_value = 0
        mock_w3.eth.send_raw_transaction.return_value = fake_tx_hash
        mock_w3.eth.wait_for_transaction_receipt.return_value = fake_receipt
        mock_w3_factory.return_value = mock_w3
        mock_account = MagicMock()
        mock_account.address = "0x" + "f" * 40
        mock_account.sign_transaction.return_value = MagicMock(raw_transaction=b"raw")
        mock_contract.functions.burnBatch.return_value.build_transaction.return_value = {}
        mock_build.return_value = (mock_account, mock_contract)

        result = await evm_batch.flush_pending_burns(db)

    assert result["confirmed"] == 1
    assert result["skipped"] == 0

    added_types = [type(c.args[0]) for c in db.add.call_args_list]
    assert CredentialLedgerEvent in added_types
    event = next(
        c.args[0] for c in db.add.call_args_list if isinstance(c.args[0], CredentialLedgerEvent)
    )
    assert event.event_type == "evm_burned"


@pytest.mark.asyncio
async def test_flush_pending_burns_preflight_skips_already_burned_token():
    """ownerOf() raises → token pre-flight-skipped, not included in burnBatch."""
    op1 = _pending_burn(credential_id="cred-gone")
    op1.id = "gone-id"
    op2 = _pending_burn(credential_id="cred-live")
    op2.id = "live-id"
    op2.token_id = "77777"

    db = _make_db()
    select_result = _make_result([op1, op2])
    db.execute.side_effect = [select_result] + [MagicMock()] * 6

    fake_tx_hash = b"\x00" * 32
    fake_receipt = {"status": 1}

    def ownerOf_side_effect(token_id):
        mock_call = MagicMock()
        if str(token_id) == op1.token_id:
            mock_call.call.side_effect = _ERC721NoToken("ERC721: invalid token ID")
        else:
            mock_call.call.return_value = "0x" + "a" * 40
        return mock_call

    with (
        patch("api.services.evm_batch._get_web3") as mock_w3_factory,
        patch("api.services.evm_batch._build_account_and_contract") as mock_build,
    ):
        mock_w3 = MagicMock()
        mock_contract = MagicMock()
        mock_contract.functions.ownerOf.side_effect = ownerOf_side_effect
        mock_w3.eth.get_transaction_count.return_value = 0
        mock_w3.eth.send_raw_transaction.return_value = fake_tx_hash
        mock_w3.eth.wait_for_transaction_receipt.return_value = fake_receipt
        mock_w3_factory.return_value = mock_w3
        mock_account = MagicMock()
        mock_account.address = "0x" + "e" * 40
        mock_account.sign_transaction.return_value = MagicMock(raw_transaction=b"raw")
        mock_contract.functions.burnBatch.return_value.build_transaction.return_value = {}
        mock_build.return_value = (mock_account, mock_contract)

        result = await evm_batch.flush_pending_burns(db)

    # op1 skipped (pre-flight), op2 confirmed.
    assert result["confirmed"] == 1
    assert result["skipped"] == 1

    # burnBatch must have been called with ONLY op2's token_id.
    burnBatch_call = mock_contract.functions.burnBatch.call_args
    token_ids_sent = burnBatch_call[0][0]
    assert int(op1.token_id) not in token_ids_sent
    assert int(op2.token_id) in token_ids_sent


# ─── Grouping by (chain_id, contract_address) ─────────────────────────────────


@pytest.mark.asyncio
async def test_flush_groups_by_chain_and_contract():
    """Two ops on different chains → two separate mintBatch() calls."""
    op_mainnet = _pending_mint(chain_id=1, contract_address="0x" + "1" * 40)
    op_mainnet.id = "op-mainnet"
    op_anvil = _pending_mint(
        chain_id=31337, contract_address="0x" + "2" * 40, credential_id="cred-anvil"
    )
    op_anvil.id = "op-anvil"

    db = _make_db()
    select_result = _make_result([op_mainnet, op_anvil])
    # Execute sequence (two separate _flush_mint_group calls):
    #   1. SELECT pending ops
    #   2. UPDATE submitted  — group 1
    #   3. SELECT wallet bindings — group 1  (_precheck_wallet_bindings)
    #   4. UPDATE confirmed  — group 1
    #   5. UPDATE submitted  — group 2
    #   6. SELECT wallet bindings — group 2
    #   7. UPDATE confirmed  — group 2
    wallet_ok = _binding_result(["0x" + "1" * 40])
    db.execute.side_effect = [
        select_result,
        MagicMock(),
        wallet_ok,
        MagicMock(),  # group 1
        MagicMock(),
        wallet_ok,
        MagicMock(),  # group 2
    ]

    fake_tx = b"\x00" * 32
    fake_receipt = {"status": 1}

    with (
        patch("api.services.evm_batch._get_web3") as mock_w3_factory,
        patch("api.services.evm_batch._build_account_and_contract") as mock_build,
    ):
        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.side_effect = lambda x: x
        mock_w3.eth.get_transaction_count.return_value = 0
        mock_w3.eth.send_raw_transaction.return_value = fake_tx
        mock_w3.eth.wait_for_transaction_receipt.return_value = fake_receipt
        mock_w3_factory.return_value = mock_w3
        mock_account = MagicMock()
        mock_account.address = "0x" + "f" * 40
        mock_account.sign_transaction.return_value = MagicMock(raw_transaction=b"raw")
        mock_contract = MagicMock()
        mock_contract.functions.mintBatch.return_value.build_transaction.return_value = {}
        mock_build.return_value = (mock_account, mock_contract)

        result = await evm_batch.flush_pending_mints(db)

    # Two groups → mintBatch called twice.
    assert mock_contract.functions.mintBatch.call_count == 2
    assert result.get("groups") == 2
    assert result["confirmed"] == 2


# ─── check_submitted_ops crash recovery ───────────────────────────────────────


@pytest.mark.asyncio
async def test_check_submitted_ops_resets_stale():
    db = _make_db()
    reset_result = MagicMock()
    reset_result.scalars.return_value.all.return_value = ["id-1", "id-2"]
    db.execute.return_value = reset_result

    count = await evm_batch.check_submitted_ops(db, timeout_minutes=5)

    assert count == 2
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_check_submitted_ops_returns_zero_when_nothing_stale():
    db = _make_db()
    reset_result = MagicMock()
    reset_result.scalars.return_value.all.return_value = []
    db.execute.return_value = reset_result

    count = await evm_batch.check_submitted_ops(db)
    assert count == 0


# ─── mintBatch keyId argument construction ────────────────────────────────────


@pytest.mark.asyncio
async def test_flush_mints_passes_correct_key_ids():
    """Verify that the key_ids array passed to mintBatch() matches the ops."""
    holder_key = "bb" * 32  # 64 hex chars = 32 bytes
    op = _pending_mint(holder_key_id=holder_key)
    db = _make_db()
    select_result = _make_result([op])
    # Execute sequence:
    #   1. SELECT pending ops
    #   2. UPDATE → submitted
    #   3. SELECT AccountWalletBinding  (_precheck_wallet_bindings)
    #   4. UPDATE → confirmed
    wallet_ok = _binding_result([op.wallet_address])
    db.execute.side_effect = [select_result, MagicMock(), wallet_ok, MagicMock()]

    fake_tx = b"\x11" * 32
    fake_receipt = {"status": 1}

    with (
        patch("api.services.evm_batch._get_web3") as mock_w3_factory,
        patch("api.services.evm_batch._build_account_and_contract") as mock_build,
    ):
        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.side_effect = lambda x: x
        mock_w3.eth.get_transaction_count.return_value = 0
        mock_w3.eth.send_raw_transaction.return_value = fake_tx
        mock_w3.eth.wait_for_transaction_receipt.return_value = fake_receipt
        mock_w3_factory.return_value = mock_w3
        mock_account = MagicMock()
        mock_account.address = "0x" + "a" * 40
        mock_account.sign_transaction.return_value = MagicMock(raw_transaction=b"raw")
        mock_contract = MagicMock()
        mock_contract.functions.mintBatch.return_value.build_transaction.return_value = {}
        mock_build.return_value = (mock_account, mock_contract)

        await evm_batch.flush_pending_mints(db)

    # Extract the key_ids positional arg sent to mintBatch.
    mintBatch_args = mock_contract.functions.mintBatch.call_args[0]
    # mintBatch(tos, tokenIds, keyIds, burnAuths, credTypes, commitIds, uris)
    key_ids_sent = mintBatch_args[2]
    expected = bytes.fromhex(holder_key)
    assert key_ids_sent[0] == expected


# ─── Authorization: burn only if issuer can burn ─────────────────────────────


@pytest.mark.asyncio
async def test_queue_burn_both_auth_creates_op():
    db = _make_db()
    db.execute.return_value = _make_result([])

    op = await evm_batch.queue_burn(
        db=db,
        credential_id="cred-both",
        ledger_commit_id="0x" + "e" * 64,
        burn_authorization="both",
    )
    assert op is not None
    assert op.op_type == "burn"


@pytest.mark.asyncio
async def test_flush_all_burns_before_mints():
    """flush_all must call flush_pending_burns before flush_pending_mints."""
    call_order: list[str] = []

    async def fake_burns(db, max_batch=50):
        call_order.append("burns")
        return {"submitted": 0, "confirmed": 0, "skipped": 0, "failed": 0, "tx_hash": None}

    async def fake_mints(db, max_batch=50):
        call_order.append("mints")
        return {"submitted": 0, "confirmed": 0, "failed": 0, "tx_hash": None}

    with (
        patch.object(evm_batch, "flush_pending_burns", fake_burns),
        patch.object(evm_batch, "flush_pending_mints", fake_mints),
    ):
        await evm_batch.flush_all(MagicMock())

    assert call_order == ["burns", "mints"]


# ─── _precheck_wallet_bindings ────────────────────────────────────────────────
#
# These tests exercise the pre-flight directly.  The integration tests below
# (flush_pending_mints_*) verify it is wired correctly into _flush_mint_group.


def _binding_result(addresses: list[str]) -> MagicMock:
    """Mock a DB result returning (wallet_address,) rows."""
    result = MagicMock()
    result.all.return_value = [(a,) for a in addresses]
    return result


@pytest.mark.asyncio
class TestPrecheckWalletBindings:
    async def test_valid_binding_survives(self):
        op = _pending_mint(wallet_address="0xABCDEF1234567890" * 2 + "aa")
        db = _make_db()
        # DB returns this address as having a valid binding.
        db.execute.return_value = _binding_result([op.wallet_address])

        now = datetime.now(timezone.utc)
        surviving = await evm_batch._precheck_wallet_bindings(db, [op], now)

        assert surviving == [op]
        db.add.assert_not_called()  # no skipped ops

    async def test_revoked_binding_marks_skipped(self):
        op = _pending_mint(wallet_address="0x" + "2" * 40)
        db = _make_db()
        # DB returns no valid bindings for this address.
        db.execute.return_value = _binding_result([])

        now = datetime.now(timezone.utc)
        surviving = await evm_batch._precheck_wallet_bindings(db, [op], now)

        assert surviving == []
        db.commit.assert_awaited()

        # Can't introspect the SQLAlchemy UPDATE AST easily; just assert that
        # commit was called (meaning the UPDATE was issued) and op was not in
        # the surviving list.
        assert db.execute.call_count >= 2  # SELECT + UPDATE(s)

    async def test_null_wallet_address_marks_skipped(self):
        op = _pending_mint()
        op.wallet_address = None
        db = _make_db()

        now = datetime.now(timezone.utc)
        surviving = await evm_batch._precheck_wallet_bindings(db, [op], now)

        assert surviving == []
        db.commit.assert_awaited()

    async def test_case_insensitive_address_match(self):
        """DB may store address in different case from op; both should match."""
        lower_addr = "0x" + "ab" * 20
        upper_addr = lower_addr.upper()
        op = _pending_mint(wallet_address=lower_addr)
        db = _make_db()
        # DB returns the uppercase variant — should still match.
        db.execute.return_value = _binding_result([upper_addr])

        now = datetime.now(timezone.utc)
        surviving = await evm_batch._precheck_wallet_bindings(db, [op], now)

        assert surviving == [op]

    async def test_mixed_batch_partial_revocation(self):
        """Valid op survives; revoked op is skipped; both in same call."""
        op_valid = _pending_mint(credential_id="cred-good", wallet_address="0x" + "aa" * 20)
        op_valid.id = "good-id"
        op_revoked = _pending_mint(credential_id="cred-bad", wallet_address="0x" + "bb" * 20)
        op_revoked.id = "bad-id"

        db = _make_db()
        # Only the valid address comes back from DB.
        db.execute.return_value = _binding_result([op_valid.wallet_address])

        now = datetime.now(timezone.utc)
        surviving = await evm_batch._precheck_wallet_bindings(db, [op_valid, op_revoked], now)

        assert surviving == [op_valid]
        db.commit.assert_awaited()

    async def test_all_revoked_returns_empty(self):
        ops = [
            _pending_mint(credential_id=f"cred-{i}", wallet_address="0x" + str(i) * 40)
            for i in range(3)
        ]
        db = _make_db()
        db.execute.return_value = _binding_result([])  # none valid

        now = datetime.now(timezone.utc)
        surviving = await evm_batch._precheck_wallet_bindings(db, ops, now)

        assert surviving == []


# ─── Integration: wallet binding revocation inside flush_pending_mints ─────────


@pytest.mark.asyncio
async def test_flush_mints_skips_revoked_binding_no_tx():
    """All ops in the group have revoked bindings → no mintBatch tx is sent."""
    op = _pending_mint()
    db = _make_db()
    select_result = _make_result([op])

    # First execute = SELECT (the pending ops query).
    # Second execute = UPDATE to "submitted".
    # Third execute = SELECT in _precheck_wallet_bindings (returns no valid addresses).
    # Fourth execute = UPDATE to "skipped".
    db.execute.side_effect = [
        select_result,
        MagicMock(),  # submitted UPDATE
        _binding_result([]),  # no valid binding
        MagicMock(),  # skipped UPDATE
    ]

    with (
        patch("api.services.evm_batch._get_web3") as mock_w3_factory,
        patch("api.services.evm_batch._build_account_and_contract") as mock_build,
    ):
        result = await evm_batch.flush_pending_mints(db)

    # No web3 call should have been made.
    mock_w3_factory.assert_not_called()
    mock_build.assert_not_called()

    assert result["confirmed"] == 0
    assert result["skipped"] == 1
    assert result["tx_hash"] is None


@pytest.mark.asyncio
async def test_flush_mints_partial_revocation_mints_valid_subset():
    """One op valid, one revoked → mintBatch sent with only the valid op."""
    op_valid = _pending_mint(credential_id="cred-v", wallet_address="0x" + "aa" * 20)
    op_valid.id = "v-id"
    op_revoked = _pending_mint(credential_id="cred-r", wallet_address="0x" + "bb" * 20)
    op_revoked.id = "r-id"

    db = _make_db()
    select_result = _make_result([op_valid, op_revoked])

    fake_tx = b"\xca\xfe" + b"\x00" * 30
    fake_receipt = {"status": 1}

    db.execute.side_effect = [
        select_result,  # SELECT pending ops
        MagicMock(),  # UPDATE → submitted (both ops)
        _binding_result([op_valid.wallet_address]),  # pre-flight: only valid survives
        MagicMock(),  # UPDATE → skipped (revoked op)
        MagicMock(),  # UPDATE → confirmed (valid op)
    ]

    with (
        patch("api.services.evm_batch._get_web3") as mock_w3_factory,
        patch("api.services.evm_batch._build_account_and_contract") as mock_build,
    ):
        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.side_effect = lambda x: x
        mock_w3.eth.get_transaction_count.return_value = 0
        mock_w3.eth.send_raw_transaction.return_value = fake_tx
        mock_w3.eth.wait_for_transaction_receipt.return_value = fake_receipt
        mock_w3_factory.return_value = mock_w3
        mock_account = MagicMock()
        mock_account.address = "0x" + "f" * 40
        mock_account.sign_transaction.return_value = MagicMock(raw_transaction=b"raw")
        mock_contract = MagicMock()
        mock_contract.functions.mintBatch.return_value.build_transaction.return_value = {}
        mock_build.return_value = (mock_account, mock_contract)

        result = await evm_batch.flush_pending_mints(db)

    assert result["confirmed"] == 1
    assert result["skipped"] == 1
    assert result["failed"] == 0
    assert result["tx_hash"] is not None

    # mintBatch must have been called with only the valid op's wallet address.
    mintBatch_args = mock_contract.functions.mintBatch.call_args[0]
    tos_sent = mintBatch_args[0]
    assert op_valid.wallet_address in tos_sent
    assert op_revoked.wallet_address not in tos_sent


@pytest.mark.asyncio
async def test_flush_mints_revoked_ops_not_overwritten_on_tx_failure():
    """If mintBatch fails after wallet pre-flight, skipped ops keep status='skipped'
    and only the submitted ops that passed pre-flight are marked 'failed'."""
    op_valid = _pending_mint(credential_id="cred-v2", wallet_address="0x" + "cc" * 20)
    op_valid.id = "v2-id"
    op_revoked = _pending_mint(credential_id="cred-r2", wallet_address="0x" + "dd" * 20)
    op_revoked.id = "r2-id"

    db = _make_db()
    select_result = _make_result([op_valid, op_revoked])

    db.execute.side_effect = [
        select_result,
        MagicMock(),  # submitted UPDATE
        _binding_result([op_valid.wallet_address]),  # only valid passes
        MagicMock(),  # skipped UPDATE for revoked
        MagicMock(),  # failed UPDATE for valid
    ]

    with (
        patch("api.services.evm_batch._get_web3") as mock_w3_factory,
        patch("api.services.evm_batch._build_account_and_contract") as mock_build,
    ):
        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.side_effect = lambda x: x
        mock_w3.eth.get_transaction_count.return_value = 0
        mock_w3.eth.send_raw_transaction.side_effect = RuntimeError("node unreachable")
        mock_w3_factory.return_value = mock_w3
        mock_build.return_value = (MagicMock(address="0x" + "a" * 40), MagicMock())

        result = await evm_batch.flush_pending_mints(db)

    # Revoked op was skipped (not failed); valid op was attempted and failed.
    assert result["skipped"] == 1
    assert result["failed"] == 1
    assert result["confirmed"] == 0


@pytest.mark.asyncio
async def test_flush_burns_preflight_skipped_ops_not_overwritten_on_tx_failure():
    """If burnBatch raises after pre-flight, ops already marked 'skipped' keep that
    status — only the surviving (non-skipped) ops are marked 'failed'."""
    op_gone = _pending_burn(credential_id="cred-gone2")
    op_gone.id = "gone2-id"
    op_live = _pending_burn(credential_id="cred-live2")
    op_live.id = "live2-id"
    op_live.token_id = "88888"

    db = _make_db()
    select_result = _make_result([op_gone, op_live])

    db.execute.side_effect = [
        select_result,
        MagicMock(),  # submitted UPDATE for both
        MagicMock(),  # skipped UPDATE for op_gone (inside _precheck_burns)
        MagicMock(),  # failed UPDATE for op_live (inside exception handler)
    ]

    def ownerOf_side_effect(token_id):
        mock_call = MagicMock()
        if str(token_id) == op_gone.token_id:
            mock_call.call.side_effect = _ERC721NoToken("ERC721: invalid token ID")
        else:
            mock_call.call.return_value = "0x" + "a" * 40
        return mock_call

    with (
        patch("api.services.evm_batch._get_web3") as mock_w3_factory,
        patch("api.services.evm_batch._build_account_and_contract") as mock_build,
    ):
        mock_w3 = MagicMock()
        mock_contract = MagicMock()
        mock_contract.functions.ownerOf.side_effect = ownerOf_side_effect
        mock_w3.eth.get_transaction_count.return_value = 0
        mock_w3.eth.send_raw_transaction.side_effect = RuntimeError("rpc down")
        mock_w3_factory.return_value = mock_w3
        mock_account = MagicMock()
        mock_account.address = "0x" + "e" * 40
        mock_account.sign_transaction.return_value = MagicMock(raw_transaction=b"raw")
        mock_contract.functions.burnBatch.return_value.build_transaction.return_value = {}
        mock_build.return_value = (mock_account, mock_contract)

        result = await evm_batch.flush_pending_burns(db)

    # op_gone was pre-flight skipped (not failed); op_live passed pre-flight and failed.
    assert result["skipped"] == 1
    assert result["failed"] == 1
    assert result["confirmed"] == 0
