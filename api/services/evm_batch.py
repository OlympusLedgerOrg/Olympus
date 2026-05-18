"""
EVM batch flush service — coalesces pending SBT mints and burns into single
on-chain transactions using OlympusCredential.mintBatch() / burnBatch().

Design invariants
-----------------
* Python writes EvmPendingOp rows with status="pending" synchronously when a
  credential is issued or revoked.  This module is the only code that advances
  those rows to submitted / confirmed / skipped / failed.

* Ops are grouped by (chain_id, contract_address, op_type) before flushing.
  This lets a single Olympus instance serve multiple chains or contract
  versions without cross-contaminating batches.

* Optimistic status advance: ops are marked "submitted" *before* the tx is
  broadcast.  If the process crashes after broadcast but before the receipt,
  the row stays "submitted" and can be reconciled by check_submitted_ops().

* burnBatch() on the contract is all-or-nothing (reverts if any token cannot
  be issuer-burned).  A pre-flight ownerOf check is performed before broadcast:
  tokens that are already owner-burned are marked "skipped" and removed from
  the batch so the remaining tokens still go through in one tx.

* mintBatch() is all-or-nothing.  A failed mint batch marks all included ops
  as "failed" and leaves them retryable.

* Wallet-binding validity is verified at transaction-construction time, not
  only at queue time.  If an AccountWalletBinding is revoked between queue and
  flush, the affected op is marked "skipped" and excluded from the batch so the
  remaining valid ops still proceed.  The Olympus-native credential is
  unaffected; the operator can re-queue an EVM mint once the holder creates a
  new binding.

* After a batch is confirmed on-chain, one CredentialLedgerEvent row is
  written per logical op so the on-chain action is reflected in the Olympus
  audit trail.

* queue_burn() is idempotent: if a pending, submitted, or confirmed burn
  already exists for the same credential, the existing op is returned.

Public API
----------
    queue_mint(...)           → create a pending "mint" op
    queue_burn(...)           → create a pending "burn" op (idempotent)
    flush_pending_burns(db)   → submit all pending burns as burnBatch tx(es)
    flush_pending_mints(db)   → submit all pending mints as mintBatch tx(es)
    flush_all(db)             → burns first, then mints
    check_submitted_ops(db)   → crash-recovery: reset stale "submitted" ops
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from itertools import groupby

from sqlalchemy import func, select, update
from web3.exceptions import BadFunctionCallOutput, ContractLogicError

from api.models.credential_event import CredentialLedgerEvent
from api.models.evm_pending_op import EvmPendingOp
from api.models.signing_key import AccountWalletBinding
from api.services.evm_mint import (
    _BURN_AUTH_MAP,
    _CONTRACT_ABI,
    _build_account_and_contract,
    _get_web3,
    derive_token_id,
    holder_key_to_bytes32,
)
from protocol.hashes import HASH_SEPARATOR, hash_string


logger = logging.getLogger(__name__)

_DEFAULT_MAX_BATCH = int(os.environ.get("OLYMPUS_EVM_MAX_BATCH", "50"))
_GAS_PER_BURN = 35_000  # approximate marginal gas per burn in a batch
_GAS_PER_MINT = 130_000  # approximate marginal gas per mint (strings + keyId)
_GAS_BASE = 50_000  # base tx overhead


# ─── Batch ABI ────────────────────────────────────────────────────────────────

_BATCH_ABI = [
    *_CONTRACT_ABI,
    {
        "name": "mintBatch",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "tos", "type": "address[]"},
            {"name": "tokenIds", "type": "uint256[]"},
            {"name": "keyIds", "type": "bytes32[]"},
            {"name": "burnAuths", "type": "uint8[]"},
            {"name": "credentialTypes", "type": "string[]"},
            {"name": "ledgerCommitIds", "type": "string[]"},
            {"name": "uris", "type": "string[]"},
        ],
        "outputs": [],
    },
    {
        "name": "burnBatch",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "tokenIds", "type": "uint256[]"}],
        "outputs": [],
    },
    {
        "name": "activeTokenByKeyId",
        "type": "function",
        "stateMutability": "view",
        "inputs": [{"name": "keyId", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
]


# ─── Env defaults ─────────────────────────────────────────────────────────────


def _default_chain_id() -> int:
    return int(os.environ.get("OLYMPUS_EVM_CHAIN_ID", "1"))


def _default_contract_address() -> str:
    return os.environ.get("OLYMPUS_EVM_CONTRACT_ADDRESS", "")


# ─── Ledger commit ID derivation for on-chain events ─────────────────────────


def _evm_event_commit_id(op_type: str, tx_hash: str, token_id: str) -> str:
    """Derive a deterministic ledger_commit_id for an on-chain batch event row.

    Uses BLAKE3 via ``protocol.hashes.hash_string`` over a HASH_SEPARATOR-joined
    canonical binding so the ID is reproducible and unique per
    (op_type, tx_hash, token_id) triple.  Matches the repo-wide hashing
    convention (CLAUDE.md).

    Returns:
        "0x" + 64 hex chars (BLAKE3 digest).
    """
    raw = HASH_SEPARATOR.join(["olympus:evm-event:v1", op_type, tx_hash, token_id])
    return "0x" + hash_string(raw).hex()


# ─── Queue helpers ────────────────────────────────────────────────────────────


async def queue_mint(
    *,
    db,
    credential_id: str,
    ledger_commit_id: str,
    wallet_address: str,
    burn_authorization: str,
    credential_type: str,
    holder_key_id: str | None = None,
    token_uri: str = "",
    chain_id: int = 0,
    contract_address: str = "",
) -> EvmPendingOp:
    """Enqueue a mint operation.

    Args:
        holder_key_id: 64-char hex Ed25519 public key (no 0x prefix), or None.
                       Passed to mintBatch() as bytes32 keyId for duplicate-
                       active-key enforcement on the contract.
        chain_id:      EVM chain ID; defaults to OLYMPUS_EVM_CHAIN_ID env var.
        contract_address: OlympusCredential contract address; defaults to
                           OLYMPUS_EVM_CONTRACT_ADDRESS env var.

    Note:
        Caller is responsible for db.commit().
    """
    token_id = derive_token_id(credential_id, ledger_commit_id)
    op = EvmPendingOp(
        op_type="mint",
        credential_id=credential_id,
        ledger_commit_id=ledger_commit_id,
        token_id=str(token_id),
        wallet_address=wallet_address,
        holder_key_id=holder_key_id or None,
        burn_authorization=burn_authorization,
        credential_type=credential_type,
        token_uri=token_uri,
        status="pending",
        queued_at=datetime.now(timezone.utc),
        chain_id=chain_id or _default_chain_id(),
        contract_address=contract_address or _default_contract_address(),
    )
    db.add(op)
    return op


async def queue_burn(
    *,
    db,
    credential_id: str,
    ledger_commit_id: str,
    burn_authorization: str,
    chain_id: int = 0,
    contract_address: str = "",
) -> EvmPendingOp | None:
    """Enqueue a burn operation.

    Returns None if the token's BurnAuth cannot be issuer-burned (OwnerOnly /
    Neither tokens must be burned directly by the holder).

    Idempotent: if a burn op for this credential already exists with status
    pending, submitted, confirmed, or skipped, the existing row is returned
    without creating a duplicate.

    Note:
        Caller is responsible for db.commit().
    """
    if burn_authorization in ("owner_only", "neither"):
        logger.debug(
            "Skipping burn queue for credential %s — burn_authorization=%s",
            credential_id,
            burn_authorization,
        )
        return None

    # Idempotency check: return any existing non-failed burn for this credential.
    result = await db.execute(
        select(EvmPendingOp).where(
            EvmPendingOp.credential_id == credential_id,
            EvmPendingOp.op_type == "burn",
            EvmPendingOp.status.in_(["pending", "submitted", "confirmed", "skipped"]),
        )
    )
    existing = result.scalar_one_or_none()
    if existing is not None:
        logger.debug(
            "Burn for credential %s already exists (id=%s status=%s) — no duplicate created",
            credential_id,
            existing.id,
            existing.status,
        )
        return existing  # type: ignore[no-any-return]

    token_id = derive_token_id(credential_id, ledger_commit_id)
    op = EvmPendingOp(
        op_type="burn",
        credential_id=credential_id,
        ledger_commit_id=ledger_commit_id,
        token_id=str(token_id),
        burn_authorization=burn_authorization,
        status="pending",
        queued_at=datetime.now(timezone.utc),
        chain_id=chain_id or _default_chain_id(),
        contract_address=contract_address or _default_contract_address(),
    )
    db.add(op)
    return op


# ─── Pre-flight helpers ───────────────────────────────────────────────────────


async def _precheck_burns(
    w3,
    contract,
    ops: list[EvmPendingOp],
    db,
    now: datetime,
) -> list[EvmPendingOp]:
    """Remove already-owner-burned tokens from the batch before submitting.

    burnBatch() is all-or-nothing on the contract.  If a token was burned by
    its holder between the time it was queued and the flush, the contract would
    revert the whole batch.  This pre-flight eliminates those tokens, marks them
    "skipped" in the DB, and returns the surviving ops.

    An ownerOf() revert (token does not exist) or a zero-address owner both
    indicate the token is gone.
    """
    surviving: list[EvmPendingOp] = []
    skipped_ids: list[str] = []

    for op in ops:
        token_id = int(op.token_id)
        gone = False
        try:
            owner = await asyncio.to_thread(contract.functions.ownerOf(token_id).call)
            if owner == "0x0000000000000000000000000000000000000000":
                gone = True
        except (BadFunctionCallOutput, ContractLogicError):
            # ownerOf reverts for non-existent tokens — that's the only
            # signal we treat as "already burned".  Transient RPC errors
            # (ConnectionError, TimeExhausted, gateway 5xx) must propagate
            # so the surrounding _flush_burn_group handler can mark the op
            # `failed` (retryable) instead of `skipped` (terminal).
            gone = True

        if gone:
            skipped_ids.append(op.id)
            logger.debug(
                "Pre-flight: token %s for credential %s not found on-chain — skipping",
                token_id,
                op.credential_id,
            )
        else:
            surviving.append(op)

    if skipped_ids:
        await db.execute(
            update(EvmPendingOp)
            .where(EvmPendingOp.id.in_(skipped_ids))
            .values(
                status="skipped",
                confirmed_at=now,
                error="token already burned by owner (pre-flight check)",
            )
        )
        await db.commit()

    return surviving


async def _precheck_wallet_bindings(
    db,
    ops: list[EvmPendingOp],
    now: datetime,
) -> list[EvmPendingOp]:
    """Verify each mint op's wallet address still has a valid, non-revoked binding.

    An AccountWalletBinding can be revoked after a mint is queued.  Minting to
    a revoked address would write an unauthorized address permanently onto the
    chain (SBTs are non-transferable), so we verify at transaction-construction
    time — not only at queue time.

    Validity criteria for AccountWalletBinding:
        verified_at IS NOT NULL  — the EIP-191 challenge was actually completed
        revoked_at IS NULL       — the holder has not explicitly de-authorized it

    We check whether the wallet_address has ANY currently valid binding (across
    all signing keys for that address).  If the holder revoked the specific
    binding that was used for issuance but created a new one for the same
    wallet, the address is still considered authorized.

    Ops whose wallet_address has no valid binding, or whose wallet_address is
    null, are marked "skipped" — not "failed".  "skipped" is appropriate
    because:
        • The Olympus-native credential is unaffected.
        • The condition is not transient; retrying without a new binding would
          produce the same result.
        • The operator can re-queue an EVM mint once the holder creates a fresh
          AccountWalletBinding for the same or a different address.

    Returns:
        The subset of `ops` whose wallet binding is still valid.
    """
    surviving: list[EvmPendingOp] = []
    null_addr_ids: list[str] = []
    needs_check: list[EvmPendingOp] = []

    for op in ops:
        if not op.wallet_address:
            null_addr_ids.append(op.id)
        else:
            needs_check.append(op)

    valid_addresses: set[str] = set()
    if needs_check:
        lower_addresses = [op.wallet_address.lower() for op in needs_check if op.wallet_address]

        result = await db.execute(
            select(AccountWalletBinding.wallet_address).where(
                func.lower(AccountWalletBinding.wallet_address).in_(lower_addresses),
                AccountWalletBinding.verified_at.is_not(None),
                AccountWalletBinding.revoked_at.is_(None),
            )
        )
        valid_addresses = {row[0].lower() for row in result.all()}

    revoked_ids: list[str] = []
    for op in needs_check:
        if op.wallet_address and op.wallet_address.lower() in valid_addresses:
            surviving.append(op)
        else:
            revoked_ids.append(op.id)

    # Persist skipped status for null-address and revoked-binding ops.
    if null_addr_ids:
        await db.execute(
            update(EvmPendingOp)
            .where(EvmPendingOp.id.in_(null_addr_ids))
            .values(
                status="skipped",
                confirmed_at=now,
                error="wallet_address is null on mint op",
            )
        )
        logger.error(
            "Pre-flight: %d mint op(s) have null wallet_address — skipped",
            len(null_addr_ids),
        )

    if revoked_ids:
        await db.execute(
            update(EvmPendingOp)
            .where(EvmPendingOp.id.in_(revoked_ids))
            .values(
                status="skipped",
                confirmed_at=now,
                error="wallet binding revoked or missing at flush time",
            )
        )
        logger.warning(
            "Pre-flight: %d mint op(s) had wallet binding revoked since queue time — skipped",
            len(revoked_ids),
        )

    if null_addr_ids or revoked_ids:
        await db.commit()

    return surviving


# ─── Ledger event helpers ─────────────────────────────────────────────────────


def _make_ledger_events(
    ops: list[EvmPendingOp],
    op_type: str,
    tx_hash: str,
    now: datetime,
) -> list[CredentialLedgerEvent]:
    """Build one CredentialLedgerEvent per op in a confirmed batch.

    event_type:
        "evm_minted" — credential SBT minted on-chain via mintBatch()
        "evm_burned" — credential SBT revoked on-chain via burnBatch()

    The ledger_commit_id is derived deterministically so it is reproducible
    by any verifier with the tx_hash and token_id.
    """
    event_type = "evm_minted" if op_type == "mint" else "evm_burned"
    return [
        CredentialLedgerEvent(
            id=str(uuid.uuid4()),
            credential_id=op.credential_id,
            event_type=event_type,
            ledger_commit_id=_evm_event_commit_id(op_type, tx_hash, op.token_id),
            created_at=now,
        )
        for op in ops
    ]


# ─── Per-group flush helpers ──────────────────────────────────────────────────


async def _flush_burn_group(
    db,
    ops: list[EvmPendingOp],
    chain_id: int,
    contract_address: str,
) -> dict:
    """Submit a burnBatch() for a single (chain_id, contract_address) group."""
    op_ids = [op.id for op in ops]
    now = datetime.now(timezone.utc)

    # Optimistic status advance before broadcast.
    await db.execute(
        update(EvmPendingOp)
        .where(EvmPendingOp.id.in_(op_ids))
        .values(status="submitted", submitted_at=now)
    )
    await db.commit()

    surviving: list[EvmPendingOp] = []
    try:
        w3 = _get_web3()
        account, contract = _build_account_and_contract(w3, abi=_BATCH_ABI)

        # Pre-flight: remove tokens already burned by their owners.
        surviving = await _precheck_burns(w3, contract, ops, db, now)
        if not surviving:
            logger.info("burnBatch: all %d ops were pre-flight skipped", len(ops))
            return {
                "submitted": len(ops),
                "confirmed": 0,
                "skipped": len(ops),
                "failed": 0,
                "tx_hash": None,
            }

        surviving_ids = [op.id for op in surviving]
        surviving_token_ids = [int(op.token_id) for op in surviving]
        timeout = int(os.environ.get("OLYMPUS_EVM_TX_TIMEOUT", "120"))
        gas_limit = _GAS_BASE + _GAS_PER_BURN * len(surviving_token_ids)

        nonce = await asyncio.to_thread(w3.eth.get_transaction_count, account.address, "pending")
        tx = contract.functions.burnBatch(surviving_token_ids).build_transaction(
            {
                "from": account.address,
                "nonce": nonce,
                "gas": gas_limit,
            }
        )
        signed = account.sign_transaction(tx)
        raw_hash = await asyncio.to_thread(w3.eth.send_raw_transaction, signed.raw_transaction)
        tx_hash = "0x" + raw_hash.hex()

        receipt = await asyncio.to_thread(w3.eth.wait_for_transaction_receipt, raw_hash, timeout)
        if receipt["status"] != 1:
            raise RuntimeError(f"burnBatch reverted on-chain. tx={tx_hash}")

        now = datetime.now(timezone.utc)
        await db.execute(
            update(EvmPendingOp)
            .where(EvmPendingOp.id.in_(surviving_ids))
            .values(status="confirmed", confirmed_at=now, batch_tx_hash=tx_hash)
        )
        for event in _make_ledger_events(surviving, "burn", tx_hash, now):
            db.add(event)
        await db.commit()

        skipped_count = len(ops) - len(surviving)
        logger.info(
            "burnBatch chain=%d contract=%s tx=%s confirmed=%d pre-skipped=%d",
            chain_id,
            contract_address,
            tx_hash,
            len(surviving),
            skipped_count,
        )
        return {
            "submitted": len(ops),
            "confirmed": len(surviving),
            "skipped": skipped_count,
            "failed": 0,
            "tx_hash": tx_hash,
        }

    except Exception as exc:
        logger.exception("burnBatch flush failed — marking ops as failed")
        # Only mark ops that passed pre-flight as failed; pre-flight skipped ops already
        # have a terminal "skipped" status and must not be overwritten.
        _surviving_ids: set[str] = {op.id for op in surviving} if surviving else set(op_ids)
        failed_ids = [oid for oid in op_ids if oid in _surviving_ids]
        skipped_count = len(ops) - len(failed_ids)
        if failed_ids:
            await db.execute(
                update(EvmPendingOp)
                .where(EvmPendingOp.id.in_(failed_ids))
                .values(status="failed", error=str(exc))
            )
            await db.commit()
        return {
            "submitted": len(ops),
            "confirmed": 0,
            "skipped": skipped_count,
            "failed": len(failed_ids),
            "tx_hash": None,
        }


async def _flush_mint_group(
    db,
    ops: list[EvmPendingOp],
    chain_id: int,
    contract_address: str,
) -> dict:
    """Submit a mintBatch() for a single (chain_id, contract_address) group.

    Pre-flight steps (before broadcast):
        1. Mark all ops "submitted" optimistically (prevents double-submit).
        2. Verify each op's wallet_address still has a valid AccountWalletBinding.
           Ops with revoked or missing bindings are marked "skipped" immediately.
        3. Build and broadcast mintBatch() with the surviving ops only.
    """
    op_ids = [op.id for op in ops]
    now = datetime.now(timezone.utc)

    # ── Step 1: optimistic status advance ────────────────────────────────────
    await db.execute(
        update(EvmPendingOp)
        .where(EvmPendingOp.id.in_(op_ids))
        .values(status="submitted", submitted_at=now)
    )
    await db.commit()

    surviving: list[EvmPendingOp] = []  # populated by pre-flight; used in except
    try:
        # ── Step 2: wallet binding pre-flight ────────────────────────────────
        # Must happen before building the web3 arrays so we never pass a
        # revoked address to the contract.
        surviving = await _precheck_wallet_bindings(db, ops, now)

        if not surviving:
            skipped_count = len(ops)
            logger.info(
                "mintBatch: all %d ops skipped (wallet bindings invalid) — no tx sent",
                skipped_count,
            )
            return {
                "submitted": len(ops),
                "confirmed": 0,
                "skipped": skipped_count,
                "failed": 0,
                "tx_hash": None,
            }

        surviving_ids = [op.id for op in surviving]

        # ── Step 3: build and broadcast ──────────────────────────────────────
        w3 = _get_web3()
        account, contract = _build_account_and_contract(w3, abi=_BATCH_ABI)
        timeout = int(os.environ.get("OLYMPUS_EVM_TX_TIMEOUT", "120"))
        # Gas is proportional to surviving ops, not the original batch size.
        gas_limit = _GAS_BASE + _GAS_PER_MINT * len(surviving)

        tos = [w3.to_checksum_address(op.wallet_address) for op in surviving]
        token_ids = [int(op.token_id) for op in surviving]
        key_ids = [holder_key_to_bytes32(op.holder_key_id) for op in surviving]
        burn_auths = [
            int(_BURN_AUTH_MAP[op.burn_authorization or "issuer_only"]) for op in surviving
        ]
        cred_types = [op.credential_type or "" for op in surviving]
        commit_ids = [op.ledger_commit_id for op in surviving]
        uris = [op.token_uri or "" for op in surviving]

        nonce = await asyncio.to_thread(w3.eth.get_transaction_count, account.address, "pending")
        tx = contract.functions.mintBatch(
            tos, token_ids, key_ids, burn_auths, cred_types, commit_ids, uris
        ).build_transaction(
            {
                "from": account.address,
                "nonce": nonce,
                "gas": gas_limit,
            }
        )
        signed = account.sign_transaction(tx)
        raw_hash = await asyncio.to_thread(w3.eth.send_raw_transaction, signed.raw_transaction)
        tx_hash = "0x" + raw_hash.hex()

        receipt = await asyncio.to_thread(w3.eth.wait_for_transaction_receipt, raw_hash, timeout)
        if receipt["status"] != 1:
            raise RuntimeError(f"mintBatch reverted on-chain. tx={tx_hash}")

        now = datetime.now(timezone.utc)
        await db.execute(
            update(EvmPendingOp)
            .where(EvmPendingOp.id.in_(surviving_ids))
            .values(status="confirmed", confirmed_at=now, batch_tx_hash=tx_hash)
        )
        for event in _make_ledger_events(surviving, "mint", tx_hash, now):
            db.add(event)
        await db.commit()

        skipped_count = len(ops) - len(surviving)
        logger.info(
            "mintBatch chain=%d contract=%s tx=%s confirmed=%d wallet-skipped=%d",
            chain_id,
            contract_address,
            tx_hash,
            len(surviving),
            skipped_count,
        )
        return {
            "submitted": len(ops),
            "confirmed": len(surviving),
            "skipped": skipped_count,
            "failed": 0,
            "tx_hash": tx_hash,
        }

    except Exception as exc:
        logger.exception("mintBatch flush failed — marking ops as failed")
        # `surviving` holds the ops that passed the wallet-binding pre-flight.
        # Those are the only ones that were attempted; mark them failed.
        # Ops already marked "skipped" by _precheck_wallet_bindings are
        # excluded — they have a terminal status and must not be overwritten.
        _exc_surviving_ids: set[str] = {op.id for op in surviving}
        failed_ids: list[str] = [op.id for op in ops if op.id in _exc_surviving_ids]
        skipped_count = len(ops) - len(failed_ids)

        if failed_ids:
            await db.execute(
                update(EvmPendingOp)
                .where(EvmPendingOp.id.in_(failed_ids))
                .values(status="failed", error=str(exc))
            )
            await db.commit()

        return {
            "submitted": len(ops),
            "confirmed": 0,
            "skipped": skipped_count,
            "failed": len(failed_ids),
            "tx_hash": None,
        }


# ─── Public flush API ─────────────────────────────────────────────────────────


async def flush_pending_burns(db, max_batch: int = _DEFAULT_MAX_BATCH) -> dict:
    """Collect up to `max_batch` pending burns, group by (chain_id, contract_address),
    and submit one burnBatch() tx per group.

    Returns an aggregate summary dict.
    """
    result = await db.execute(
        select(EvmPendingOp)
        .where(EvmPendingOp.op_type == "burn", EvmPendingOp.status == "pending")
        .order_by(EvmPendingOp.chain_id, EvmPendingOp.contract_address, EvmPendingOp.queued_at)
        .limit(max_batch)
        .with_for_update(skip_locked=True)
    )
    ops = result.scalars().all()
    if not ops:
        return {"submitted": 0, "confirmed": 0, "skipped": 0, "failed": 0, "tx_hash": None}

    total: dict = {"submitted": 0, "confirmed": 0, "skipped": 0, "failed": 0}
    group_results: list[dict] = []

    def _group_key(op: EvmPendingOp) -> tuple[int, str]:
        return (op.chain_id, (op.contract_address or "").lower())

    for (chain_id, contract_address), group_iter in groupby(ops, key=_group_key):
        group_ops = list(group_iter)
        r = await _flush_burn_group(db, group_ops, chain_id, contract_address)
        for k in ("submitted", "confirmed", "skipped", "failed"):
            total[k] += r.get(k, 0)
        group_results.append(r)

    last_hash = next((r["tx_hash"] for r in reversed(group_results) if r.get("tx_hash")), None)
    return {**total, "tx_hash": last_hash, "groups": len(group_results)}


async def flush_pending_mints(db, max_batch: int = _DEFAULT_MAX_BATCH) -> dict:
    """Collect up to `max_batch` pending mints, group by (chain_id, contract_address),
    and submit one mintBatch() tx per group.

    mintBatch is all-or-nothing per group.
    """
    result = await db.execute(
        select(EvmPendingOp)
        .where(EvmPendingOp.op_type == "mint", EvmPendingOp.status == "pending")
        .order_by(EvmPendingOp.chain_id, EvmPendingOp.contract_address, EvmPendingOp.queued_at)
        .limit(max_batch)
        .with_for_update(skip_locked=True)
    )
    ops = result.scalars().all()
    if not ops:
        return {"submitted": 0, "confirmed": 0, "skipped": 0, "failed": 0, "tx_hash": None}

    total: dict = {"submitted": 0, "confirmed": 0, "skipped": 0, "failed": 0}
    group_results: list[dict] = []

    def _group_key(op: EvmPendingOp) -> tuple[int, str]:
        return (op.chain_id, (op.contract_address or "").lower())

    for (chain_id, contract_address), group_iter in groupby(ops, key=_group_key):
        group_ops = list(group_iter)
        r = await _flush_mint_group(db, group_ops, chain_id, contract_address)
        for k in ("submitted", "confirmed", "skipped", "failed"):
            total[k] += r.get(k, 0)
        group_results.append(r)

    last_hash = next((r["tx_hash"] for r in reversed(group_results) if r.get("tx_hash")), None)
    return {**total, "tx_hash": last_hash, "groups": len(group_results)}


async def flush_all(db, max_batch: int = _DEFAULT_MAX_BATCH) -> dict:
    """Flush pending burns then pending mints in one call.

    Burns go first so revoked credentials are removed from supply before new
    ones are added — keeping on-chain supply consistent with Olympus state.
    """
    burns = await flush_pending_burns(db, max_batch)
    mints = await flush_pending_mints(db, max_batch)
    return {"burns": burns, "mints": mints}


async def check_submitted_ops(db, timeout_minutes: int = 10) -> int:
    """Reset ops that were marked 'submitted' but never got a tx hash (crash recovery).

    Any op that has been 'submitted' for longer than `timeout_minutes` without a
    batch_tx_hash is reset to 'pending' so the next flush picks it up.  Ops that
    have a batch_tx_hash but no confirmed_at may need manual receipt reconciliation
    (they were broadcast but we crashed before recording the receipt).

    Returns the number of ops reset to pending.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=timeout_minutes)
    result = await db.execute(
        update(EvmPendingOp)
        .where(
            EvmPendingOp.status == "submitted",
            EvmPendingOp.batch_tx_hash.is_(None),
            EvmPendingOp.submitted_at < cutoff,
        )
        .values(status="pending", submitted_at=None)
        .returning(EvmPendingOp.id)
    )
    reset_ids = result.scalars().all()
    await db.commit()
    if reset_ids:
        logger.warning("Reset %d stale submitted ops to pending", len(reset_ids))
    return len(reset_ids)
