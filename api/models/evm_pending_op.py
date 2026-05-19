"""
EvmPendingOp — queue table for batched EVM on-chain operations.

Each row represents one SBT mint or burn that has been authorised at the
Olympus layer but not yet submitted to the chain.  The batch-flush service
(api/services/evm_batch.py) reads `status="pending"` rows, groups them by
(chain_id, contract_address, op_type), and submits a single mintBatch() or
burnBatch() call covering all of them.

Status lifecycle:
    pending   → written when the Olympus-native credential is committed (or revoked)
    submitted → set optimistically before the tx is broadcast (prevents double-submit)
    confirmed → set after the receipt shows status=1
    skipped   → set for burn ops where the token was already burned by its owner
                 (pre-flight ownerOf check catches race conditions) — not retried
    failed    → set if the tx reverted or the RPC call errored; retryable

Grouping:
    Ops are grouped by (chain_id, contract_address) so that a single Olympus
    instance can eventually target multiple chains or contract versions without
    mixing batches.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class EvmPendingOp(Base):
    """A single pending EVM operation waiting to be included in the next batch flush.

    op_type:
        "mint" — mirror an Olympus credential on-chain via mintBatch()
        "burn" — revoke the on-chain mirror via burnBatch()

    Only REVOKER_ROLE-eligible burns (IssuerOnly, Both) should be queued here.
    OwnerOnly / Neither tokens are not issuer-controlled and cannot be batched.
    """

    __tablename__ = "evm_pending_ops"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    op_type: Mapped[str] = mapped_column(String(8), nullable=False, index=True)  # "mint" | "burn"

    # ── Target chain ──────────────────────────────────────────────────────────

    #: EVM chain ID (1 = mainnet, 11155111 = Sepolia, 31337 = Anvil).
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False, default=1, index=True)

    #: Checksummed OlympusCredential contract address this op targets.
    contract_address: Mapped[str] = mapped_column(String(42), nullable=False, index=True)

    # ── Credential identity ───────────────────────────────────────────────────

    credential_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("key_credentials.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ledger_commit_id: Mapped[str] = mapped_column(String(66), nullable=False)

    # ── On-chain payload (resolved at queue time) ─────────────────────────────

    #: uint256 token ID as a decimal string.
    token_id: Mapped[str] = mapped_column(String(78), nullable=False)

    #: Recipient wallet address (mint only).
    wallet_address: Mapped[str | None] = mapped_column(String(42), nullable=True)

    #: Hex-encoded 32-byte Ed25519 public key (64 hex chars, no 0x prefix).
    #: Passed to the contract as bytes32 keyId for duplicate-active-key enforcement.
    #: Mint only; None if the credential has no key binding.
    holder_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    #: Burn authorization string from the Olympus credential (mint only).
    burn_authorization: Mapped[str | None] = mapped_column(String(32), nullable=True)

    #: Human-readable credential type, e.g. "journalist" (mint only).
    credential_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    #: Token metadata URI, e.g. "ipfs://…" (mint only).
    token_uri: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Lifecycle status ──────────────────────────────────────────────────────

    status: Mapped[str] = mapped_column(String(12), nullable=False, default="pending", index=True)
    queued_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    #: Covers all ops in the same flush batch — set after broadcast.
    batch_tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True, index=True)

    #: Non-null when status="failed" or status="skipped".
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
