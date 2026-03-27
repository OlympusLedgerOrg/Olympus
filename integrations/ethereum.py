"""Ethereum anchoring helpers for Olympus proof bundles."""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


ETHEREUM_ANCHOR_CONTRACT = """pragma solidity ^0.8.24;

contract OlympusAnchorRegistry {
    address public owner;
    mapping(address => bool) public allowedSubmitters;

    event OlympusCommitmentAnchored(
        string proofId,
        bytes32 contentHash,
        bytes32 merkleRoot,
        bytes32 ledgerEntryHash
    );

    constructor() {
        owner = msg.sender;
        allowedSubmitters[msg.sender] = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized: owner only");
        _;
    }

    modifier onlyAllowed() {
        require(allowedSubmitters[msg.sender], "Not authorized");
        _;
    }

    function addSubmitter(address submitter) external onlyOwner {
        allowedSubmitters[submitter] = true;
    }

    function removeSubmitter(address submitter) external onlyOwner {
        allowedSubmitters[submitter] = false;
    }

    function anchor(
        string calldata proofId,
        bytes32 contentHash,
        bytes32 merkleRoot,
        bytes32 ledgerEntryHash
    ) external onlyAllowed {
        emit OlympusCommitmentAnchored(proofId, contentHash, merkleRoot, ledgerEntryHash);
    }
}
"""


def validate_anchor_wallet(wallet_address: str) -> None:
    """Validate that *wallet_address* matches the expected anchor address.

    Raises :class:`ValueError` when ``OLYMPUS_ETH_ANCHOR_ADDRESS`` is set and
    *wallet_address* does not match.  This prevents accidental submission from
    an unauthorized wallet.

    Args:
        wallet_address: The wallet address that would submit the anchor tx.

    Raises:
        ValueError: If the wallet address does not match the expected address.
    """
    expected = os.environ.get("OLYMPUS_ETH_ANCHOR_ADDRESS", "").strip().lower()
    if expected and wallet_address.strip().lower() != expected:
        raise ValueError(
            f"Configured wallet {wallet_address} does not match "
            f"expected anchor address {expected}."
        )


def build_ethereum_anchor_payload(
    proof_bundle: dict[str, Any],
    *,
    wallet_address: str | None = None,
) -> dict[str, str]:
    """Convert an Olympus proof bundle into bytes32-friendly EVM calldata.

    When *wallet_address* is provided, it is validated against the
    ``OLYMPUS_ETH_ANCHOR_ADDRESS`` environment variable before building
    the payload.

    Args:
        proof_bundle: Proof bundle dictionary with required hash fields.
        wallet_address: Optional wallet address to validate.

    Returns:
        Dictionary with EVM-compatible calldata fields.

    Raises:
        ValueError: If *wallet_address* does not match the expected anchor address.
    """
    if wallet_address is not None:
        validate_anchor_wallet(wallet_address)

    return {
        "proofId": str(proof_bundle.get("proof_id", "")),
        "contentHash": f"0x{proof_bundle['content_hash']}",
        "merkleRoot": f"0x{proof_bundle['merkle_root']}",
        "ledgerEntryHash": f"0x{proof_bundle['ledger_entry_hash']}",
    }
