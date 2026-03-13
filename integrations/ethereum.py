"""Ethereum anchoring helpers for Olympus proof bundles."""

from __future__ import annotations

from typing import Any


ETHEREUM_ANCHOR_CONTRACT = """pragma solidity ^0.8.24;

contract OlympusAnchorRegistry {
    event OlympusCommitmentAnchored(
        string proofId,
        bytes32 contentHash,
        bytes32 merkleRoot,
        bytes32 ledgerEntryHash
    );

    function anchor(
        string calldata proofId,
        bytes32 contentHash,
        bytes32 merkleRoot,
        bytes32 ledgerEntryHash
    ) external {
        emit OlympusCommitmentAnchored(proofId, contentHash, merkleRoot, ledgerEntryHash);
    }
}
"""


def build_ethereum_anchor_payload(proof_bundle: dict[str, Any]) -> dict[str, str]:
    """Convert an Olympus proof bundle into bytes32-friendly EVM calldata."""
    return {
        "proofId": str(proof_bundle.get("proof_id", "")),
        "contentHash": f"0x{proof_bundle['content_hash']}",
        "merkleRoot": f"0x{proof_bundle['merkle_root']}",
        "ledgerEntryHash": f"0x{proof_bundle['ledger_entry_hash']}",
    }
