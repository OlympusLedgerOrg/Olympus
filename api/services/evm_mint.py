"""
EVM mint service — OPTIONAL ERC-5484 on-chain mirror for Olympus credentials.

Olympus-native credentials (KeyCredential) are account-bound and signing-key-bound
without any Ethereum dependency.  This module is an OPTIONAL layer that mirrors an
already-issued Olympus credential onto an EVM chain as an ERC-5484 soulbound token.

Calling order (strict):
    1. Holder completes Ed25519 consent flow:
           POST /key/signing/{key_id}/consent/challenge
           POST /key/signing/{key_id}/consent/{id}/accept
    2. Issuer calls POST /key/credential (with consent_id) → KeyCredential created.
       This is the authoritative record, verifiable via Olympus SMT proof — no chain needed.
    3. [OPTIONAL] Holder binds an Ethereum wallet:
           POST /key/signing/{key_id}/wallet/challenge
           POST /key/signing/{key_id}/wallet/verify
    4. [OPTIONAL] Call mint_credential_on_chain() to project the credential on-chain.

Omitting steps 3–4 does NOT affect the Olympus-native credential.  The on-chain
token is a convenience projection, not the authoritative source of truth.

Language-boundary rule: Python owns orchestration and all DB side-effects.
This module never computes cryptographic hashes or persists Ethereum private keys.

Required env vars (only if using the ERC-5484 mirror)
------------------------------------------------------
OLYMPUS_EVM_CONTRACT_ADDRESS  — checksummed deployed OlympusCredential address
OLYMPUS_EVM_RPC_URL           — JSON-RPC endpoint (Anvil, Infura, Alchemy, etc.)
OLYMPUS_EVM_HOT_WALLET_KEY    — hex private key holding ISSUER_ROLE / REVOKER_ROLE

Optional
--------
OLYMPUS_EVM_GAS_LIMIT_MINT   — gas limit for mint txs (default 300 000)
OLYMPUS_EVM_GAS_LIMIT_BURN   — gas limit for burn txs (default 150 000)
OLYMPUS_EVM_TX_TIMEOUT       — seconds to wait for receipt (default 120)
"""

from __future__ import annotations

import hashlib
import logging
import os
from enum import IntEnum


logger = logging.getLogger(__name__)

# ─── BurnAuth ─────────────────────────────────────────────────────────────────


class BurnAuth(IntEnum):
    """Mirrors the Solidity IERC5484.BurnAuth enum (values must stay in sync)."""

    ISSUER_ONLY = 0
    OWNER_ONLY = 1
    BOTH = 2
    NEITHER = 3


_BURN_AUTH_MAP: dict[str, BurnAuth] = {
    "issuer_only": BurnAuth.ISSUER_ONLY,
    "owner_only": BurnAuth.OWNER_ONLY,
    "both": BurnAuth.BOTH,
    "neither": BurnAuth.NEITHER,
}

# ─── ABI (minimal — only functions this service calls) ────────────────────────

_CONTRACT_ABI = [
    {
        "name": "mint",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "tokenId", "type": "uint256"},
            {"name": "keyId", "type": "bytes32"},
            {"name": "burnAuth_", "type": "uint8"},
            {"name": "credentialType", "type": "string"},
            {"name": "ledgerCommitId", "type": "string"},
            {"name": "uri", "type": "string"},
        ],
        "outputs": [],
    },
    {
        "name": "burn",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "tokenId", "type": "uint256"}],
        "outputs": [],
    },
    {
        "name": "ownerOf",
        "type": "function",
        "stateMutability": "view",
        "inputs": [{"name": "tokenId", "type": "uint256"}],
        "outputs": [{"name": "", "type": "address"}],
    },
    {
        "name": "burnAuth",
        "type": "function",
        "stateMutability": "view",
        "inputs": [{"name": "tokenId", "type": "uint256"}],
        "outputs": [{"name": "", "type": "uint8"}],
    },
]

# ─── Token ID derivation ──────────────────────────────────────────────────────


def derive_token_id(credential_id: str, ledger_commit_id: str) -> int:
    """Derive a deterministic uint256 token ID from an Olympus credential.

    Uses SHA-256 over a canonical binding string so the ID is reproducible by
    any verifier with access to the ledger record, without querying the chain.

    Args:
        credential_id:    Olympus credential UUID (from key_credentials.id).
        ledger_commit_id: Olympus ledger commit hash (key_credentials.commit_id).

    Returns:
        A non-zero uint256 token ID.  Collision probability is negligible
        (SHA-256 pre-image resistance) over realistic credential volumes.
    """
    raw = f"olympus:sbt:v1:{credential_id}:{ledger_commit_id}".encode()
    digest = hashlib.sha256(raw).digest()
    token_id = int.from_bytes(digest, "big")
    # SHA-256 is never zero in practice, but be defensive
    return token_id if token_id != 0 else 1


# ─── Internal helpers ─────────────────────────────────────────────────────────


def _env_require(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Required env var {name!r} is not set.")
    return value


def _get_web3():
    try:
        from web3 import Web3  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "web3 is required for EVM operations.  Install it: pip install 'web3>=6.0'"
        ) from exc

    rpc_url = os.environ.get("OLYMPUS_EVM_RPC_URL", "http://127.0.0.1:8545")
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError(f"Cannot connect to EVM node at {rpc_url!r}")
    return w3


def _build_account_and_contract(w3, abi: list | None = None):
    """Build (account, contract) from env config.

    Args:
        w3:  Connected Web3 instance.
        abi: Optional ABI override (pass the extended batch ABI from evm_batch.py).
             Defaults to the minimal single-op ABI defined in this module.
    """
    from eth_account import Account  # type: ignore[import-not-found]

    hot_wallet_key = _env_require("OLYMPUS_EVM_HOT_WALLET_KEY")
    contract_address = _env_require("OLYMPUS_EVM_CONTRACT_ADDRESS")

    account = Account.from_key(hot_wallet_key)
    contract = w3.eth.contract(
        address=w3.to_checksum_address(contract_address),
        abi=abi if abi is not None else _CONTRACT_ABI,
    )
    return account, contract


def _send_and_wait(w3, account, tx_data: dict, gas_limit: int, timeout: int) -> str:
    """Sign, broadcast, and wait for a transaction receipt.  Returns the tx hash (0x…)."""

    tx = {
        **tx_data,
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address, "pending"),
        "gas": gas_limit,
    }
    signed = account.sign_transaction(tx)
    raw_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(raw_hash, timeout=timeout)

    if receipt["status"] != 1:
        raise RuntimeError(f"Transaction reverted on-chain. tx={raw_hash.hex()}")
    return "0x" + raw_hash.hex()  # type: ignore[no-any-return]


# ─── Public API ───────────────────────────────────────────────────────────────


def holder_key_to_bytes32(holder_key: str | None) -> bytes:
    """Convert a hex Ed25519 public key to a 32-byte value for the keyId parameter.

    The contract stores keyId as ``bytes32``.  Ed25519 public keys are exactly
    32 bytes, so the hex string maps directly.  Pass ``None`` or an empty string
    to get ``bytes32(0)`` which disables the duplicate-active-key guard for that
    token (anonymous credentials).

    Args:
        holder_key: 64-char hex string (no 0x prefix) representing the 32-byte
                    Ed25519 public key, or None / "" for an unbound credential.

    Returns:
        32 bytes, left-padded with zeros if the input is shorter than 32 bytes.

    Raises:
        ValueError: holder_key has an odd length or contains non-hex characters.
    """
    if not holder_key:
        return b"\x00" * 32
    raw = bytes.fromhex(holder_key)
    if len(raw) > 32:
        raise ValueError(f"holder_key decoded to {len(raw)} bytes; max is 32")
    return raw.rjust(32, b"\x00")


def mint_credential_on_chain(
    *,
    wallet_address: str,
    credential_id: str,
    credential_type: str,
    ledger_commit_id: str,
    burn_authorization: str,
    holder_key: str | None = None,
    token_uri: str = "",
) -> dict[str, str]:
    """Build, sign, and submit an OlympusCredential.mint() transaction.

    Must only be called after:
      1. credential_consents.accepted_at is set (Ed25519 consent confirmed).
      2. The credential is recorded in key_credentials with a valid commit_id.

    Args:
        wallet_address:     Recipient's Ethereum address.
        credential_id:      Olympus credential UUID (key_credentials.id).
        credential_type:    e.g. "journalist" or "researcher".
        ledger_commit_id:   Olympus ledger commit hash (key_credentials.commit_id).
        burn_authorization: One of "issuer_only", "owner_only", "both", "neither".
        holder_key:         64-char hex Ed25519 public key.  Passed as bytes32 keyId
                            so the contract can enforce one-active-token-per-key.
                            Pass None for credentials without a signing-key binding.
        token_uri:          Optional metadata URI (IPFS CID or Arweave hash).

    Returns:
        {"tx_hash": "0x…", "token_id": "<decimal string>"}

    Raises:
        RuntimeError: Missing env config, RPC failure, or on-chain revert.
        ValueError:   Unrecognized burn_authorization string.
    """
    burn_auth = _BURN_AUTH_MAP.get(burn_authorization)
    if burn_auth is None:
        raise ValueError(
            f"Unknown burn_authorization {burn_authorization!r}. Allowed: {sorted(_BURN_AUTH_MAP)}"
        )

    w3 = _get_web3()
    account, contract = _build_account_and_contract(w3)

    token_id = derive_token_id(credential_id, ledger_commit_id)
    to_addr = w3.to_checksum_address(wallet_address)
    key_id = holder_key_to_bytes32(holder_key)
    gas_limit = int(os.environ.get("OLYMPUS_EVM_GAS_LIMIT_MINT", "300000"))
    timeout = int(os.environ.get("OLYMPUS_EVM_TX_TIMEOUT", "120"))

    tx_data = contract.functions.mint(
        to_addr,
        token_id,
        key_id,
        int(burn_auth),
        credential_type,
        ledger_commit_id,
        token_uri,
    ).build_transaction({})

    tx_hash = _send_and_wait(w3, account, tx_data, gas_limit, timeout)

    logger.info(
        "Minted SBT token_id=%s key_id=%s to=%s tx=%s credential=%s",
        token_id,
        holder_key or "anonymous",
        wallet_address,
        tx_hash,
        credential_id,
    )
    return {"tx_hash": tx_hash, "token_id": str(token_id)}


def revoke_credential_on_chain(
    *,
    credential_id: str,
    ledger_commit_id: str,
) -> dict[str, str]:
    """Build, sign, and submit an OlympusCredential.burn() transaction.

    The hot wallet must hold REVOKER_ROLE for burn auth modes that permit issuer burns.
    Calling this for a BurnAuth.OwnerOnly or BurnAuth.Neither token will revert.

    Args:
        credential_id:    Olympus credential UUID (must match the value used at mint).
        ledger_commit_id: Commit hash used at mint time (must match exactly for token_id
                          derivation to produce the correct on-chain ID).

    Returns:
        {"tx_hash": "0x…"}

    Raises:
        RuntimeError: Missing env config, RPC failure, or on-chain revert.
    """
    w3 = _get_web3()
    account, contract = _build_account_and_contract(w3)

    token_id = derive_token_id(credential_id, ledger_commit_id)
    gas_limit = int(os.environ.get("OLYMPUS_EVM_GAS_LIMIT_BURN", "150000"))
    timeout = int(os.environ.get("OLYMPUS_EVM_TX_TIMEOUT", "120"))

    tx_data = contract.functions.burn(token_id).build_transaction({})
    tx_hash = _send_and_wait(w3, account, tx_data, gas_limit, timeout)

    logger.info(
        "Burned SBT token_id=%s tx=%s credential=%s",
        token_id,
        tx_hash,
        credential_id,
    )
    return {"tx_hash": tx_hash}


def query_token_owner(credential_id: str, ledger_commit_id: str) -> str | None:
    """Return the current on-chain owner of a credential token, or None if burned/unminted.

    Args:
        credential_id:    Olympus credential UUID.
        ledger_commit_id: Commit hash used at mint time.

    Returns:
        Checksummed Ethereum address, or None if the token does not exist on-chain.
    """
    w3 = _get_web3()
    _, contract = _build_account_and_contract(w3)

    token_id = derive_token_id(credential_id, ledger_commit_id)
    try:
        owner: str = contract.functions.ownerOf(token_id).call()
        return owner if owner != "0x0000000000000000000000000000000000000000" else None
    except Exception:
        return None
