// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  IERC5484 — Consensual Soulbound Token
/// @notice Minimal interface from EIP-5484 (https://eips.ethereum.org/EIPS/eip-5484).
///         Tokens are non-transferable NFTs whose burn authority is fixed at mint time
///         and recorded in the `Issued` event for off-chain verification.
interface IERC5484 {
    /// @notice Who may burn a given token.
    /// @dev    Values mirror the EIP-5484 enum ordering exactly; the Python backend
    ///         maps the strings "issuer_only"→0, "owner_only"→1, "both"→2, "neither"→3.
    enum BurnAuth {
        IssuerOnly, // 0 — only an address holding REVOKER_ROLE may burn
        OwnerOnly,  // 1 — only the current token owner may burn
        Both,       // 2 — either the owner or an issuer may burn
        Neither     // 3 — the token is permanently non-burnable
    }

    /// @notice Emitted exactly once per token, at mint time.
    /// @param  from     Always address(0) for a mint (no prior owner).
    /// @param  to       Recipient wallet; must have given EIP-191 consent off-chain.
    /// @param  tokenId  Unique token ID; derived from the Olympus ledger commit hash.
    /// @param  burnAuth Burn authority recorded permanently for this token.
    event Issued(
        address indexed from,
        address indexed to,
        uint256 indexed tokenId,
        BurnAuth burnAuth
    );

    /// @notice Returns the burn authorization that was set when `tokenId` was minted.
    /// @dev    Reverts if `tokenId` does not exist.
    function burnAuth(uint256 tokenId) external view returns (BurnAuth);
}
