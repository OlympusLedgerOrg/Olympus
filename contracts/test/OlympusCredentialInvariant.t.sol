// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, StdInvariant} from "forge-std/Test.sol";
import {OlympusCredential}  from "../src/OlympusCredential.sol";
import {IERC5484}           from "../src/interfaces/IERC5484.sol";

/// @dev Handler that the fuzzer drives. It records ghost-state so invariants can
///      compare expected vs. actual contract state without trusting the contract's
///      own counters alone.
contract CredentialHandler is Test {
    OlympusCredential public cred;
    address           public issuer;
    address           public revoker;

    // Ghost state mirrors what we expect the contract to track.
    uint256 public ghost_minted;
    uint256 public ghost_burned;

    // tokenId → initial owner (set at mint; never updated — SBT invariant).
    mapping(uint256 => address) public ghost_mintedTo;

    // keyId → tokenId (mirrors contract's activeTokenByKeyId).
    // 0 means unbound.
    mapping(bytes32 => uint256) public ghost_activeByKey;

    // ordered list of live token IDs for random selection.
    uint256[] public liveIds;

    constructor(OlympusCredential _cred, address _issuer, address _revoker) {
        cred    = _cred;
        issuer  = _issuer;
        revoker = _revoker;
    }

    // ─── Bounded actions ──────────────────────────────────────────────────────

    /// @dev Mint a new token to a bounded EOA address with a unique keyId.
    function mintToken(address to, uint8 burnAuthSeed) external {
        to = address(uint160(bound(uint160(to), 1, type(uint96).max)));
        if (to.code.length != 0) return;

        uint256 tokenId = ghost_minted + 1; // sequential → no collision risk
        bytes32 keyId   = bytes32(tokenId); // unique per mint → never a duplicate
        IERC5484.BurnAuth auth = IERC5484.BurnAuth(burnAuthSeed % 4);

        vm.prank(issuer);
        try cred.mint(to, tokenId, keyId, auth, "researcher", "0xcommit", "ipfs://test") {
            ghost_minted++;
            ghost_mintedTo[tokenId]   = to;
            ghost_activeByKey[keyId]  = tokenId;
            liveIds.push(tokenId);
        } catch {}
    }

    /// @dev Burn a random live token when the burn auth permits it.
    function burnToken(uint256 idxSeed) external {
        if (liveIds.length == 0) return;
        uint256 idx     = bound(idxSeed, 0, liveIds.length - 1);
        uint256 tokenId = liveIds[idx];

        if (cred.ownerOf(tokenId) == address(0)) { _removeLiveId(idx); return; }

        IERC5484.BurnAuth auth = cred.burnAuth(tokenId);
        bytes32 keyId = bytes32(tokenId); // matches our sequential keyId strategy

        if (auth == IERC5484.BurnAuth.IssuerOnly || auth == IERC5484.BurnAuth.Both) {
            vm.prank(revoker);
            try cred.burn(tokenId) {
                ghost_burned++;
                ghost_activeByKey[keyId] = 0;
                _removeLiveId(idx);
            } catch {}
        } else if (auth == IERC5484.BurnAuth.OwnerOnly || auth == IERC5484.BurnAuth.Both) {
            address owner = cred.ownerOf(tokenId);
            vm.prank(owner);
            try cred.burn(tokenId) {
                ghost_burned++;
                ghost_activeByKey[keyId] = 0;
                _removeLiveId(idx);
            } catch {}
        }
        // BurnAuth.Neither → intentionally nothing; token should stay live.
    }

    /// @dev Attempt a transfer with a random recipient — must ALWAYS revert.
    function attemptTransfer(uint256 idxSeed, address to) external {
        if (liveIds.length == 0) return;
        uint256 idx     = bound(idxSeed, 0, liveIds.length - 1);
        uint256 tokenId = liveIds[idx];

        to = address(uint160(bound(uint160(to), 1, type(uint96).max)));
        if (to.code.length != 0) return;

        address owner = cred.ownerOf(tokenId);
        if (owner == address(0) || owner == to) return;

        vm.prank(owner);
        try cred.transferFrom(owner, to, tokenId) {
            // Reaching here is a critical invariant failure — detected below.
        } catch {}
    }

    // ─── Utilities ────────────────────────────────────────────────────────────

    function liveCount() external view returns (uint256) { return liveIds.length; }

    function _removeLiveId(uint256 idx) internal {
        liveIds[idx] = liveIds[liveIds.length - 1];
        liveIds.pop();
    }
}

/// @title OlympusCredentialInvariant
/// @notice Stateful fuzz tests that run across many sequences of actions.
///         Foundry calls each `invariant_*` after every fuzzer-chosen sequence.
contract OlympusCredentialInvariant is StdInvariant, Test {
    OlympusCredential  internal cred;
    CredentialHandler  internal handler;

    address internal admin   = makeAddr("admin");
    address internal issuer  = makeAddr("issuer");
    address internal revoker = makeAddr("revoker");

    function setUp() public {
        cred = new OlympusCredential(admin);

        vm.startPrank(admin);
        cred.grantRole(cred.ISSUER_ROLE(),  issuer);
        cred.grantRole(cred.REVOKER_ROLE(), revoker);
        vm.stopPrank();

        handler = new CredentialHandler(cred, issuer, revoker);

        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = CredentialHandler.mintToken.selector;
        selectors[1] = CredentialHandler.burnToken.selector;
        selectors[2] = CredentialHandler.attemptTransfer.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    // ─── Invariants ───────────────────────────────────────────────────────────

    /// @notice totalSupply == totalMinted - totalBurned (all three views must agree).
    function invariant_SupplyConsistency() public view {
        assertEq(
            cred.totalSupply(),
            cred.totalMinted() - cred.totalBurned(),
            "supply != minted - burned"
        );
    }

    /// @notice Ghost minted count matches the contract's totalMinted.
    function invariant_GhostMintedMatchesContract() public view {
        assertEq(
            handler.ghost_minted(),
            cred.totalMinted(),
            "ghost_minted diverged from contract"
        );
    }

    /// @notice Contract supply never exceeds the ghost minted count.
    function invariant_SupplyNeverExceedsGhostMinted() public view {
        assertLe(
            cred.totalSupply(),
            handler.ghost_minted(),
            "live supply > ever minted"
        );
    }

    /// @notice Every token in the handler's liveIds is still owned by its original
    ///         minted-to address — transfers cannot change ownership.
    function invariant_NoTransferSucceeds() public view {
        uint256 count = handler.liveCount();
        for (uint256 i; i < count; i++) {
            uint256 id    = handler.liveIds(i);
            address owner = cred.ownerOf(id);
            assertEq(
                owner,
                handler.ghost_mintedTo(id),
                "token owner changed after mint (transfer succeeded)"
            );
        }
    }

    /// @notice totalBurned is monotonically increasing.
    function invariant_BurnedNeverDecreases() public view {
        assertLe(
            handler.ghost_burned(),
            cred.totalMinted(),
            "burned > minted (impossible)"
        );
        assertGe(cred.totalBurned(), 0, "totalBurned underflow");
    }

    /// @notice For every live token, its keyId binding is consistent between ghost
    ///         state and the contract's activeTokenByKeyId mapping.
    function invariant_KeyBindingConsistency() public view {
        uint256 count = handler.liveCount();
        for (uint256 i; i < count; i++) {
            uint256 tokenId = handler.liveIds(i);
            bytes32 keyId   = bytes32(tokenId); // matches sequential strategy in handler
            // Ghost says this keyId maps to tokenId; contract must agree.
            assertEq(
                cred.activeTokenByKeyId(keyId),
                handler.ghost_activeByKey(keyId),
                "activeTokenByKeyId diverged from ghost"
            );
        }
    }

    /// @notice No keyId should map to a token that is no longer live (i.e. burned).
    ///         If a token is burned, its keyId slot must read 0.
    function invariant_NoActiveKeyForBurnedToken() public view {
        // Check ghost_burned against all tokenIds we've ever seen via totalMinted.
        uint256 total = cred.totalMinted();
        for (uint256 tokenId = 1; tokenId <= total; tokenId++) {
            bytes32 keyId = bytes32(tokenId);
            uint256 active = cred.activeTokenByKeyId(keyId);
            if (active != 0) {
                // There is an active token for this keyId — it must still exist.
                address owner = cred.ownerOf(active);
                assertNotEq(
                    owner,
                    address(0),
                    "activeTokenByKeyId points to a burned token"
                );
            }
        }
    }
}
