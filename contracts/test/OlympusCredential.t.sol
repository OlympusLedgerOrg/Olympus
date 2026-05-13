// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {OlympusCredential} from "../src/OlympusCredential.sol";
import {IERC5484}          from "../src/interfaces/IERC5484.sol";

contract OlympusCredentialTest is Test {
    OlympusCredential internal cred;

    address internal admin   = makeAddr("admin");
    address internal issuer  = makeAddr("issuer");
    address internal revoker = makeAddr("revoker");
    address internal alice   = makeAddr("alice");
    address internal bob     = makeAddr("bob");

    uint256 internal constant TOKEN_1    = 1;
    bytes32 internal constant KEY_1      = bytes32(uint256(0xA1));
    bytes32 internal constant KEY_2      = bytes32(uint256(0xA2));
    string  internal constant CRED_TYPE  = "journalist";
    string  internal constant COMMIT_ID  = "0xdeadbeef00000000000000000000000000000000000000000000000000000001";
    string  internal constant URI        = "ipfs://QmOlympusTest";

    function setUp() public {
        cred = new OlympusCredential(admin);
        vm.startPrank(admin);
        cred.grantRole(cred.ISSUER_ROLE(),  issuer);
        cred.grantRole(cred.REVOKER_ROLE(), revoker);
        vm.stopPrank();
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    /// @dev Mint a single token with a caller-chosen keyId.
    function _mint(address to, uint256 tokenId, bytes32 keyId, IERC5484.BurnAuth auth) internal {
        vm.prank(issuer);
        cred.mint(to, tokenId, keyId, auth, CRED_TYPE, COMMIT_ID, URI);
    }

    /// @dev Mint TOKEN_1 for alice using KEY_1 with IssuerOnly auth.
    function _mintDefault() internal {
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.IssuerOnly);
    }

    // ─── Mint — happy path ────────────────────────────────────────────────────

    function test_MintSuccess_OwnerAndSupply() public {
        vm.expectEmit(true, true, true, true);
        emit IERC5484.Issued(address(0), alice, TOKEN_1, IERC5484.BurnAuth.IssuerOnly);
        vm.expectEmit(true, true, false, false);
        emit OlympusCredential.KeyBound(TOKEN_1, KEY_1);

        _mintDefault();

        assertEq(cred.ownerOf(TOKEN_1), alice);
        assertEq(cred.totalSupply(),    1);
        assertEq(cred.totalMinted(),    1);
        assertEq(cred.totalBurned(),    0);
        assertEq(cred.tokenURI(TOKEN_1), URI);
    }

    function test_MintRecordsAllBurnAuthModes() public {
        IERC5484.BurnAuth[4] memory modes = [
            IERC5484.BurnAuth.IssuerOnly,
            IERC5484.BurnAuth.OwnerOnly,
            IERC5484.BurnAuth.Both,
            IERC5484.BurnAuth.Neither
        ];
        for (uint256 i; i < 4; i++) {
            bytes32 kid = bytes32(uint256(i + 1));
            _mint(alice, i + 1, kid, modes[i]);
            assertEq(uint8(cred.burnAuth(i + 1)), uint8(modes[i]));
        }
    }

    function test_MintRecordsCredentialData() public {
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.Both);

        (IERC5484.BurnAuth auth, bytes32 kid, string memory ct, string memory cid) =
            cred.credentialOf(TOKEN_1);
        assertEq(uint8(auth), uint8(IERC5484.BurnAuth.Both));
        assertEq(kid, KEY_1);
        assertEq(ct,  CRED_TYPE);
        assertEq(cid, COMMIT_ID);
    }

    function test_MintBindsActiveTokenByKeyId() public {
        _mintDefault();
        assertEq(cred.activeTokenByKeyId(KEY_1), TOKEN_1);
    }

    // ─── Mint — access control ────────────────────────────────────────────────

    function test_MintReverts_NonIssuer() public {
        vm.prank(alice);
        vm.expectRevert();
        cred.mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.IssuerOnly, CRED_TYPE, COMMIT_ID, URI);
    }

    function test_MintReverts_RevokerWithoutIssuerRole() public {
        vm.prank(revoker);
        vm.expectRevert();
        cred.mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.IssuerOnly, CRED_TYPE, COMMIT_ID, URI);
    }

    // ─── Mint — duplicate active key guard ───────────────────────────────────

    function test_MintReverts_DuplicateActiveKey() public {
        _mintDefault(); // TOKEN_1 → KEY_1

        // Trying to mint a second token bound to the same key must revert.
        vm.prank(issuer);
        vm.expectRevert(
            abi.encodeWithSelector(OlympusCredential.DuplicateActiveKey.selector, KEY_1, TOKEN_1)
        );
        cred.mint(alice, 2, KEY_1, IERC5484.BurnAuth.IssuerOnly, CRED_TYPE, COMMIT_ID, URI);
    }

    function test_MintSucceeds_AfterBurnFreesKey() public {
        _mintDefault();

        // Burn TOKEN_1 — this should free KEY_1.
        vm.prank(revoker);
        cred.burn(TOKEN_1);

        assertEq(cred.activeTokenByKeyId(KEY_1), 0, "keyId not released after burn");

        // Now a second mint for KEY_1 must succeed.
        _mint(alice, 2, KEY_1, IERC5484.BurnAuth.IssuerOnly);
        assertEq(cred.activeTokenByKeyId(KEY_1), 2);
    }

    function test_MintAnonymous_ZeroKeyId_NoActiveSlot() public {
        // bytes32(0) means "no key binding" — no duplicate check applies.
        vm.prank(issuer);
        cred.mint(alice, 1, bytes32(0), IERC5484.BurnAuth.IssuerOnly, CRED_TYPE, COMMIT_ID, URI);
        vm.prank(issuer);
        cred.mint(alice, 2, bytes32(0), IERC5484.BurnAuth.IssuerOnly, CRED_TYPE, COMMIT_ID, URI);
        assertEq(cred.totalMinted(), 2);
    }

    // ─── Non-transferability ──────────────────────────────────────────────────

    function test_TransferFrom_Reverts() public {
        _mintDefault();
        vm.prank(alice);
        vm.expectRevert(OlympusCredential.NonTransferable.selector);
        cred.transferFrom(alice, bob, TOKEN_1);
    }

    function test_SafeTransferFrom_Reverts() public {
        _mintDefault();
        vm.prank(alice);
        vm.expectRevert(OlympusCredential.NonTransferable.selector);
        cred.safeTransferFrom(alice, bob, TOKEN_1);
    }

    function test_ApprovedTransfer_Reverts() public {
        _mintDefault();
        vm.prank(alice);
        cred.approve(bob, TOKEN_1);

        vm.prank(bob);
        vm.expectRevert(OlympusCredential.NonTransferable.selector);
        cred.transferFrom(alice, bob, TOKEN_1);
    }

    function test_OperatorTransfer_Reverts() public {
        _mintDefault();
        vm.prank(alice);
        cred.setApprovalForAll(bob, true);

        vm.prank(bob);
        vm.expectRevert(OlympusCredential.NonTransferable.selector);
        cred.transferFrom(alice, bob, TOKEN_1);
    }

    // ─── Burn — IssuerOnly ────────────────────────────────────────────────────

    function test_Burn_IssuerOnly_RevokerSucceeds() public {
        _mintDefault();
        vm.expectEmit(true, true, false, false);
        emit OlympusCredential.KeyRevoked(TOKEN_1, KEY_1);

        vm.prank(revoker);
        cred.burn(TOKEN_1);

        assertEq(cred.totalSupply(), 0);
        assertEq(cred.totalBurned(), 1);
        assertEq(cred.activeTokenByKeyId(KEY_1), 0);
    }

    function test_Burn_IssuerOnly_OwnerReverts() public {
        _mintDefault();
        vm.prank(alice);
        vm.expectRevert(OlympusCredential.Unauthorized.selector);
        cred.burn(TOKEN_1);
    }

    function test_Burn_IssuerOnly_ThirdPartyReverts() public {
        _mintDefault();
        vm.prank(bob);
        vm.expectRevert(OlympusCredential.Unauthorized.selector);
        cred.burn(TOKEN_1);
    }

    // ─── Burn — OwnerOnly ─────────────────────────────────────────────────────

    function test_Burn_OwnerOnly_OwnerSucceeds() public {
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.OwnerOnly);
        vm.expectEmit(true, true, false, false);
        emit OlympusCredential.KeyRevoked(TOKEN_1, KEY_1);

        vm.prank(alice);
        cred.burn(TOKEN_1);
        assertEq(cred.totalSupply(), 0);
        assertEq(cred.activeTokenByKeyId(KEY_1), 0);
    }

    function test_Burn_OwnerOnly_RevokerReverts() public {
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.OwnerOnly);
        vm.prank(revoker);
        vm.expectRevert(OlympusCredential.Unauthorized.selector);
        cred.burn(TOKEN_1);
    }

    function test_Burn_OwnerOnly_ThirdPartyReverts() public {
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.OwnerOnly);
        vm.prank(bob);
        vm.expectRevert(OlympusCredential.Unauthorized.selector);
        cred.burn(TOKEN_1);
    }

    // ─── Burn — Both ──────────────────────────────────────────────────────────

    function test_Burn_Both_OwnerSucceeds() public {
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.Both);
        vm.prank(alice);
        cred.burn(TOKEN_1);
        assertEq(cred.totalSupply(), 0);
    }

    function test_Burn_Both_RevokerSucceeds() public {
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.Both);
        vm.prank(revoker);
        cred.burn(TOKEN_1);
        assertEq(cred.totalSupply(), 0);
    }

    function test_Burn_Both_ThirdPartyReverts() public {
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.Both);
        vm.prank(bob);
        vm.expectRevert(OlympusCredential.Unauthorized.selector);
        cred.burn(TOKEN_1);
    }

    // ─── Burn — Neither ───────────────────────────────────────────────────────

    function test_Burn_Neither_OwnerReverts() public {
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.Neither);
        vm.prank(alice);
        vm.expectRevert(OlympusCredential.Unauthorized.selector);
        cred.burn(TOKEN_1);
    }

    function test_Burn_Neither_RevokerReverts() public {
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.Neither);
        vm.prank(revoker);
        vm.expectRevert(OlympusCredential.Unauthorized.selector);
        cred.burn(TOKEN_1);
    }

    function test_Burn_Neither_AdminReverts() public {
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.Neither);
        vm.prank(admin);
        vm.expectRevert(OlympusCredential.Unauthorized.selector);
        cred.burn(TOKEN_1);
    }

    // ─── Burn — nonexistent token ─────────────────────────────────────────────

    function test_Burn_NonexistentToken_Reverts() public {
        vm.prank(revoker);
        vm.expectRevert(abi.encodeWithSelector(OlympusCredential.TokenDoesNotExist.selector, 999));
        cred.burn(999);
    }

    function test_BurnAuth_NonexistentToken_Reverts() public {
        vm.expectRevert(abi.encodeWithSelector(OlympusCredential.TokenDoesNotExist.selector, 999));
        cred.burnAuth(999);
    }

    function test_CredentialOf_NonexistentToken_Reverts() public {
        vm.expectRevert(abi.encodeWithSelector(OlympusCredential.TokenDoesNotExist.selector, 999));
        cred.credentialOf(999);
    }

    // ─── Supply accounting ────────────────────────────────────────────────────

    function test_SupplyAccountingAcrossMintAndBurn() public {
        _mint(alice, 1, bytes32(uint256(1)), IERC5484.BurnAuth.IssuerOnly);
        _mint(alice, 2, bytes32(uint256(2)), IERC5484.BurnAuth.OwnerOnly);
        _mint(alice, 3, bytes32(uint256(3)), IERC5484.BurnAuth.Both);

        assertEq(cred.totalMinted(),  3);
        assertEq(cred.totalBurned(),  0);
        assertEq(cred.totalSupply(),  3);

        vm.prank(revoker);
        cred.burn(1);
        vm.prank(alice);
        cred.burn(2);

        assertEq(cred.totalMinted(),  3);
        assertEq(cred.totalBurned(),  2);
        assertEq(cred.totalSupply(),  1);
    }

    // ─── ERC-5484 / ERC-165 interface ────────────────────────────────────────

    function test_SupportsIERC5484() public view {
        assertTrue(cred.supportsInterface(type(IERC5484).interfaceId));
    }

    function test_SupportsERC721() public view {
        // 0x80ac58cd = ERC-721 interface ID
        assertTrue(cred.supportsInterface(0x80ac58cd));
    }

    function test_SupportsAccessControl() public view {
        // 0x7965db0b = IAccessControl interface ID
        assertTrue(cred.supportsInterface(0x7965db0b));
    }

    // ─── Fuzz — mint + query ──────────────────────────────────────────────────

    function testFuzz_MintAndQuery(
        address to,
        uint256 tokenId,
        bytes32 keyId,
        uint8   burnAuthSeed,
        string calldata credType,
        string calldata commitId,
        string calldata uri
    ) public {
        vm.assume(to != address(0));
        vm.assume(to.code.length == 0);      // skip contracts (safeTransfer callback)
        vm.assume(tokenId != 0);             // OZ rejects tokenId 0 on _mint
        // Ensure no existing active token for this keyId
        vm.assume(keyId == bytes32(0) || cred.activeTokenByKeyId(keyId) == 0);

        IERC5484.BurnAuth auth = IERC5484.BurnAuth(burnAuthSeed % 4);

        vm.prank(issuer);
        cred.mint(to, tokenId, keyId, auth, credType, commitId, uri);

        assertEq(cred.ownerOf(tokenId), to);
        assertEq(uint8(cred.burnAuth(tokenId)), uint8(auth));

        (IERC5484.BurnAuth a, bytes32 kid, string memory ct, string memory cid) =
            cred.credentialOf(tokenId);
        assertEq(uint8(a), uint8(auth));
        assertEq(kid, keyId);
        assertEq(ct,  credType);
        assertEq(cid, commitId);

        if (keyId != bytes32(0)) {
            assertEq(cred.activeTokenByKeyId(keyId), tokenId);
        }
    }

    function testFuzz_TransferAlwaysReverts(address to, uint256 tokenId) public {
        vm.assume(to != address(0) && to != alice);
        vm.assume(to.code.length == 0);
        vm.assume(tokenId != 0);

        _mint(alice, tokenId, bytes32(tokenId), IERC5484.BurnAuth.IssuerOnly);

        vm.prank(alice);
        vm.expectRevert(OlympusCredential.NonTransferable.selector);
        cred.transferFrom(alice, to, tokenId);
    }

    function testFuzz_BurnAuthNeitherAlwaysReverts(address caller, uint256 tokenId) public {
        vm.assume(caller != address(0));
        vm.assume(caller.code.length == 0);
        vm.assume(tokenId != 0);

        _mint(alice, tokenId, bytes32(tokenId), IERC5484.BurnAuth.Neither);

        vm.prank(caller);
        vm.expectRevert(OlympusCredential.Unauthorized.selector);
        cred.burn(tokenId);
    }

    function testFuzz_SupplyNeverExceedsMinted(uint8 mintCount, uint8 burnCount) public {
        mintCount = uint8(bound(mintCount, 0, 20));
        burnCount = uint8(bound(burnCount, 0, mintCount));

        for (uint256 i = 1; i <= mintCount; i++) {
            _mint(alice, i, bytes32(i), IERC5484.BurnAuth.IssuerOnly);
        }
        for (uint256 i = 1; i <= burnCount; i++) {
            vm.prank(revoker);
            cred.burn(i);
        }

        assertEq(cred.totalSupply(), cred.totalMinted() - cred.totalBurned());
        assertLe(cred.totalSupply(), cred.totalMinted());
    }

    // ─── mintBatch helpers ────────────────────────────────────────────────────

    function _batchArrays(uint256 n)
        internal
        view
        returns (
            address[]  memory tos,
            uint256[]  memory ids,
            bytes32[]  memory keyIds,
            IERC5484.BurnAuth[] memory auths,
            string[]   memory types_,
            string[]   memory commits,
            string[]   memory uris_
        )
    {
        tos     = new address[](n);
        ids     = new uint256[](n);
        keyIds  = new bytes32[](n);
        auths   = new IERC5484.BurnAuth[](n);
        types_  = new string[](n);
        commits = new string[](n);
        uris_   = new string[](n);
        for (uint256 i; i < n; i++) {
            tos[i]     = alice;
            ids[i]     = i + 1;
            keyIds[i]  = bytes32(i + 1); // distinct per-token keyId
            auths[i]   = IERC5484.BurnAuth.IssuerOnly;
            types_[i]  = CRED_TYPE;
            commits[i] = COMMIT_ID;
            uris_[i]   = URI;
        }
    }

    function _mintN(uint256 n, IERC5484.BurnAuth auth) internal {
        for (uint256 i = 1; i <= n; i++) {
            vm.prank(issuer);
            cred.mint(alice, i, bytes32(i), auth, CRED_TYPE, COMMIT_ID, URI);
        }
    }

    // ─── mintBatch — happy path ───────────────────────────────────────────────

    function test_MintBatch_Success() public {
        (
            address[]  memory tos,
            uint256[]  memory ids,
            bytes32[]  memory keyIds,
            IERC5484.BurnAuth[] memory auths,
            string[]   memory types_,
            string[]   memory commits,
            string[]   memory uris_
        ) = _batchArrays(3);

        vm.prank(issuer);
        cred.mintBatch(tos, ids, keyIds, auths, types_, commits, uris_);

        assertEq(cred.totalMinted(), 3);
        assertEq(cred.totalSupply(), 3);
        for (uint256 i = 1; i <= 3; i++) {
            assertEq(cred.ownerOf(i), alice);
            assertEq(cred.activeTokenByKeyId(bytes32(i)), i);
        }
    }

    function test_MintBatch_EmitsIssuedAndKeyBoundPerToken() public {
        (
            address[]  memory tos,
            uint256[]  memory ids,
            bytes32[]  memory keyIds,
            IERC5484.BurnAuth[] memory auths,
            string[]   memory types_,
            string[]   memory commits,
            string[]   memory uris_
        ) = _batchArrays(2);

        // Expect Issued + KeyBound for token 1, then for token 2.
        vm.expectEmit(true, true, true, true);
        emit IERC5484.Issued(address(0), alice, 1, IERC5484.BurnAuth.IssuerOnly);
        vm.expectEmit(true, true, false, false);
        emit OlympusCredential.KeyBound(1, bytes32(uint256(1)));

        vm.expectEmit(true, true, true, true);
        emit IERC5484.Issued(address(0), alice, 2, IERC5484.BurnAuth.IssuerOnly);
        vm.expectEmit(true, true, false, false);
        emit OlympusCredential.KeyBound(2, bytes32(uint256(2)));

        vm.prank(issuer);
        cred.mintBatch(tos, ids, keyIds, auths, types_, commits, uris_);
    }

    function test_MintBatch_RevertsForNonIssuer() public {
        (
            address[]  memory tos,
            uint256[]  memory ids,
            bytes32[]  memory keyIds,
            IERC5484.BurnAuth[] memory auths,
            string[]   memory types_,
            string[]   memory commits,
            string[]   memory uris_
        ) = _batchArrays(2);

        vm.prank(alice);
        vm.expectRevert();
        cred.mintBatch(tos, ids, keyIds, auths, types_, commits, uris_);
    }

    function test_MintBatch_RevertsOnArrayMismatch() public {
        address[]  memory tos    = new address[](2);
        uint256[]  memory ids    = new uint256[](3); // mismatch
        bytes32[]  memory keyIds = new bytes32[](2);
        IERC5484.BurnAuth[] memory auths = new IERC5484.BurnAuth[](2);
        string[]   memory types_ = new string[](2);
        string[]   memory commits = new string[](2);
        string[]   memory uris_  = new string[](2);
        tos[0] = tos[1] = alice;

        vm.prank(issuer);
        vm.expectRevert(OlympusCredential.ArrayLengthMismatch.selector);
        cred.mintBatch(tos, ids, keyIds, auths, types_, commits, uris_);
    }

    function test_MintBatch_RevertsAboveMaxBatchSize() public {
        uint256 n = cred.MAX_BATCH_SIZE() + 1;
        (
            address[]  memory tos,
            uint256[]  memory ids,
            bytes32[]  memory keyIds,
            IERC5484.BurnAuth[] memory auths,
            string[]   memory types_,
            string[]   memory commits,
            string[]   memory uris_
        ) = _batchArrays(n);

        vm.prank(issuer);
        vm.expectRevert(
            abi.encodeWithSelector(OlympusCredential.BatchTooLarge.selector, n, cred.MAX_BATCH_SIZE())
        );
        cred.mintBatch(tos, ids, keyIds, auths, types_, commits, uris_);
    }

    function test_MintBatch_RevertsOnDuplicateKeyIdWithinBatch() public {
        // Put the same keyId in two slots of the batch.
        (
            address[]  memory tos,
            uint256[]  memory ids,
            bytes32[]  memory keyIds,
            IERC5484.BurnAuth[] memory auths,
            string[]   memory types_,
            string[]   memory commits,
            string[]   memory uris_
        ) = _batchArrays(2);
        keyIds[1] = keyIds[0]; // collision

        vm.prank(issuer);
        // First mint succeeds, second sees the already-bound slot → DuplicateActiveKey.
        vm.expectRevert(
            abi.encodeWithSelector(OlympusCredential.DuplicateActiveKey.selector, keyIds[0], ids[0])
        );
        cred.mintBatch(tos, ids, keyIds, auths, types_, commits, uris_);
    }

    function test_MintBatch_RevertsOnDuplicateKeyIdAlreadyOnChain() public {
        // Mint token 1 → KEY_1 is now active.
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.IssuerOnly);

        // Attempt a batch that includes KEY_1 again.
        address[]  memory tos    = new address[](1);
        uint256[]  memory ids    = new uint256[](1);
        bytes32[]  memory keyIds = new bytes32[](1);
        IERC5484.BurnAuth[] memory auths = new IERC5484.BurnAuth[](1);
        string[]   memory types_ = new string[](1);
        string[]   memory commits = new string[](1);
        string[]   memory uris_  = new string[](1);
        tos[0] = alice; ids[0] = 2; keyIds[0] = KEY_1;
        auths[0] = IERC5484.BurnAuth.IssuerOnly;
        types_[0] = CRED_TYPE; commits[0] = COMMIT_ID; uris_[0] = URI;

        vm.prank(issuer);
        vm.expectRevert(
            abi.encodeWithSelector(OlympusCredential.DuplicateActiveKey.selector, KEY_1, TOKEN_1)
        );
        cred.mintBatch(tos, ids, keyIds, auths, types_, commits, uris_);
    }

    function test_MintBatch_EmptyArrayIsNoOp() public {
        address[]  memory tos    = new address[](0);
        uint256[]  memory ids    = new uint256[](0);
        bytes32[]  memory keyIds = new bytes32[](0);
        IERC5484.BurnAuth[] memory auths = new IERC5484.BurnAuth[](0);
        string[]   memory types_ = new string[](0);
        string[]   memory commits = new string[](0);
        string[]   memory uris_  = new string[](0);

        vm.prank(issuer);
        cred.mintBatch(tos, ids, keyIds, auths, types_, commits, uris_);
        assertEq(cred.totalMinted(), 0);
    }

    // ─── burnBatch — happy path ───────────────────────────────────────────────

    function test_BurnBatch_AllIssuerOnly_EmitsKeyRevoked() public {
        _mintN(4, IERC5484.BurnAuth.IssuerOnly);

        uint256[] memory ids = new uint256[](4);
        for (uint256 i; i < 4; i++) {
            ids[i] = i + 1;
            vm.expectEmit(true, true, false, false);
            emit OlympusCredential.KeyRevoked(i + 1, bytes32(i + 1));
        }

        vm.prank(revoker);
        cred.burnBatch(ids);

        assertEq(cred.totalBurned(), 4);
        assertEq(cred.totalSupply(), 0);
        for (uint256 i = 1; i <= 4; i++) {
            assertEq(cred.activeTokenByKeyId(bytes32(i)), 0);
        }
    }

    function test_BurnBatch_BothAuth_IssuerCanBatch() public {
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.Both);

        uint256[] memory ids = new uint256[](1);
        ids[0] = TOKEN_1;

        vm.prank(revoker);
        cred.burnBatch(ids);

        assertEq(cred.totalBurned(), 1);
        assertEq(cred.activeTokenByKeyId(KEY_1), 0);
    }

    // ─── burnBatch — all-or-nothing reversions ────────────────────────────────

    function test_BurnBatch_RevertsOnNonExistentToken() public {
        _mintN(2, IERC5484.BurnAuth.IssuerOnly);
        uint256[] memory ids = new uint256[](3);
        ids[0] = 1; ids[1] = 999; ids[2] = 2; // 999 does not exist

        vm.prank(revoker);
        vm.expectRevert(
            abi.encodeWithSelector(OlympusCredential.TokenDoesNotExist.selector, 999)
        );
        cred.burnBatch(ids);

        // All-or-nothing: tokens 1 and 2 must still exist.
        assertEq(cred.totalBurned(), 0);
        assertEq(cred.ownerOf(1), alice);
        assertEq(cred.ownerOf(2), alice);
    }

    function test_BurnBatch_RevertsOnOwnerOnlyToken() public {
        vm.prank(issuer);
        cred.mint(alice, 1, bytes32(uint256(1)), IERC5484.BurnAuth.OwnerOnly, CRED_TYPE, COMMIT_ID, URI);
        vm.prank(issuer);
        cred.mint(alice, 2, bytes32(uint256(2)), IERC5484.BurnAuth.IssuerOnly, CRED_TYPE, COMMIT_ID, URI);

        uint256[] memory ids = new uint256[](2);
        ids[0] = 1; ids[1] = 2;

        vm.prank(revoker);
        vm.expectRevert(OlympusCredential.Unauthorized.selector);
        cred.burnBatch(ids);

        // Neither token burned.
        assertEq(cred.totalBurned(), 0);
        assertEq(cred.ownerOf(1), alice);
        assertEq(cred.ownerOf(2), alice);
    }

    function test_BurnBatch_RevertsOnNeitherToken() public {
        _mint(alice, TOKEN_1, KEY_1, IERC5484.BurnAuth.Neither);

        uint256[] memory ids = new uint256[](1);
        ids[0] = TOKEN_1;

        vm.prank(revoker);
        vm.expectRevert(OlympusCredential.Unauthorized.selector);
        cred.burnBatch(ids);

        assertEq(cred.totalBurned(), 0);
    }

    function test_BurnBatch_RevertsAboveMaxBatchSize() public {
        uint256 n = cred.MAX_BATCH_SIZE() + 1;
        uint256[] memory ids = new uint256[](n);
        for (uint256 i; i < n; i++) ids[i] = i + 1;

        vm.prank(revoker);
        vm.expectRevert(
            abi.encodeWithSelector(OlympusCredential.BatchTooLarge.selector, n, cred.MAX_BATCH_SIZE())
        );
        cred.burnBatch(ids);
    }

    function test_BurnBatch_RevertsForNonRevoker() public {
        _mintN(2, IERC5484.BurnAuth.IssuerOnly);
        uint256[] memory ids = new uint256[](2);
        ids[0] = 1; ids[1] = 2;

        vm.prank(alice);
        vm.expectRevert();
        cred.burnBatch(ids);
    }

    function test_BurnBatch_EmptyArrayIsNoOp() public {
        _mintN(2, IERC5484.BurnAuth.IssuerOnly);
        uint256[] memory ids = new uint256[](0);

        vm.prank(revoker);
        cred.burnBatch(ids);
        assertEq(cred.totalBurned(), 0);
    }

    // ─── Fuzz — batch ─────────────────────────────────────────────────────────

    function testFuzz_MintBatch_SupplyAccountedCorrectly(uint8 n) public {
        n = uint8(bound(n, 0, 20));
        if (n == 0) return;

        (
            address[]  memory tos,
            uint256[]  memory ids,
            bytes32[]  memory keyIds,
            IERC5484.BurnAuth[] memory auths,
            string[]   memory types_,
            string[]   memory commits,
            string[]   memory uris_
        ) = _batchArrays(n);

        vm.prank(issuer);
        cred.mintBatch(tos, ids, keyIds, auths, types_, commits, uris_);

        assertEq(cred.totalMinted(), n);
        assertEq(cred.totalSupply(), n);
        for (uint256 i = 1; i <= n; i++) {
            assertEq(cred.activeTokenByKeyId(bytes32(i)), i);
        }
    }

    function testFuzz_BurnBatch_AllOrNothingOnOwnerOnly(uint8 n) public {
        n = uint8(bound(n, 1, 10));

        // Mint n tokens, alternating IssuerOnly / OwnerOnly.
        for (uint256 i = 1; i <= n; i++) {
            IERC5484.BurnAuth auth = (i % 2 == 0)
                ? IERC5484.BurnAuth.OwnerOnly
                : IERC5484.BurnAuth.IssuerOnly;
            vm.prank(issuer);
            cred.mint(alice, i, bytes32(i), auth, CRED_TYPE, COMMIT_ID, URI);
        }

        // If there are any OwnerOnly tokens, the batch must revert.
        bool hasOwnerOnly = (n >= 2);
        uint256[] memory ids = new uint256[](n);
        for (uint256 i; i < n; i++) ids[i] = i + 1;

        if (hasOwnerOnly) {
            vm.prank(revoker);
            vm.expectRevert();
            cred.burnBatch(ids);
            assertEq(cred.totalBurned(), 0, "all-or-nothing violated");
        } else {
            // n == 1, odd → IssuerOnly only — batch must succeed.
            vm.prank(revoker);
            cred.burnBatch(ids);
            assertEq(cred.totalBurned(), 1);
        }
    }

    function testFuzz_KeyReleasedAfterBurn(uint8 n) public {
        n = uint8(bound(n, 1, 10));
        for (uint256 i = 1; i <= n; i++) {
            vm.prank(issuer);
            cred.mint(alice, i, bytes32(i), IERC5484.BurnAuth.IssuerOnly, CRED_TYPE, COMMIT_ID, URI);
        }

        uint256[] memory ids = new uint256[](n);
        for (uint256 i; i < n; i++) ids[i] = i + 1;
        vm.prank(revoker);
        cred.burnBatch(ids);

        // All keyIds should be free again.
        for (uint256 i = 1; i <= n; i++) {
            assertEq(cred.activeTokenByKeyId(bytes32(i)), 0, "keyId not released");
        }

        // Re-issuance for the same keys must now succeed.
        for (uint256 i = 1; i <= n; i++) {
            vm.prank(issuer);
            cred.mint(alice, i + n, bytes32(i), IERC5484.BurnAuth.IssuerOnly, CRED_TYPE, COMMIT_ID, URI);
            assertEq(cred.activeTokenByKeyId(bytes32(i)), i + n);
        }
    }
}
