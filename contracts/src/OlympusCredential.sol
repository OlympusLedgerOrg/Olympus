// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721}           from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC721URIStorage} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import {AccessControl}    from "@openzeppelin/contracts/access/AccessControl.sol";
import {IERC5484}         from "./interfaces/IERC5484.sol";

/// @title  OlympusCredential — ERC-5484 Soulbound Credential NFT
/// @notice Non-transferable ERC-721 whose issuance and revocation are anchored to the
///         Olympus cryptographic ledger.  Each token binds an Olympus Ed25519 signing key
///         (keyId = the raw 32-byte Ed25519 public key) and carries the `ledgerCommitId`
///         (0x-prefixed BLAKE3 commit hash) so on-chain state can be independently
///         verified against the off-chain append-only ledger.
///
/// @dev    Architecture notes (matches Olympus language-boundary rules):
///           • Python backend holds ISSUER_ROLE and REVOKER_ROLE via a hot-wallet key
///             stored in OLYMPUS_EVM_HOT_WALLET_KEY.
///           • Consent (Ed25519 JCS challenge/response) is recorded in the Python DB
///             (`credential_consents`) before any mint is submitted.
///           • Token IDs are derived deterministically: SHA-256("olympus:sbt:v1:{credId}:{commitId}"),
///             so the ID is reproducible by any party with access to the ledger record.
///           • keyId is the raw 32-byte Ed25519 public key cast to bytes32.  The contract
///             enforces that at most one ACTIVE token exists per keyId at any time.
///           • Transfer is blocked at the `_update` hook (OZ v5) — there is no
///             approve/transferFrom/safeTransferFrom escape hatch that bypasses it.
///           • mintBatch is all-or-nothing (reverts if any individual mint fails).
///           • burnBatch is all-or-nothing (reverts if any token is non-burnable by issuer).
///             The Python flush service pre-checks ownerOf before submitting.
contract OlympusCredential is ERC721URIStorage, AccessControl, IERC5484 {

    // ─── Roles ────────────────────────────────────────────────────────────────

    /// @notice Role required to mint credentials (single or batch).
    bytes32 public constant ISSUER_ROLE  = keccak256("ISSUER_ROLE");

    /// @notice Role required to burn credentials (single or batch).
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");

    // ─── Constants ────────────────────────────────────────────────────────────

    /// @notice Maximum number of tokens in a single mintBatch or burnBatch call.
    /// @dev    Keeps gas costs predictable and protects against block-gas-limit DoS.
    uint256 public constant MAX_BATCH_SIZE = 50;

    // ─── Errors ───────────────────────────────────────────────────────────────

    /// @notice Thrown on any attempt to transfer a token between two non-zero addresses.
    error NonTransferable();

    /// @notice Thrown when `msg.sender` is not permitted to burn under the token's BurnAuth.
    error Unauthorized();

    /// @notice Thrown when querying or burning a token ID that does not exist (or was burned).
    error TokenDoesNotExist(uint256 tokenId);

    /// @notice Thrown by mintBatch/burnBatch when the parallel input arrays have different lengths.
    error ArrayLengthMismatch();

    /// @notice Thrown when a batch exceeds MAX_BATCH_SIZE.
    error BatchTooLarge(uint256 given, uint256 max);

    /// @notice Thrown when minting a credential for a keyId that already has an active token.
    /// @dev    Prevents double-issuance for the same Ed25519 signing key.
    error DuplicateActiveKey(bytes32 keyId, uint256 existingTokenId);

    // ─── Olympus-specific events ──────────────────────────────────────────────

    /// @notice Emitted when a token is minted and an Ed25519 key is bound to it.
    /// @param  tokenId The minted token ID.
    /// @param  keyId   The raw 32-byte Ed25519 public key that controls this credential.
    event KeyBound(uint256 indexed tokenId, bytes32 indexed keyId);

    /// @notice Emitted when a token is burned and its Ed25519 key binding is released.
    /// @param  tokenId The burned token ID.
    /// @param  keyId   The key that was bound to this credential (now free to re-issue).
    event KeyRevoked(uint256 indexed tokenId, bytes32 indexed keyId);

    // ─── Storage ──────────────────────────────────────────────────────────────

    struct CredentialData {
        BurnAuth burnAuth;
        bytes32  keyId;          // raw Ed25519 pubkey (32 bytes); bytes32(0) if not bound
        string   credentialType; // e.g. "journalist", "researcher"
        string   ledgerCommitId; // Olympus ledger commit (0x… BLAKE3 hash)
    }

    /// @notice Credential metadata stored per token ID.
    mapping(uint256 => CredentialData) private _credentials;

    /// @notice Maps an Ed25519 keyId to its currently active token ID.
    ///         Value is 0 when no active token exists for this key.
    mapping(bytes32 => uint256) public activeTokenByKeyId;

    uint256 private _totalMinted;
    uint256 private _totalBurned;

    // ─── Constructor ──────────────────────────────────────────────────────────

    /// @param admin Address that receives DEFAULT_ADMIN_ROLE, ISSUER_ROLE, and REVOKER_ROLE.
    ///              In production this should be a multisig; ISSUER_ROLE and REVOKER_ROLE
    ///              are then delegated to the hot-wallet via `grantRole`.
    constructor(address admin) ERC721("OlympusCredential", "OLYCRED") {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ISSUER_ROLE,        admin);
        _grantRole(REVOKER_ROLE,       admin);
    }

    // ─── Mint ─────────────────────────────────────────────────────────────────

    /// @notice Mint a soulbound credential to `to`, binding the given Ed25519 key.
    /// @dev    The Python backend (api/services/evm_mint.py) calls this after:
    ///           1. Verifying Ed25519 consent via credential_consents.accepted_at
    ///           2. Anchoring the issuance to the Olympus ledger (ledgerCommitId)
    ///           3. Deriving tokenId as SHA-256("olympus:sbt:v1:{credId}:{commitId}")
    ///           4. Passing the raw Ed25519 pubkey (32 bytes) as keyId
    ///
    /// @param to              Wallet that consented to receive this SBT.
    /// @param tokenId         Unique ID, derived off-chain from ledger commit hash.
    /// @param keyId           Raw 32-byte Ed25519 public key bound to this credential.
    /// @param burnAuth_       Burn authorization mode (immutable for the token's lifetime).
    /// @param credentialType  Human-readable type, e.g. "journalist".
    /// @param ledgerCommitId  Olympus ledger commit hash anchoring this issuance.
    /// @param uri             Token metadata URI (IPFS CID or Arweave hash).
    function mint(
        address         to,
        uint256         tokenId,
        bytes32         keyId,
        BurnAuth        burnAuth_,
        string calldata credentialType,
        string calldata ledgerCommitId,
        string calldata uri
    ) external onlyRole(ISSUER_ROLE) {
        _checkAndBindKey(keyId, tokenId);
        _credentials[tokenId] = CredentialData({
            burnAuth:       burnAuth_,
            keyId:          keyId,
            credentialType: credentialType,
            ledgerCommitId: ledgerCommitId
        });
        _mint(to, tokenId);
        _setTokenURI(tokenId, uri);
        unchecked { _totalMinted++; }
        emit Issued(address(0), to, tokenId, burnAuth_);
        emit KeyBound(tokenId, keyId);
    }

    // ─── Burn ─────────────────────────────────────────────────────────────────

    /// @notice Burn a credential, gated by its immutable BurnAuth.
    /// @dev    BurnAuth.Neither tokens are permanently locked; even DEFAULT_ADMIN_ROLE
    ///         cannot override this — it would require a contract upgrade.
    ///         Emits KeyRevoked so the keyId becomes available for re-issuance.
    function burn(uint256 tokenId) external {
        if (_ownerOf(tokenId) == address(0)) revert TokenDoesNotExist(tokenId);

        BurnAuth auth    = _credentials[tokenId].burnAuth;
        address  owner   = ownerOf(tokenId);
        bool     issuer  = hasRole(REVOKER_ROLE, msg.sender);
        bool     isOwner = (msg.sender == owner);

        if      (auth == BurnAuth.IssuerOnly && !issuer)              revert Unauthorized();
        else if (auth == BurnAuth.OwnerOnly  && !isOwner)             revert Unauthorized();
        else if (auth == BurnAuth.Both       && !issuer && !isOwner)  revert Unauthorized();
        else if (auth == BurnAuth.Neither)                             revert Unauthorized();

        bytes32 keyId = _credentials[tokenId].keyId;
        _releaseKey(keyId, tokenId);
        delete _credentials[tokenId];
        unchecked { _totalBurned++; }
        _burn(tokenId); // ERC721URIStorage._burn clears tokenURI automatically
        emit KeyRevoked(tokenId, keyId);
    }

    // ─── Batch operations ─────────────────────────────────────────────────────

    /// @notice Mint multiple credentials in a single transaction.
    /// @dev    All-or-nothing: if any individual mint fails the entire call reverts.
    ///         Enforces MAX_BATCH_SIZE to bound gas costs.
    ///         Enforces that no two tokens in the batch bind the same keyId, and that
    ///         no provided keyId already has an active token on-chain.
    ///         Emits the ERC-5484 Issued event AND the Olympus KeyBound event per token.
    ///
    /// @param tos             Recipient addresses (one per token).
    /// @param tokenIds        Deterministic token IDs (one per token).
    /// @param keyIds          Raw 32-byte Ed25519 pubkeys (one per token).
    /// @param burnAuths       Burn authorization modes (one per token).
    /// @param credentialTypes Credential type strings (one per token).
    /// @param ledgerCommitIds Olympus ledger commit hashes (one per token).
    /// @param uris            Token metadata URIs (one per token).
    function mintBatch(
        address[]  calldata tos,
        uint256[]  calldata tokenIds,
        bytes32[]  calldata keyIds,
        BurnAuth[] calldata burnAuths,
        string[]   calldata credentialTypes,
        string[]   calldata ledgerCommitIds,
        string[]   calldata uris
    ) external onlyRole(ISSUER_ROLE) {
        uint256 len = tos.length;
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);
        if (
            tokenIds.length        != len ||
            keyIds.length          != len ||
            burnAuths.length       != len ||
            credentialTypes.length != len ||
            ledgerCommitIds.length != len ||
            uris.length            != len
        ) revert ArrayLengthMismatch();

        for (uint256 i; i < len; ) {
            uint256 tokenId = tokenIds[i];
            bytes32 keyId   = keyIds[i];

            _checkAndBindKey(keyId, tokenId);
            _credentials[tokenId] = CredentialData({
                burnAuth:       burnAuths[i],
                keyId:          keyId,
                credentialType: credentialTypes[i],
                ledgerCommitId: ledgerCommitIds[i]
            });
            _mint(tos[i], tokenId);
            _setTokenURI(tokenId, uris[i]);
            emit Issued(address(0), tos[i], tokenId, burnAuths[i]);
            emit KeyBound(tokenId, keyId);
            unchecked { ++i; }
        }
        unchecked { _totalMinted += len; }
    }

    /// @notice Burn multiple issuer-controlled credentials in a single transaction.
    /// @dev    All-or-nothing for v1: reverts if ANY token in the batch cannot be
    ///         issuer-burned (does not exist, or has BurnAuth.OwnerOnly / BurnAuth.Neither).
    ///
    ///         The Python flush service pre-checks ownerOf for each token before
    ///         submitting, marking owner-burned tokens as 'skipped' in the queue DB
    ///         so they are excluded from the batch.  This keeps the contract semantics
    ///         clean while keeping the batch resilient to race conditions.
    ///
    ///         Only tokens with BurnAuth.IssuerOnly or BurnAuth.Both are eligible.
    ///         Emits KeyRevoked per burned token so keyIds become available for re-issuance.
    ///
    /// @param tokenIds IDs of the tokens to burn.
    function burnBatch(uint256[] calldata tokenIds) external onlyRole(REVOKER_ROLE) {
        uint256 len = tokenIds.length;
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);

        for (uint256 i; i < len; ) {
            uint256 tokenId = tokenIds[i];

            // Revert if token does not exist — the Python pre-flight should have
            // removed already-burned tokens before submitting.
            if (_ownerOf(tokenId) == address(0)) revert TokenDoesNotExist(tokenId);

            BurnAuth auth = _credentials[tokenId].burnAuth;
            // OwnerOnly and Neither cannot be issuer-burned; revert the whole batch.
            if (auth == BurnAuth.OwnerOnly || auth == BurnAuth.Neither) revert Unauthorized();

            bytes32 keyId = _credentials[tokenId].keyId;
            _releaseKey(keyId, tokenId);
            delete _credentials[tokenId];
            _burn(tokenId);
            emit KeyRevoked(tokenId, keyId);
            unchecked { ++i; }
        }
        unchecked { _totalBurned += len; }
    }

    // ─── Views ────────────────────────────────────────────────────────────────

    /// @inheritdoc IERC5484
    function burnAuth(uint256 tokenId) external view override returns (BurnAuth) {
        if (_ownerOf(tokenId) == address(0)) revert TokenDoesNotExist(tokenId);
        return _credentials[tokenId].burnAuth;
    }

    /// @notice Returns the full credential metadata stored for `tokenId`.
    function credentialOf(uint256 tokenId)
        external
        view
        returns (
            BurnAuth burnAuth_,
            bytes32  keyId,
            string memory credentialType,
            string memory ledgerCommitId
        )
    {
        if (_ownerOf(tokenId) == address(0)) revert TokenDoesNotExist(tokenId);
        CredentialData storage d = _credentials[tokenId];
        return (d.burnAuth, d.keyId, d.credentialType, d.ledgerCommitId);
    }

    /// @notice Live supply: minted tokens that have not been burned.
    function totalSupply() external view returns (uint256) {
        return _totalMinted - _totalBurned;
    }

    /// @notice Cumulative count of all tokens ever minted (monotonically increasing).
    function totalMinted() external view returns (uint256) {
        return _totalMinted;
    }

    /// @notice Cumulative count of all tokens ever burned (monotonically increasing).
    function totalBurned() external view returns (uint256) {
        return _totalBurned;
    }

    // ─── Non-transferability ──────────────────────────────────────────────────

    /// @dev OZ v5 routes every ownership change through `_update`.
    ///      We allow only mint (from == 0) and burn (to == 0); everything else reverts.
    ///      This covers transferFrom, safeTransferFrom, and any future OZ extension
    ///      that calls super._update — there is no bypass path.
    function _update(address to, uint256 tokenId, address auth_)
        internal
        override
        returns (address)
    {
        address from = _ownerOf(tokenId); // address(0) when token doesn't exist yet
        if (from != address(0) && to != address(0)) revert NonTransferable();
        return super._update(to, tokenId, auth_);
    }

    // ─── Interface support ────────────────────────────────────────────────────

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721URIStorage, AccessControl)
        returns (bool)
    {
        return
            interfaceId == type(IERC5484).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    // ─── Internal helpers ─────────────────────────────────────────────────────

    /// @dev Check that `keyId` has no active token, then record the binding.
    ///      Uses bytes32(0) as a sentinel for "no keyId" (anonymous credentials).
    function _checkAndBindKey(bytes32 keyId, uint256 tokenId) private {
        if (keyId != bytes32(0)) {
            uint256 existing = activeTokenByKeyId[keyId];
            if (existing != 0) revert DuplicateActiveKey(keyId, existing);
            activeTokenByKeyId[keyId] = tokenId;
        }
    }

    /// @dev Clear the keyId → tokenId binding on burn.
    function _releaseKey(bytes32 keyId, uint256 /*tokenId*/) private {
        if (keyId != bytes32(0)) {
            delete activeTokenByKeyId[keyId];
        }
    }
}
