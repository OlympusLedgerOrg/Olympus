// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {OlympusCredential} from "../src/OlympusCredential.sol";
import {IERC5484}          from "../src/interfaces/IERC5484.sol";

/// @notice Mint a single OlympusCredential token.  Intended for Cast/CI use and
///         local dev smoke-testing.  Production mints go through the Python service
///         (api/services/evm_mint.py) which derives the token ID deterministically
///         and records consent in the DB before broadcasting.
///
/// Required env vars:
///   OLYMPUS_CONTRACT_ADDRESS — deployed OlympusCredential (checksummed)
///   MINT_TO                  — recipient wallet address
///   MINT_TOKEN_ID            — uint256 token ID (decimal or 0x hex)
///   MINT_BURN_AUTH           — 0=IssuerOnly 1=OwnerOnly 2=Both 3=Neither
///   MINT_CRED_TYPE           — credential type string, e.g. "journalist"
///   MINT_COMMIT_ID           — Olympus ledger commit hash (0x…)
///   MINT_URI                 — token metadata URI, e.g. "ipfs://QmXxx"
///
/// Example (local Anvil, Anvil account #0 as minter):
///   OLYMPUS_CONTRACT_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3 \
///   MINT_TO=0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
///   MINT_TOKEN_ID=1 \
///   MINT_BURN_AUTH=0 \
///   MINT_CRED_TYPE=journalist \
///   MINT_COMMIT_ID=0xdeadbeef \
///   MINT_URI="ipfs://QmOlympus" \
///   forge script script/Mint.s.sol \
///     --rpc-url http://127.0.0.1:8545 \
///     --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
///     --broadcast -vvv
contract Mint is Script {
    function run() external {
        address contractAddr = vm.envAddress("OLYMPUS_CONTRACT_ADDRESS");
        address to           = vm.envAddress("MINT_TO");
        uint256 tokenId      = vm.envUint("MINT_TOKEN_ID");
        uint8   burnAuthInt  = uint8(vm.envUint("MINT_BURN_AUTH"));
        string  memory credType  = vm.envString("MINT_CRED_TYPE");
        string  memory commitId  = vm.envString("MINT_COMMIT_ID");
        string  memory uri       = vm.envString("MINT_URI");

        require(burnAuthInt < 4, "MINT_BURN_AUTH must be 0-3");

        OlympusCredential cred = OlympusCredential(contractAddr);
        IERC5484.BurnAuth auth = IERC5484.BurnAuth(burnAuthInt);

        vm.startBroadcast();
        cred.mint(to, tokenId, auth, credType, commitId, uri);
        vm.stopBroadcast();

        console2.log("Minted token", tokenId, "to", to);
        console2.log("BurnAuth:    ", burnAuthInt);
        console2.log("CredType:    ", credType);
        console2.log("CommitId:    ", commitId);
    }
}
