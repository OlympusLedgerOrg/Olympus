// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {OlympusCredential} from "../src/OlympusCredential.sol";

/// @notice Deploy OlympusCredential.
///
/// Required env vars:
///   OLYMPUS_EVM_ADMIN   — address that receives DEFAULT_ADMIN_ROLE at deployment.
///                         In production this should be a multisig.  The hot-wallet
///                         is then granted MINTER_ROLE and REVOKER_ROLE separately.
///
/// Example (local Anvil):
///   OLYMPUS_EVM_ADMIN=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
///   forge script script/Deploy.s.sol \
///     --rpc-url http://127.0.0.1:8545 \
///     --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
///     --broadcast -vvv
contract Deploy is Script {
    function run() external returns (address) {
        address admin = vm.envAddress("OLYMPUS_EVM_ADMIN");

        vm.startBroadcast();
        OlympusCredential cred = new OlympusCredential(admin);
        vm.stopBroadcast();

        console2.log("OlympusCredential:", address(cred));
        console2.log("Admin:            ", admin);
        console2.log("MINTER_ROLE:      ", vm.toString(cred.MINTER_ROLE()));
        console2.log("REVOKER_ROLE:     ", vm.toString(cred.REVOKER_ROLE()));

        return address(cred);
    }
}
