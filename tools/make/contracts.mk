## ─── EVM / Foundry targets ───────────────────────────────────────────────────
.PHONY: forge-install forge-build forge-test forge-test-v forge-coverage \
        forge-snapshot forge-clean anvil forge-deploy-local forge-grant-roles

## forge-install: Install OZ + forge-std into contracts/lib (run once per clone)
forge-install:
	cd contracts && \
	  forge install OpenZeppelin/openzeppelin-contracts@v5.1.0 --no-commit && \
	  forge install foundry-rs/forge-std --no-commit

## forge-build: Compile all Solidity contracts
forge-build:
	cd contracts && forge build

## forge-test: Run unit + fuzz + invariant tests (reproducible seed)
forge-test:
	cd contracts && forge test --fuzz-seed 0xdeadbeef

## forge-test-v: Verbose Forge run — shows gas, traces, and test names
forge-test-v:
	cd contracts && forge test -vvv --fuzz-seed 0xdeadbeef

## forge-coverage: Generate LCOV + terminal coverage report for contracts
forge-coverage:
	cd contracts && forge coverage --report lcov && forge coverage

## forge-snapshot: Write gas snapshot to .gas-snapshot (track regressions)
forge-snapshot:
	cd contracts && forge snapshot --fuzz-seed 0xdeadbeef

## forge-clean: Remove build artifacts (out/ and cache/)
forge-clean:
	cd contracts && forge clean

## anvil: Start a local Anvil chain — deterministic accounts, 1-second blocks
##        Account #0 (0xf39F…) has ETH and can be used as admin/minter in local dev.
anvil:
	anvil \
	  --chain-id 31337 \
	  --block-time 1 \
	  --mnemonic "test test test test test test test test test test test junk"

## forge-deploy-local: Deploy OlympusCredential to a running local Anvil instance.
##   Uses Anvil account #0 as broadcaster (admin).  The contract address is printed
##   to stdout; copy it into OLYMPUS_CONTRACT_ADDRESS in your .env.
forge-deploy-local:
	OLYMPUS_EVM_ADMIN=$${OLYMPUS_EVM_ADMIN:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266} \
	cd contracts && forge script script/Deploy.s.sol \
	  --rpc-url http://127.0.0.1:8545 \
	  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
	  --broadcast \
	  -vvv

## forge-grant-roles: Grant MINTER_ROLE + REVOKER_ROLE to the hot wallet via Cast.
##   Requires:
##     OLYMPUS_CONTRACT_ADDRESS — deployed contract address
##     OLYMPUS_EVM_HOT_WALLET   — wallet address to grant roles to
##     OLYMPUS_EVM_ADMIN_KEY    — private key of current DEFAULT_ADMIN_ROLE holder
forge-grant-roles:
	@if [ -z "$(OLYMPUS_CONTRACT_ADDRESS)" ]; then echo "Set OLYMPUS_CONTRACT_ADDRESS"; exit 1; fi
	@if [ -z "$(OLYMPUS_EVM_HOT_WALLET)" ];  then echo "Set OLYMPUS_EVM_HOT_WALLET";  exit 1; fi
	@if [ -z "$(OLYMPUS_EVM_ADMIN_KEY)" ];   then echo "Set OLYMPUS_EVM_ADMIN_KEY";   exit 1; fi
	cast send $(OLYMPUS_CONTRACT_ADDRESS) \
	  "grantRole(bytes32,address)" \
	  $$(cast call $(OLYMPUS_CONTRACT_ADDRESS) "MINTER_ROLE()(bytes32)") \
	  $(OLYMPUS_EVM_HOT_WALLET) \
	  --rpc-url $${OLYMPUS_EVM_RPC_URL:-http://127.0.0.1:8545} \
	  --private-key $(OLYMPUS_EVM_ADMIN_KEY)
	cast send $(OLYMPUS_CONTRACT_ADDRESS) \
	  "grantRole(bytes32,address)" \
	  $$(cast call $(OLYMPUS_CONTRACT_ADDRESS) "REVOKER_ROLE()(bytes32)") \
	  $(OLYMPUS_EVM_HOT_WALLET) \
	  --rpc-url $${OLYMPUS_EVM_RPC_URL:-http://127.0.0.1:8545} \
	  --private-key $(OLYMPUS_EVM_ADMIN_KEY)
	@echo "Roles granted to $(OLYMPUS_EVM_HOT_WALLET)"
