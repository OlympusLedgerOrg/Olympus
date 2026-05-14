# SBT Deployment Notes

Olympus credentials are native, non-transferable credentials first. The EVM SBT layer is an optional ERC-5484 mirror for deployments that want wallet-visible credentials.

## Current Flow

1. Issue an Olympus-native credential with `POST /key/credential`.
2. Bind a holder wallet with the wallet challenge flow, or provide a wallet address explicitly as an admin.
3. Queue the optional on-chain mirror with `POST /key/credential/{credential_id}/evm/mint-queue`.
4. Flush queued EVM operations with `POST /key/evm/flush`.
5. Check `GET /key/credential/{credential_id}` for `evm_status`.
6. Use `GET /sbt/metadata/{credential_id}` as the token metadata URI.

The Olympus-native credential remains authoritative. The on-chain SBT is a projection for wallets, explorers, and public display.

## Required Environment

Set these only when the EVM mirror is enabled:

```text
OLYMPUS_EVM_CONTRACT_ADDRESS=0x...
OLYMPUS_EVM_RPC_URL=http://127.0.0.1:8545
OLYMPUS_EVM_HOT_WALLET_KEY=...
```

Optional:

```text
OLYMPUS_EVM_CHAIN_ID=31337
OLYMPUS_EVM_MAX_BATCH=50
OLYMPUS_EVM_TX_TIMEOUT=120
OLYMPUS_BASE_URL=https://your-public-olympus.example
OLYMPUS_SBT_IMAGE_URI=ipfs://...
```

## Queue A Mint

Requires an API key with the `admin` scope.

```bash
curl -X POST "$OLYMPUS_API/key/credential/$CREDENTIAL_ID/evm/mint-queue" \
  -H "X-API-Key: $OLYMPUS_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "wallet_address": "0x1111111111111111111111111111111111111111",
    "flush": false
  }'
```

If `wallet_address` is omitted, Olympus uses the latest verified wallet binding for the credential holder and signing key.

## Flush Pending Mints

```bash
curl -X POST "$OLYMPUS_API/key/evm/flush" \
  -H "X-API-Key: $OLYMPUS_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "max_batch": 50,
    "mints": true,
    "burns": true,
    "reset_stale_submitted": true
  }'
```

`flush` spends gas through the configured hot wallet. Keep this endpoint admin-only in deployment.

## Status Values

`GET /key/credential/{credential_id}` returns:

- `none`: no on-chain mirror queued or all mint attempts were skipped
- `pending`: mint queued or submitted
- `anchored`: mint confirmed on-chain
- `revoked`: burn confirmed on-chain
- `failed`: latest mint attempt failed and can be retried

## Metadata

`GET /sbt/metadata/{credential_id}` returns ERC-721-compatible metadata for wallets and explorers. It is public and does not require an API key.
