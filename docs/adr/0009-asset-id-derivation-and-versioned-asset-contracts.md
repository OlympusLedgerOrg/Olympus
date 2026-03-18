# ADR 0009: Asset ID Derivation and Versioned Asset Contracts

## Status
Accepted

## Context
- Olympus needs asset-layer implementation paths (`mint.py`, transfer logic, valuation) in future phases.
- We want to avoid a breaking schema migration after external integrators start consuming verification artifacts.
- The verification bundle already exists and should remain the cryptographic primitive that asset envelopes wrap.

## Decision
- Define `proof_asset.json` and `dataset_asset.json` as schema-only contracts before implementation.
- Treat `verification_bundle.json` as a versioned primitive and embed it as `verification_bundle` in both asset schemas.
- Standardize Asset ID derivation as a BLAKE3 fingerprint over four inputs:
  1. `canonical_claim`
  2. `merkle_root`
  3. `zk_public_inputs`
  4. `version`

### Normative Asset ID Formula
- Canonicalize `canonical_claim` and `zk_public_inputs` with Olympus JSON canonicalization rules:
  - `json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)`
- When `zk_public_inputs` is null (allowed for dataset assets), canonicalize it as the literal JSON token `null` (i.e., the direct output of `json.dumps(None, ...)`).
- `HASH_SEPARATOR` is the literal string `"|"` and separator bytes are `b"|"`.
- Build preimage bytes by joining UTF-8 values in this exact order using `HASH_SEPARATOR` from `protocol.hashes`:
  - `canonical_claim_json`
  - `merkle_root`
  - `zk_public_inputs_json`
  - `version`
- Compute digest with `hash_bytes(preimage)` (BLAKE3), and store the resulting hex digest as `asset_id.digest`.

### Null-Case Test Vector (Normative)
- Inputs:
  - `canonical_claim = {"claim_id":"dataset-claim-1","records":2}`
  - `merkle_root = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`
  - `zk_public_inputs = null`
  - `version = "1.0.0"`
- Canonicalized parts:
  - `canonical_claim_json = {"claim_id":"dataset-claim-1","records":2}`
  - `zk_public_inputs_json = null`
- Preimage UTF-8 string:
  - `{"claim_id":"dataset-claim-1","records":2}|0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef|null|1.0.0`
- Preimage bytes (hex):
  - `7b22636c61696d5f6964223a22646174617365742d636c61696d2d31222c227265636f726473223a327d7c303132333435363738396162636465663031323334353637383961626364656630313233343536373839616263646566303132333435363738396162636465667c6e756c6c7c312e302e30`
- Asset ID digest (`hash_bytes(preimage).hex()`):
  - `adc21c103a3750692b21c058858bd9c69d0f17ba83b076eb583a4612b320ecba`

## Consequences
- Future `mint.py` work becomes implementation against a stable contract instead of contract design in-flight.
- Asset wrappers can evolve append-only while keeping verification bundle compatibility.
- Out of scope for this ADR: transfer semantics, valuation logic, ownership state in ledger, issuer reputation.
