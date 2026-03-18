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
  - `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
- Build preimage bytes by joining UTF-8 values in this exact order using `HASH_SEPARATOR` from `protocol.hashes`:
  - `canonical_claim_json`
  - `merkle_root`
  - `zk_public_inputs_json`
  - `version`
- Compute digest with `hash_bytes(preimage)` (BLAKE3), and store the resulting hex digest as `asset_id.digest`.

## Consequences
- Future `mint.py` work becomes implementation against a stable contract instead of contract design in-flight.
- Asset wrappers can evolve append-only while keeping verification bundle compatibility.
- Out of scope for this ADR: transfer semantics, valuation logic, ownership state in ledger, issuer reputation.
