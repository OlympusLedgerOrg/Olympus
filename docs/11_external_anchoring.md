# External Anchoring Implementation

Olympus optionally anchors ledger state to an external Timestamp Authority (TSA) using RFC 3161 TimeStampTokens (TST). Anchoring provides an independently verifiable wall-clock ordering for shard and ledger roots.

## What is Anchored

- **Primary**: Merkle forest root or shard header hash at the end of a batching window.
- **Optional**: Ledger entry hash for high-value events.
- **Metadata**: TSA certificate fingerprint (SHA-256), timestamped nonce, and batch window boundaries.

## Batching Strategy

- **Cadence**: Fixed interval (e.g., every 5 minutes) to amortize cost.
- **Window Closure**: At the end of the window, compute the target hash and request a TST.
- **Backpressure**: If anchoring fails, pause window closure until a successful TST is recorded; do not emit unanchored “closed” windows.
- **Redundancy**: Multiple TSA requests per window are allowed; verifiers accept any valid TST whose `messageImprint` matches the documented hash.

## Anchoring Flow (v1.0)

1. Compute the target hash (Merkle root or shard header hash).
2. Build an RFC 3161 `TimeStampReq` with `sha256` or `blake3` OIDs as supported by the TSA.
3. Send the request via `protocol.rfc3161.request_timestamp_quorum(...)` so the
   same shard header hash is submitted to two independent TSAs.
4. Store the raw TST bytes, TSA certificate chain, and SHA-256 fingerprint in the ledger entry metadata.
5. Finalize the batch only after `protocol.rfc3161.verify_timestamp_quorum(...)`
   succeeds for both required TSAs, and surface
   `protocol.rfc3161.timestamp_watchdog_status(...)` alerts when either anchor
   goes missing or stale.

## Verification Flow

1. Recompute the target hash locally.
2. Parse the TST and verify `messageImprint` equals the target hash.
3. Validate the TSA signature chain against **pinned fingerprints** or an approved trust store.
4. Check that the TST timestamp falls within the claimed batch window.
5. Record the verified anchor as evidence; multiple valid anchors are acceptable.

## Failure Handling

- **TSA Unreachable**: Retry with exponential backoff; keep the window open until an anchor succeeds or a manual override is recorded.
- **Invalid TST**: Reject the anchor and keep the window open; record the failure for audit.
- **Clock Skew**: Reject anchors whose timestamps fall outside the configured tolerance; emit an audit event.

## Production Policies

- Publish TSA certificate fingerprints in an append-only registry.
- Separate TSA credentials (if any) from protocol signing keys; no shared key material.
- Audit logs must include request/response transcripts (minus secrets) for forensic reconstruction.
- Anchoring configuration (cadence, target hash type, acceptance policy) is versioned and recorded in the ledger.

## References

- Implementation: `protocol/rfc3161.py`
- Ledger integration guidance: `docs/04_ledger_protocol.md`
- Governance requirements: `docs/10_federation_governance.md`
