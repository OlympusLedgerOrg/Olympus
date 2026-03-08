# Public Explorer Interface

The public explorer is a **read-only**, zero-auth interface for citizens, auditors, and journalists to inspect Olympus state. It consumes protocol artifacts without adding new trust assumptions.

## Goals

- Make ledger, shard headers, and proofs discoverable without credentials.
- Provide human-friendly views backed by verifiable data (hashes, signatures, anchors).
- Keep provenance obvious: every UI element should link back to canonical JSON or proof material.

## Minimum Capabilities

- **Search & Browse**
  - List shards and latest headers (seq, root hash, previous hash, signature, timestamp).
  - View recent ledger entries per shard with canonical JSON and entry hashes.
  - Keyword / ID lookup for documents, receipts, and redaction proofs.
- **Proof Retrieval**
  - Download Merkle proofs for records and SMT paths.
  - Download redaction proof bundles (Poseidon commitments + revealed leaves).
  - Download RFC 3161 timestamp tokens and TSA certificate fingerprints.
- **Verification Aids**
  - Inline hash recomputation results and signature checks using in-browser WASM or linkable CLI commands.
  - Cross-node comparison view to surface forks or replication gaps (Phase 1+).
- **Transparency Artifacts**
  - Governance events (admit/evict/rotate/upgrade) with signatures.
  - Anchor history with batch windows and TST metadata.

## Non-Goals

- No write paths (submissions, redactions, or mutations).
- No custodial wallet, token, or credential management.
- No reliance on hidden APIs; every rendered item must be fetchable from documented endpoints.

## Implementation Notes

- Back the explorer with the read-only API described in `api/app.py`; do not expose internal admin APIs.
- Prefer static rendering backed by signed JSON responses to minimize active attack surface.
- Caching is allowed but must not hide conflicting responses across nodes; cache keys should include the source node identity.
- Accessibility and print-friendly exports are required for legal and audit workflows.

## Operational Requirements

- Served over TLS with strict transport security.
- Deterministic builds; published build hashes should match the served assets.
- Monitor for divergence between explorer data and offline CLI verification results; raise alarms on mismatch.

See `docs/12_protocol_vs_applications.md` for boundary guidance and `docs/10_federation_governance.md` for federation-aware monitoring expectations.
