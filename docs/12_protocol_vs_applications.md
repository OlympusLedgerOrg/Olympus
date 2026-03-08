# Protocol vs Applications

Olympus distinguishes between the **protocol** (cryptographic rules and data formats) and **applications** (APIs, UIs, ingestion services). This separation keeps proofs stable even as product surfaces evolve.

## Protocol Surface (Stable)

- Canonicalization rules and versions (`protocol.canonical*`, `protocol.canonicalizer`)
- Hashing and domain separation (`protocol.hashes`, `protocol.poseidon_tree`)
- Merkle/Sparse Merkle commitment formats (`protocol.merkle`, `protocol.ssmf`)
- Ledger and shard header schemas, signature rules, and hash chaining (`protocol.ledger`, `protocol.shards`)
- Redaction commitments and verification circuits (`protocol.redaction`, `proofs/circuits`)
- External anchoring evidence formats (`protocol.rfc3161`)
- Timestamp format (`protocol.timestamps`) and canonical JSON encoding (`protocol.canonical_json`)

**Non-negotiable property**: Any change that would alter canonical bytes or cryptographic verification constitutes a protocol version change and must be additive and explicit.

## Application Surface (Evolving)

- HTTP APIs, GraphQL, or gRPC facades around the protocol
- Web consoles, public explorers, dashboards
- Ingestion pipelines, OCR or format converters feeding canonicalizers
- Notifications, analytics, and operational monitoring
- Authentication/authorization wrappers for submission endpoints

Applications may change without invalidating proofs **as long as** they continue to emit protocol-compliant artifacts and ledger entries.

## Dependency Boundaries

- Protocol modules depend only on deterministic, version-pinned libraries. They must not import UI, web frameworks, or database ORMs.
- Application layers may import protocol modules but must treat them as pure libraries; no application logic should modify protocol state representations in place.
- Storage (`storage/`) is part of the protocol boundary for append-only semantics but may be swapped if the same invariants and schemas are preserved.

## Extension Rules

- New artifact formats or canonicalizer versions are appended (never mutated) and referenced explicitly in results.
- New application features must not bypass canonicalization or hash chaining.
- Cross-system integrations (e.g., public explorer, federation monitoring) consume protocol outputs (hashes, proofs, anchors) rather than redefining them.

## Testing Expectations

- Protocol changes require golden vectors and compatibility tests across versions.
- Application changes must keep existing protocol tests green; UI tests should never rewrite canonical data.

For governance of federated deployments, see `docs/10_federation_governance.md`. For public explorer requirements, see `docs/13_public_explorer.md`.
