# Status & Risk FAQ

This note answers the outstanding questions raised about protocol gaps, AI authorship controls, STH readiness, federation behavior, and sustainability.

## Set 1 — Protocol Gaps & Known Risks
- **STH signer key pinning:** Today `verify_sth_consistency` only checks signature validity. Before Phase 1 ships we will bind STH verification to the federation registry and reject STHs whose `signer_pubkey` is not present in the active registry snapshot. This is a Phase 1 gate item; until then the threat model treats unpinned STH signers as a detectable-but-not-blocking risk for gossip monitors.
- **Other accepted gaps:** The STH API still synthesizes history signatures/public keys from headers and the `scaffolding.view_change` helpers are flagged as Phase 1+ scaffolding. These are documented compatibility stubs rather than shipped functionality.
- **Guardian serves an inconsistent STH:** Detection is explicit—witnesses should treat mismatched STH roots or consistency failures as fork evidence and stop replication from that peer. There is no auto-rollback; operators are expected to quarantine the peer and publish fork evidence.

## Set 2 — AI Authorship & Correctness Confidence
- **CT math verification:** RFC 6962 semantics are exercised with property-based tests (`tests/test_merkle_proof_verification.py`) and consistency-specific cases (`tests/test_consistency_proofs.py`), covering CT-style promotion, depth bounds, and proof-node validation. Cross-language canonicalization vectors live in `verifiers/test_vectors`.
- **Human review status:** No independent cryptographer has signed off yet; external review is planned as a Phase 1 entrance criterion alongside the existing 33 unit/property tests and zk proof checks (`proofs/formal_verify.sh`).
- **Copilot/AI guardrails:** Protocol invariants are documented in-repo and enforced in review; PRs must pass `make check`, and maintainers review AI-authored diffs for hash domain separation, append-only linkage, and registry pinning before merge to prevent silent drift.

## Set 3 — Production Readiness & the `tree_size: 0` Problem
- **Fix implemented:** The STH gossip endpoints now report `tree_size` from `StorageLayer.get_leaf_count`, which counts SMT leaves up to the header timestamp. No schema migration is needed because it reuses `smt_leaves` (and optional `smt_checkpoints`) data already persisted.
- **Downstream reliance:** `schemas/verification_bundle.json` and the bundle verifier expect accurate `tree_size` for consistency proofs; the prior `0` placeholder blocked meaningful gossip monitoring and has been removed.
- **Minimal storage change:** Counting leaves against the existing `smt_leaves` index is the smallest change to make gossip usable for monitors; a future background job can materialize STH rows, but is not required for correctness.
- **SQLite fallback:** The in-memory/SQLite path is `_TEST_MODE` only for API tests; production remains PostgreSQL-only per `docs/08_database_strategy.md`.

## Set 4 — Federation & the Guardian Model
- **Quorum loss:** v1.0 runs single-operator by design; if Guardians are offline the Steward can still emit headers, but they are not federation-final (no quorum certificate). Monitors should flag missing acknowledgments rather than stall the ledger.
- **Registry evolution:** Static `examples/federation_registry.json` is a prototype; Phase 1 promotes it to an append-only, Steward-signed registry (≥2/3 Stewards) recorded as ledger/governance events per `docs/10_federation_governance.md`.
- **`scaffolding/view_change.py` scope:** It is a membership/window helper for Phase 1+ (grace periods, watermarks). It is not a complete view-change protocol and does not run in v1.0.

## Set 5 — Sustainability & Governance Document
- **Funder/steward status:** No committed funder or steward institution yet; conversations are focused on civic/open-government grantmakers and watchdog NGOs, but no agreements are in place.
- **First deployment target:** Intended pilot is a small-city/county records office or newsroom transparency partner willing to run a single Steward plus two Guardians in a monitored demo network.
- **Phase 1 completion bar:** Phase 1 is “done” only when (1) Guardian replication with quorum certificates is live, (2) the membership registry is append-only with signed rotations, (3) STHs are signer-pinned with non-zero `tree_size` and gossipable consistency proofs, and (4) checkpoints/quorum certs are anchored externally. A short milestone doc will be published alongside the registry cutover to track these gates.
