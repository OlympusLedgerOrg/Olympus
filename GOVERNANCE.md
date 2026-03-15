# Olympus Governance & Sustainability (Aspirational)

Olympus is entering a protocol-hardening phase with an explicit plan for long-term stewardship. This document captures the intended governance posture so funders, auditors, and collaborators can evaluate sustainability beyond any single contributor.

## Principles
- **Protocol-first:** the ledger and proof semantics are stable, versioned, and documented (see `docs/adr/`).
- **Transparency:** all decisions and releases are documented via ADRs and signed tags.
- **Multi-party resilience:** Phase 1+ introduces Guardian replication and quorum-signed shard headers to reduce operator single points of failure.

## Roles
- **Maintainers:** steward the reference implementation, review PRs, and publish releases.
- **Security response contacts:** own coordinated disclosure and patch issuance (see `SECURITY.md`).
- **Contributors:** community members submitting PRs and proposals (see `CONTRIBUTING.md`).

## Decision Process
- **Technical changes:** require PR + review + passing CI + ADR for architectural shifts.
- **Breaking changes:** must include a migration note, version bump, and ADR.
- **Cryptographic parameters:** changes require a new ADR and signed release tag.

## Versioning & Releases
- Semantic-ish versioning during 0.x hardening: `0.<minor>.<patch>`.
- Release artifacts (tags) are signed; changelogs enumerate protocol-impacting changes.
- ZK keys and ceremony transcripts are versioned and stored under `proofs/` and `ceremony/`.

## Roadmap & Stewardship
- **Phase 0.x:** protocol hardening (current) — single-operator storage, dual-root commitments, Groth16 proofs.
- **Phase 1:** Guardian replication and federation hygiene; stronger availability guarantees.
- **Phase 1+:** optional Halo2 / recursive proofs for high-assurance contexts.

## Revenue Distribution Model

Olympus operates under a dual licensing model (see `LICENSE` and `LICENSE-COMMERCIAL.md`). Revenue from commercial licensing follows a transparent distribution model that prioritizes civic responsibility and public good.

### Distribution Structure
- **10% Founder**: Minimal compensation for project creation, vision, and ongoing leadership
- **10% Operations**: Operational expenses with room for growth (infrastructure, personnel, marketing, legal, etc.)
- **70% Civic**: Public good initiatives, open source development, education, community grants, and democracy infrastructure projects
- **10% R&D**: Protocol enhancements, cryptographic improvements, and innovation

This civic-first structure ensures that the majority of commercial revenue (70%) directly serves the public interest. The distribution is documented in `schemas/revenue_distribution.json` with a reference implementation in `examples/revenue_distribution_v1.json`. The distribution model is reviewed annually and may be adjusted based on business needs and market conditions.

## Sustainability Signals
- ADR coverage for critical design decisions (hash separation, dual commitments, ledger vs redaction path).
- Public threat model and security scope (see `docs/threat_model.md` and `docs/pentest-scope.md`).
- Documented trusted-setup process with dev transcripts (`ceremony/`), emphasizing non-production status.
- Clear intake for security reports with a PGP key (`SECURITY.md`).
- Transparent revenue distribution model ensuring civic engagement and R&D investment.

## Escalation & Succession
- If a maintainer becomes unavailable, remaining maintainers (or designated stewards) will:
  1. Rotate signing keys for releases and shard headers.
  2. Publish an ADR and signed notice documenting the change.
  3. Invite additional maintainers from active contributors to restore redundancy.

This governance plan is intentionally lightweight and will evolve with community and funder feedback.
