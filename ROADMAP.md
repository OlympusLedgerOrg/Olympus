# Olympus Roadmap

This is the **public roadmap** for Olympus. It exists so adopters, contributors,
funders, and auditors can see where the project is going and where they can
help. It is intentionally directional, not a contract — dates are targets, and
priorities shift with security findings and community input.

- **Decision process:** [`docs/governance.md`](docs/governance.md)
- **How larger changes are proposed:** the RFC process in
  [`docs/rfcs/README.md`](docs/rfcs/README.md)
- **Release history & protocol changes:** [`CHANGELOG.md`](CHANGELOG.md)
- **Architecture rationale:** [`docs/adr/`](docs/adr/)

Items below link to their tracking issue where one exists. To propose a change
to this roadmap, open a GitHub issue tagged `roadmap`, or an RFC for anything
that affects protocol semantics, the threat model, or governance.

## Now — v0.10.x (current, mid-2026)

Shipping and hardening the self-contained desktop node.

- ✅ Tauri 2 desktop app: embedded Axum server + pg_embed PostgreSQL, no
  external runtime.
- ✅ BLAKE3 CD-HS-ST sparse Merkle tree with operator-controlled shard registry.
- ✅ Native Rust Groth16 prover/verifier (arkworks 0.6); four production
  circuits wired to `/zk/prove` and `/zk/verify`.
- ✅ PDF object-level redaction (ADR-0025) with non-malleable proofs.
- ✅ External anchoring: RFC 3161 TSA, Sigstore Rekor, OpenTimestamps.
- ✅ Olympus-native SBT credentials with optional M-of-N federation quorum.
- 🔨 Packaging and first-run reliability: signed installers, startup-error
  surfaces, local DB recovery — making the demo path runnable by non-developers.
- 🔨 Community & governance layer: Code of Conduct, maintainer ladder,
  this roadmap, operational governance, RFC process (this milestone).

## Next — toward v1.0 (late 2026)

The release bar for v1.0 is **production-grade trust setup + reduced
single-operator risk + external review**.

- ☐ **Production Groth16 ceremony.** Multi-contributor Phase-2 ceremony
  (`proofs/phase2_ceremony.sh`) replacing the single-contributor dev setup;
  published transcripts and signed manifests. *Required to tag v1.0.*
- ☐ **Federation MVP.** Multi-node Guardian replication and quorum-signed
  checkpoints so the ledger no longer depends on a single operator for
  availability and equivocation detection. (Today this is feature-gated and
  partial.)
- ☐ **Independent security audit.** Third-party cryptographic/implementation
  review of `crates/olympus-crypto`, `src-tauri/`, `proofs/`, and `verifiers/`,
  with remediations tracked as public PRs (see `SECURITY.md`).
- ☐ **Hardened, portable proof-bundle format** with stronger offline verifier
  tooling and sample packages for non-technical reviewers.
- ☐ **Pilot deployment** alongside a real public-records / clerk workflow
  (see [`GRANTS.md`](GRANTS.md)).
- ☐ **Multi-maintainer governance in effect** — at least two to three active
  maintainers and a populated [`MAINTAINERS.md`](MAINTAINERS.md) roster, moving
  governance from bootstrapping to steady-state.

## Later — post-1.0 (2027+)

Directional; not yet committed.

- ☐ External verifier ecosystem: additional language implementations and a
  conformance suite built on `verifiers/test_vectors/`.
- ☐ Optional Halo2 / recursive proofs for high-assurance contexts.
- ☐ Document-portal integrations for existing clerk and records workflows.
- ☐ Broader anchoring options and stronger availability guarantees under
  operator failure.

## How priorities are set

1. **Security findings** take precedence over feature work — always.
2. **Protocol-impacting changes** require an ADR and follow the RFC process.
3. **Community input** via `roadmap`-tagged issues and RFCs shapes ordering;
   maintainers reconcile competing priorities under `docs/governance.md`.

_Legend: ✅ done · 🔨 in progress · ☐ planned._
