# Olympus

**Olympus is a verifiable ledger for sensitive information.**

It's a Sharded Sparse Merkle Forest (SSMF) that turns institutional data, compliance actions, and oversight decisions into **cryptographically provable facts**—not dashboards, not trust-me PDFs, not promises.

At its core, Olympus answers one question with mathematical certainty:

> **"Can any party independently verify that this record existed at a specific time, hasn't been altered, and is part of the official state?"**

The answer is **yes**, offline, forever.

The repository is focused on protocol hardening: deterministic canonicalization, Merkle commitments, verifiable proofs, and developer tooling for inspecting and validating those primitives.

## Licensing

Olympus uses a **two-layer licensing model** to balance openness and sustainability:

### Open Source Core (Apache 2.0)
The cryptographic core and protocol implementation are licensed under **Apache License 2.0**:
- Protocol implementations (`protocol/`)
- Zero-knowledge circuits (`proofs/`)
- Storage layer (`storage/`)
- Schemas (`schemas/`)
- Verification tools (`verifiers/`)
- CLI tools (`tools/`)
- Examples and test vectors (`examples/`, `test_vectors/`)

**Why Apache 2.0?** Strong patent protection, enterprise-friendly, and protects cryptographic IP from patent trolls.

### Proprietary Components (Commercial License)
The application layer and enterprise features require a **commercial license** (see [`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md)):
- Web Application (`dashboard/`)
- Debug UI (`ui/`)
- API Gateway (`api/`)
- Cloud Service (hosted deployments)
- Enterprise features (SAML, audit exports, retention policies, etc.)

**For commercial licensing inquiries**, please contact the Olympus team.

This model allows the protocol to remain transparent and auditable while providing sustainable revenue through hosting, dashboards, integrations, and enterprise support.

### Revenue Distribution
Commercial revenue follows a transparent distribution model (see [`GOVERNANCE.md`](GOVERNANCE.md) and [`schemas/revenue_distribution.json`](schemas/revenue_distribution.json)):
- **40%** to operations (infrastructure, personnel, growth) — funded first
- **10%** to founder (project creation and leadership)
- **30%** to the Antman Civic Fund (founder-directed for-profit allocator; all inflows/outflows and purposes recorded on-ledger)
- **20%** to R&D (protocol enhancements, reviewed quarterly; may be adjusted based on findings with reductions flowing to civic remainder)
- **0%** to general civic (remainder is directed to the Antman Civic Fund)

**Antman Civic Fund control:** A for-profit allocator 100% controlled by the founder or a founder-appointed steward. All inflows/outflows and their purposes are recorded on-ledger while the founder directs destinations.

**Total civic-purpose allocations: 30%** (all via the founder-directed Antman Civic Fund with full on-ledger transparency).

## Trust & Threat Model (60-second summary)

- **Adversaries:** malicious submitters, compromised operators, and network attackers who can observe and modify traffic but cannot break modern cryptography.
- **What we defend:** append-only ledger integrity (BLAKE3 SMT + shard headers), verifiable provenance, and non-malleable redaction proofs (Poseidon + Groth16).
- **What we do not promise:** availability under single-operator failure (Guardian replication is Phase 1+), confidentiality of submitted content, or completeness of all possible records.
- **Why it holds:** dual-root commitments bind BLAKE3 ledger roots to Poseidon circuit roots; deterministic canonicalization removes parser ambiguity; shard headers are Ed25519-signed and timestamp-tokened; verification bundles allow offline re-validation.
- See [`docs/threat_model.md`](docs/threat_model.md) and [`docs/07_non_goals.md`](docs/07_non_goals.md) for the full threat/assurance boundaries.

## The Vision

A layered cryptographic infrastructure for real-world applications that require:

- **Legal/regulatory compliance** — immutable, independently auditable records
  for institutional documents, court records, and regulatory filings.
- **Auditable data provenance** — end-to-end verifiable data lineage for supply
  chains, financial audits, and any domain where chain-of-custody matters.
- **Privacy with accountability** — selective redaction capabilities
  (GDPR-compatible) that preserve cryptographic proofs of what was disclosed and
  what was withheld.
- **Cross-institutional consensus** — a federation of independent trusted
  parties that reaches quorum without requiring trust in any single
  institution. *(Basic federation quorum signing is prototyped in v1.0;
  full Guardian multi-node replication is a Phase 1+ roadmap item.)*

## Technical architecture

Olympus is built on a **Sharded Sparse Merkle Forest (SSMF)** architecture:

### 1. Shards (Local Truth)
Each jurisdiction and data stream (e.g. `watauga:2025:budget`) has its own **Sparse Merkle Tree**:
- Records are committed as cryptographic leaves
- Each shard has its own root hash
- Updates are append-only and ordered

### 2. Forest (Global Truth)
All shard roots are committed into a second Sparse Merkle Tree—the **Forest**:
- `forest_key = hash(shard_id)`
- `forest_value = shard_root`
- The forest root represents the **entire system state**

This creates a single, deterministic **global state root**.

### 3. Signatures (Authority Without Trust)
Every state update produces a **signed header**:
- Ed25519 signature over the shard root and forest root
- Anyone can verify authenticity without trusting the operator

### Pipeline

Olympus follows a strict, auditable pipeline:

```text
Ingest → Canonicalize → Hash → Commit → Prove → (Replicate, Phase 1+) → Verify
```

- **Implemented in v1.0:** Ingest, Canonicalize, Hash, Commit, Prove, Verify
- **Phase 1+ (not implemented in v1.0):** Replicate (Guardian multi-node
  replication)

Core technical guarantees:

- Deterministic canonicalization for stable, reproducible document bytes
- Domain-separated BLAKE3 hashing for collision-resistant commitments
- Sparse Merkle structures for inclusion/non-membership proofs
- Append-only ledger linkage for tamper-evident history
- Independent verification paths through CLI tools and cross-language verifiers

See [`docs/architecture.md`](docs/architecture.md) for the complete
stage-to-module mapping and dependency flow.

## Technology stack

- **Language/runtime:** Python 3.10+ (3.12 in CI/dev tooling)
- **Core architecture:** Sharded Sparse Merkle Forest (SSMF) with dual-root commitments (BLAKE3 + Poseidon)
- **API/UI framework:** FastAPI + Starlette + Uvicorn (API), Next.js 15 + React 19 (Dashboard)
- **Cryptography:** BLAKE3 hashing, Ed25519 signatures (PyNaCl), RFC3161
  timestamping support, Poseidon hashing (BN128) for ZK circuits
- **Zero-knowledge proofs:** Circom circuits, Groth16 backend (primary), Halo2 backend (alternative for recursive proofs)
- **Data/storage:** PostgreSQL integration via psycopg/psycopg-pool
- **Proof tooling:** Merkle and redaction primitives in `protocol/`, sparse Merkle trees (`protocol/ssmf.py`), epochs and checkpoints, attestations and anchors
- **Quality tooling:** Ruff, mypy, Bandit, pytest, Hypothesis

## Current repository state

The primary local developer workflows are:

- `python -m pip install -e ".[dev]"` — install the package plus development
  tooling.
- `make help` — list all available make targets with descriptions.
- `make check` — run schema validation, Ruff, mypy, Bandit, and the Python test
  suites (includes `boundary-check`).
- `make vectors` — verify golden test vectors deterministically (canonicalization
  + hashing regression detection).
- `make boundary-check` — verify protocol module import boundaries are intact.
- `make lint` — run Ruff + mypy + Bandit without running tests.
- `make format` — auto-format code with Ruff.
- `make smoke` — run the PostgreSQL-backed smoke path defined in
  `tools/dev_smoke.sh`.
- `make dev` — start the FastAPI API on `127.0.0.1:8000` and the debug UI on
  `127.0.0.1:8080`.

The smoke test currently provisions PostgreSQL with Docker Compose, initializes
the schema, imports the test-only app, and runs the `postgres`-marked pytest
suite.

## Documentation

See [`docs/README.md`](docs/README.md) for a full index of the documentation.
See [`docs/architecture.md`](docs/architecture.md) for the pipeline → module
map and developer entrypoints.
- Governance & sustainability plan: [`GOVERNANCE.md`](GOVERNANCE.md)

## Repository scaffold

```text
api/         FastAPI application and ingestion routes (Commercial License)
dashboard/   Next.js 15 + React 19 web application (Commercial License)
ui/          FastAPI debug console and public verification portal (Commercial License)
scaffolding/ non-production helpers (test-only FastAPI wiring, view-change scaffolding)
docs/        protocol notes, threat model material, and walkthroughs
examples/    sample artifacts and notebook examples
integrations/ interoperability helpers for Ethereum/IPFS-style bridges
proofs/      Circom circuits, proving assets, and JS-based proof tooling (Apache 2.0)
protocol/    reference implementations of hashing, Merkle, SSMF, and redaction logic (Apache 2.0)
schemas/     JSON schema definitions validated by tools/validate_schemas.py (Apache 2.0)
storage/     persistence layer implementations and schema bootstrap logic (Apache 2.0)
tests/       regression tests for protocol, API, UI, and smoke/dev workflows
tools/       command-line helpers, schema validation, and dev smoke script (Apache 2.0)
verifiers/   cross-language verifier implementations (Python, Go, JS, Rust) (Apache 2.0)
```

## Quick start

```bash
git clone https://github.com/wombatvagina69-crypto/Olympus.git
cd Olympus
python -m pip install -e ".[dev]"
```

### Quality gate

```bash
make check
```

### Smoke test

The smoke target expects Docker Compose so it can start PostgreSQL locally.

```bash
make smoke
```

### Run the API + UI locally

```bash
export DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
export TEST_DATABASE_URL="$DATABASE_URL"
make dev
```

## Federation Architecture

Olympus operates as a federated transparency log. Multiple independent nodes
maintain shard state and sign shard headers, so no single node can rewrite
history once a federation quorum has acknowledged a header.

Prototype components in this repository:

- `protocol/federation.py` — persistent node identity, static registry loading,
  and a simple `>= 2/3` shard-header quorum model
- `examples/federation_registry.json` — static federation membership for local
  development and tests
- `docker-compose.federation.yml` and `make federation-dev` — local three-node
  federation simulation

Federation data flow:

```text
client
  ↓
commit request
  ↓
node receives commit
  ↓
node updates shard tree
  ↓
node proposes shard header
  ↓
federation nodes sign header
  ↓
header finalized
  ↓
global state root updated
```

Useful prototype commands:

```bash
python tools/olympus.py node list
python tools/olympus.py federation status
python tools/olympus.py ingest examples/pipeline_golden_example.json --api-key demo-key --generate-proof --verify --json
make federation-dev
bash examples/run_local_testnet_demo.sh
```

Olympus is influenced by the operational model of Certificate Transparency and
Sigstore: transparency logs, multiple operators, and independent verification.

## Key developer entrypoints

- API application: `api/app.py`
- Debug UI / verification portal: `ui/app.py`
- Canonicalization + verification CLIs: `tools/canonicalize_cli.py`,
  `tools/verify_cli.py`, `tools/verify_bundle_cli.py`, and `tools/olympus.py`
- Zero-knowledge proof setup and smoke docs: `proofs/README.md`
- Runnable demos: `examples/README.md`
- Interoperability helpers: `integrations/README.md`
- Extended setup guide: `QUICKSTART.md`
- Contribution workflow: `CONTRIBUTING.md`

## Notes

- Python requirement: `>=3.10` (3.12 is used in CI/dev tooling).
- The debug console is disabled by default; set `OLYMPUS_DEBUG_UI=true` when
  running the UI directly.
- The public verification portal remains available at `/verification-portal`
  even when debug-only routes are disabled.

## External Security Review

Olympus is designed to be audit-friendly, and external review is encouraged:

- Security policy and coordinated disclosure: [`SECURITY.md`](SECURITY.md)
- Penetration-test scope for third-party auditors:
  [`docs/pentest-scope.md`](docs/pentest-scope.md)
- Public bug-bounty intake channel (HackerOne):
  <https://hackerone.com/olympus>
