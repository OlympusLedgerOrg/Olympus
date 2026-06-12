# ADR-0027: Dataset-manifest commitments + client CLI/SDK

- **Status:** **Accepted — 2026-06-12.**
- **Date proposed:** 2026-06-12
- **Builds on:** ADR-0003 (parser-version leaf binding), ADR-0004 (model-hash
  leaf binding), ADR-0005 (structured leaf prefix + shard binding), ADR-0009
  (Poseidon suite), ADR-0022 (lazy deep-node SMT). This ADR adds a
  **client-side product layer** on top of the existing commitment primitives; it
  introduces **no new on-chain/leaf domain** and does not change any committed
  byte layout.
- **Related invariants:** the leaf/node domain rules (ADR-0005), the
  Critical-Invariant rule that a leaf-layout change moves `olympus-crypto` + both
  verifiers + golden vectors together (untouched here — the manifest reuses
  `leaf_hash`/`node_hash` unchanged), and the language-ownership boundary
  (security-critical crypto stays in Rust).

## Context

Olympus committed data **one record at a time** through `/ingest/files`: each
file is a leaf in the global Sparse Merkle Tree (SMT), keyed by
`shard_record_key(shard_id, record_key(record_type, record_id, version))` and
valued by the record's BLAKE3 content hash (ADR-0003/0004/0005). The desktop app
and two internal binaries (`export_ark_zkey`, `generate_manifest`) are operator
tooling, not a customer surface.

A lab that wants to put Olympus in a training-data pipeline needs something the
record-at-a-time API does not provide:

1. **A pip/cargo-installable client** that hashes shards locally, builds a
   commitment, commits its root, and pulls proofs — runnable headless in a data
   pipeline, with no Tauri app and no GUI.
2. **A dataset manifest as a first-class object**: a defined schema (shard list,
   per-shard roots, dataset metadata) where **one commit covers millions of
   records**, with record-level **inclusion *and* exclusion** proofs against a
   single `manifest_root`.
3. **Incremental version commits**: `v2 = v1 − removed + added` with a proof
   linking the versions, so daily curation is affordable.

The hard design question is the commitment structure for (2)/(3): it must give
**sound non-membership** (an auditor must be able to verify "record X is *not* in
this dataset version" without trusting the committer) and must scale to millions
of records, while staying compatible with the existing verifiers and the
`document_existence`/`non_existence` ZK circuits.

## Decision

### 1. `manifest_root` *is* the Olympus SMT global root

A dataset manifest commits its records as leaves in the **existing** 256-height
SMT (`olympus_crypto::smt`). `manifest_root` is that tree's global root. We
deliberately **reuse** the SMT instead of inventing a bespoke (e.g. sorted-leaf)
tree, because:

- **Sound exclusion.** Sparse-tree non-membership is sound against an
  adversarial committer: the key path is fixed by `record_id` (not chosen by the
  prover) and the empty-leaf sentinel cannot be forged. A sorted-leaf Merkle tree
  *cannot* prove non-membership without revealing the whole set, and is only
  sound if the verifier trusts the committer to have sorted honestly — which
  defeats the "independently verifiable" property.
- **Verifier and circuit reuse.** Roots and proofs are byte-identical to what the
  desktop node produces, so the Rust/JavaScript offline verifiers and the
  `document_existence` / `non_existence` Groth16 circuits validate manifest
  proofs unchanged. A client-built manifest root is reproducible by a node.
- **No new protocol surface.** No new leaf/node domain, no migration, no change
  to any golden vector.

### 2. The committed manifest document is compact; the record index is not

The manifest **document** (`DatasetManifest`) carries only dataset metadata,
per-shard subtree roots + counts, and `manifest_root` — never the record list —
so one small blob commits an arbitrarily large dataset. It is committed to the
ledger as an ordinary file via `/ingest/files`; its BLAKE3 content hash anchors
the whole version, and the anchored bytes contain `manifest_root`. The full
`record_id → content_hash` mapping (`RecordIndex`) is the prover's working set,
committed only *by reference* (through the root it produces) and never embedded
in the commitment.

This is what makes "one commit covering millions of records" literal: the commit
is a few hundred bytes regardless of dataset size.

### 3. Path-compressed batch builder

The reference in-memory SMT materialises up to 256 nodes per leaf, so it cannot
build a 10M-record tree. `olympus_manifest::smt_batch` builds a **path-compressed**
tree over the leaves sorted by key: one branch node per real branch point
(`O(N)` nodes), compressed single-child runs whose off-path siblings are the
precomputed empty-subtree hashes, and lone-leaf ladders. Build is `O(N·256)`
hashing worst case; a proof is `O(256)`. The output is byte-identical to the
reference tree — the reference `SparseMerkleTree` is the parity oracle in tests
(`smt_batch::tests::parity_with_reference_smt`, sizes 1‥1000 incl. prefix-sharing
non-membership). Measured: **1M records sealed in ~35 s single-threaded; proofs
in ~0.02 ms / ~30 KB** (see `docs/benchmarks/manifest-throughput.md`).

### 4. Incremental versions

A `ManifestDiff` records the added/removed `RecordRef`s between a parent and
child version and commits to that change set with a domain-separated
`diff_root = BLAKE3("OLY:MANIFEST:DIFF:V1" ‖ u32(count) ‖ sorted entries…)`. The
child manifest carries a `ParentRef` (binding the parent's `manifest_root`) and a
`DiffSummary` (carrying `diff_root`). Together these give a cheap **structural**
link. The **record-level** guarantee is established on demand: each removed
record has an inclusion proof in the parent + an exclusion proof in the child;
each added record, the reverse. (`OLY:MANIFEST:DIFF:V1` is a manifest-layer
commitment domain, disjoint from the protocol SMT leaf/node domains.) The
"removed" half is the natural ZK pairing with the redaction circuit — a removal
is a redaction.

### 5. Client packaging

- `crates/olympus-manifest` — the schema + commitment + proofs (shared Rust
  library, workspace member, the source of truth).
- `clients/cli` — the `olympus` binary: `cargo install`-able, **excluded** from
  the main workspace (own release cadence, like `verifiers/rust`). Offline core
  (`build`/`prove`/`verify`/`diff`/`link`/`hash`) has **zero** extra
  dependencies; network `commit`/`fetch` are behind a `server` feature
  (blocking reqwest, rustls — no OpenSSL/GPL).
- `clients/python` — a pip-installable Python SDK (`olympus-manifest`) that
  verifies proofs and talks to a node. It re-implements the domain-separated
  hashing and proof verification, pinned byte-for-byte against vectors generated
  from the Rust crate (`gen_python_vectors` → `tests/test_parity.py`). Like the
  JavaScript verifier it is verify-only; the authoritative `manifest_root` is
  produced by the Rust builder.

Security-critical hashing/commitment stays in Rust (`olympus-manifest`); clients
in other languages only re-verify, consistent with the language-ownership rule.

## Consequences

- **New capability, no protocol risk.** The desktop node, migrations, and
  ceremony are untouched; the manifest layer is additive and lives client-side.
- **Reproducibility.** Because leaves use the canonical `leaf_hash`, a node can
  re-derive a client's `manifest_root` from the same records, and a future native
  `/manifest/*` endpoint can adopt the exact same root with no format change.
- **Shard-scoped exclusion.** Non-membership is proved per shard (the common
  audit question, "is record X in shard S?"). Dataset-wide exclusion is the
  conjunction over shards; for many shards that is a bundle, noted as a cost.
- **Provenance is bound.** `parser_id` / `canonical_parser_version` / `model_hash`
  enter every leaf, so the model/parser that produced a dataset version is part
  of `manifest_root` — directly usable for AI-Act training-data documentation
  (`docs/compliance/eu-ai-act-mapping.md`).
- **Future work.** Parallelize the batch build (left/right subtrees are
  independent); add a shard-subtree inclusion proof so per-shard roots are
  verifiable against `manifest_root` without the record index; ZK inclusion/
  exclusion via the existing circuits; the Python SDK; native server endpoints.
