# Olympus proof bundles → EU AI Act training-data documentation

This note maps the fields Olympus commits and proves (ADR-0027 dataset
manifests; ADR-0003/0004/0005 leaf provenance) to the training-data
documentation obligations of **Regulation (EU) 2024/1689 (the AI Act)**. It is a
practical crosswalk for a provider's legal/compliance review, not legal advice;
cite the regulation text for authoritative wording.

## Why a cryptographic commitment helps

The AI Act's data-governance and technical-documentation duties are
*evidentiary*: a provider must be able to **show**, after the fact, which data a
model was trained on, where it came from, and what processing it underwent. An
**anchored** Olympus `manifest_root` turns those claims into facts an auditor (or
a market-surveillance authority) can verify **independently and offline**: a
verifier establishes the expected root by hashing the anchored manifest document
and checks record proofs against it (`manifest_root == expected_root` in
`crates/olympus-manifest/src/proof.rs`) — there is no separate signature
primitive over the bare `manifest_root` itself; its authenticity comes from the
ledger anchor of the manifest blob. With that root a verifier can confirm that a
specific dataset version existed at a point in time, that a given record **is**
or **is not** part of it, and which parser/model produced it — without trusting
the provider's word or re-running the pipeline.

## Field-level crosswalk

`DatasetManifest` and `RecordProofBundle` fields (see
`crates/olympus-manifest/src/lib.rs` and `…/proof.rs`):

| Olympus field | What it commits | AI Act obligation it supports |
|---|---|---|
| `manifest_root` | SMT root over every record in the dataset version | **Art. 11 + Annex IV §2(d)** (technical documentation: data requirements, provenance); **Art. 12** (automatic record-keeping / traceability) — a single verifiable anchor for "this is the exact training set". |
| `dataset_id`, `version`, `parent` | Stable dataset identity + linked version lineage | **Annex IV §2(d)** datasets used and their **provenance**; **Art. 10(2)** governance over successive data-processing versions; GPAI **Art. 53(1)(a)+(b)** training-content documentation across releases. |
| `created_at` + ledger anchor | Tamper-evident commitment time | **Art. 12** record-keeping over the lifecycle; demonstrates *when* a training set was fixed. |
| `metadata.parser_id`, `metadata.canonical_parser_version` | The exact parser/canonicalisation that produced each leaf (bound **into** every leaf, ADR-0003) | **Annex IV §2(c)/(d)** description of data-preparation/processing methodology; **Art. 10(2)(b)–(c)** data-preparation and assumptions. |
| `metadata.model_hash` | The model artifact associated with the dataset (bound into every leaf, ADR-0004) | **Annex IV §2(d)** linkage between training data and the resulting model; **Art. 53** GPAI model/dataset association. |
| `metadata.license`, `metadata.source` | Declared licence + source of the dataset | **Art. 10(2)(a)** design choices incl. data origin; **Art. 53(1)(c)** + the **Art. 53(1)(d)** copyright-policy/training-content-summary duties (provenance evidence). |
| `shards[].shard_root`, `shards[].record_count` | Per-shard subtree root + size | **Annex IV §2(d)** data characterisation; supports **Art. 10(3)** examination for biases at shard granularity. |
| Inclusion proof (`ProofKind::Inclusion` + SMT existence) | "Record X **is** in dataset version V" | Responding to **Art. 10** data-quality/representativeness queries; substantiating **Art. 53(1)(d)** training-content claims about what *was* used. |
| Exclusion proof (`ProofKind::Exclusion` + SMT non-existence) | Cryptographically demonstrates "Record X **is not** in dataset version V" — sound non-membership against an adversarial committer | Operational/forensic evidence that the committed manifest **does not contain** the record: proving a flagged/copyrighted/PII record was **excluded** from a training set. For **GDPR Art. 17** this is *evidence of exclusion* (the record is absent from version V); it is **not** proof that an erasure request was received or honoured — see Limits. |
| `diff` (`ManifestDiff`, `diff_root`) + version-link | "V2 = V1 − removed + added", per-record provable | **Art. 12** lifecycle record-keeping; **Art. 10(2)** governance of curation over time; evidences *removals* (e.g. takedowns) without re-publishing the whole set. |

## How an obligation is discharged, end to end

1. **Build + commit (provider).** `olympus build` hashes the training shards
   locally and seals a `DatasetManifest`; `olympus commit` anchors its
   `manifest_root` to an Olympus node. Provenance (`parser_id`,
   `canonical_parser_version`, `model_hash`, `license`, `source`) is set at build
   time and bound into the commitment.
2. **Document (Annex IV / Art. 53).** The compact manifest document — a few
   hundred bytes — is the artifact referenced in the technical documentation /
   GPAI training-content summary. It names the dataset, version, provenance, and
   `manifest_root`.
3. **Answer a query (auditor / authority).** Given a record (e.g. a specific
   copyrighted work or a data subject's record), the provider produces an
   inclusion **or** exclusion `RecordProofBundle` with `olympus prove`. The
   auditor verifies it offline with `olympus verify` against the anchored
   `manifest_root` — no access to the full dataset required, preserving
   confidentiality of the rest of the corpus.
4. **Show curation (Art. 12 / Art. 10).** For a later version, the provider
   produces the `ManifestDiff` and version-link; the auditor confirms exactly
   which records were added/removed and that the new version descends from the
   documented parent.

## Limits / honest scoping

- Olympus proves **what was committed**, not that the committed hashes faithfully
  represent the real files — that binding is established at hashing time, on the
  provider's machine, which is why `olympus build` hashes the bytes locally and
  the node re-hashes on commit. The commitment is only as honest as the inputs
  at first hash.
- Exclusion proofs are **shard-scoped** (sound for "record X ∉ shard S");
  dataset-wide exclusion is the conjunction over the manifest's shard list.
- An exclusion proof attests only that the record is **absent from the committed
  manifest** — it is forensic evidence of non-membership, not evidence that any
  upstream deletion/erasure request was received, authorised, or honoured. The
  SMT cannot attest to out-of-band requests or to policy/process compliance; for
  GDPR Art. 17 it shows the *end state* (record excluded from version V), and the
  request/decision trail must be documented separately.
- This crosswalk references AI Act articles by number for navigation; binding
  interpretation (including delegated/implementing acts and the GPAI Code of
  Practice) should be confirmed with counsel. The **external audit + legal memo**
  (see `docs/audits/manifest-external-audit-scope.md`) is the gate before relying
  on these mappings in a regulated submission.
