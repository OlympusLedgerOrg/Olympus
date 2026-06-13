# ADR-0026: Multi-format object-level redaction producer + object-level ingest commitment

- **Status:** **Accepted — 2026-06-13** (Phase 1 PDF shipped #1232; the
  `Segmenter`/`SegmentManifest` generalisation it specified, plus Phase 2 (text)
  and Phase 3 (OOXML), landed 2026-06-13. Modern-PDF cross-reference-stream /
  ObjStm support is split out into **ADR-0028**. Phase 4 (Google Docs) remains
  routing-only / future.)
- **Date proposed:** 2026-06-09
- **Builds on:** **ADR-0025** (PDF object-level redaction — *Accepted*). ADR-0025
  migrated the `redaction_validity` **circuit + witness + verifier** to the
  1024-leaf / depth-10 object-level scheme and shipped `src-tauri/src/zk/pdf_objects.rs`.
  It did **not** migrate the *producer* (`/redaction/issue`, `/redaction/redact`,
  the "Create a redaction" UI) or the *ingest commitment* path. This ADR finishes
  that migration and generalises it from PDF-only to multiple document formats.
- **Supersedes (operationally):** the chunk-based producer path
  (`src-tauri/src/zk/chunk.rs`, `src-tauri/src/zk/redact.rs::redact_chunk_aligned`,
  the 16-chunk branches of `src-tauri/src/api/redaction.rs`, and the chunk-based
  `original_root` computed at ingest in `src-tauri/src/api/ingest/files.rs`).
  `chunk.rs` is retained only to replay records sealed before this change.
- **Related invariants:** ADR-0005 (structured leaf prefix / length-prefix
  framing), ADR-0009 (Poseidon suite — MUST NOT change), the rule that a
  commitment-format change moves `olympus-crypto` + both verifiers + golden
  vectors in one commit, and ceremony-manifest atomicity. **The circuit,
  public-signal surface, and trusted setup are unchanged by this ADR** — it only
  changes how the committed leaves are produced and which producers feed them.

## Context

### The producer is broken on `main`

ADR-0025 (#1226) changed `RedactionWitness::new` to require **1024 leaves**
(`MAX_LEAVES`, `REDACTION_DEPTH = 10`) and rewired the circuit to a flat fold.
But the live producer was never migrated:

- `POST /redaction/issue` and `POST /redaction/redact`
  (`src-tauri/src/api/redaction.rs`) still build a **16-leaf** witness via
  `crate::zk::chunk::{CHUNK_LEAVES = 16, chunk_hex_to_leaf, paths_for_chunk_tree}`
  and pass it to `RedactionWitness::new`, which now rejects it with
  `RedactionError::WrongLeaves(16)`. Any real prove call 500s.
- The "Create a redaction" UI (`useRedactionCreate.ts` → `POST /redaction/redact`)
  inherits the break.
- CI did not catch this: the redaction API tests cover only error paths
  (401 / 404 / 422), never a full happy-path prove.

### Ingest commits a chunk-based root

`src-tauri/src/api/ingest/files.rs` computes the ledger `original_root` as
`fr_to_hex(chunk_tree.original_root)` — the 16-chunk Poseidon root. The redaction
proof's `originalRoot` public signal must equal the value the document was
**committed under on the ledger** (so a verifier can tie the proof to the
on-ledger record). An object-level proof produces a *different* root, so simply
fixing the producer to call `pdf_objects::witness_inputs` is **insufficient**:
ingest must also commit the object-level root.

### Requirement: more than PDF

`pdf_objects.rs` parses **traditional-xref PDFs only**. The product requirement
is that redaction also cover **Word/OOXML (`.docx`/`.pptx`/`.xlsx`)**,
**plain-text / Markdown**, and **Google Docs** (via export). The chunk scheme it
replaces was format-agnostic (any bytes → 16 chunks), so a PDF-only object scheme
would *narrow* what redaction supports — unacceptable. The commitment must
generalise across formats while keeping the single 1024/10 circuit.

## Decision

### 1. Format-agnostic "segment" commitment over the unchanged circuit

Generalise ADR-0025's per-PDF-object leaf into a **per-segment, hiding** leaf. A
*segment* is a format-defined, independently-redactable unit of a document
(a PDF indirect object, an OOXML package part, a text line/paragraph). Each
segment yields exactly one circuit leaf, computed as a **blinding (hiding)
commitment** so a redacted leaf's preimage cannot be brute-forced (see
§Security):

```
content_i = blake3_xof("OLY:REDACTION:OBJ:V1"   || lp(segment_id_i) || segment_bytes_i)[..64] mod l
b_i       = blake3_xof("OLY:REDACTION:BLIND:V1"  || blind_secret || lp(content_hash) || lp(segment_id_i))[..64] mod l
C_i       = content_i · G + b_i · H            // Pedersen on Baby Jubjub (prime-order subgroup)
leaf_i    = Poseidon(C_i.x, C_i.y)             // ADR-0024 `commit_tile` construction
```

**Scalars reduce mod `l` (the Baby Jubjub prime-subgroup order,
`bjj_subgroup_order()`), NOT mod `p`** — `pedersen::commit` / `to_subgroup_scalar`
**fail closed** (`ScalarOutOfRange`) on any scalar ≥ `l` and never silently
reduce, so a raw `blake3(...) mod p` (where `l ≈ p/8`) would error ~7/8 of the
time. Use 64-byte XOF wide-sampling then reduce mod `l` (the `random_blinding`
pattern) to avoid modulo bias. This reduction is **identical** across producer,
both offline verifiers, and the golden vectors. (CodeRabbit #1228 review item 1.)

`b_i` is **derived deterministically** from a persisted server `blind_secret`
plus `(content_hash, segment_id)` — not freshly random — so **re-ingesting the
same file is idempotent** (same `original_root` every time) and blindings are
reproducible without an at-rest secret table (resolves CodeRabbit item 4). It
stays hiding: without `blind_secret`, knowing one revealed `b_i` reveals nothing
about the others. Revealed segments publish their `b_i` in the bundle; redacted
segments never do.

Leaves are folded into the same domain-1 depth-10 / 1024-leaf Poseidon tree, with
zero-leaf padding. **No circuit, public-signal, domain-tag, vkey, or ceremony
change** — the circuit treats `leaf_i` as an opaque field element (§Security),
and the fold is reused verbatim. `segment_id` is length-prefixed (ADR-0005), so
the binary `obj_id`-keyed framing already proven for PDF objects carries over to
part-name / line-index keys. (The deterministic `object_leaf` from ADR-0025 is
replaced by the hiding form above; the `POSEIDON_DOMAIN_OBJ_LEAF` content scalar
is reused as `content_i`.)

### 2. `RedactableDocument` trait + per-format extractors

Introduce a trait that captures the three operations the producer needs, with one
implementation per supported format:

```rust
pub trait RedactableDocument {
    /// Parse the document into ordered, independently-redactable segments,
    /// compute each leaf, and fold the object-level root. Pure byte ops.
    fn extract(&self, bytes: &[u8]) -> Result<SegmentManifest, RedactError>;
    /// Produce a redacted artifact with the selected segments removed/zeroed,
    /// preserving every non-redacted segment's committed leaf byte-for-byte.
    fn apply_redaction(&self, bytes: &[u8], m: &SegmentManifest, redacted: &[SegmentId])
        -> Result<Vec<u8>, RedactError>;
    /// 1024-leaf witness inputs (leaves + Merkle paths), shape unchanged.
    fn witness_inputs(&self, m: &SegmentManifest)
        -> Result<(Vec<Fr>, Vec<Vec<Fr>>, Vec<Vec<u8>>), RedactError>;
}
```

`pdf_objects.rs` becomes the **PDF** implementation (its existing
`extract_objects` / `apply_redaction` / `witness_inputs` slot in directly).
`SegmentManifest` is `PdfObjectManifest` generalised: ordered segments
`(segment_id, byte_offset?, byte_length?, leaf_hex)` + `original_root_hex` +
`tree_depth` + `max_leaves`.

#### Per-format extractors

| Format | Segment | Redaction (byte-preserving property) | Status |
|---|---|---|---|
| **PDF** (traditional xref) | one indirect object | in-place NUL-fill of object content; offsets/xref/length preserved; non-redacted objects byte-identical | exists (`pdf_objects.rs`) |
| **OOXML** (`.docx`/`.pptx`/`.xlsx`) | one ZIP package part, keyed by canonical part name | **canonical repackaging** (see §3); redacted part's bytes zeroed/emptied, all other parts byte-identical in the canonical container | new |
| **Plain text / Markdown** | one line (LF-delimited; final-newline normalised) | NUL/space-fill or removal of the selected line spans; other lines byte-identical | new (can reuse `redact.rs` span logic, but commits per-line leaves) |
| **Google Docs** | n/a — **export-then-redact** | user exports to PDF or `.docx`; producer routes to the PDF/OOXML extractor. No Google API or native gdoc parser in scope. | routing only |

OOXML detail (the one with a real subtlety): a `.docx` is a ZIP whose entries are
DEFLATE-compressed with per-entry CRCs, so "zero the bytes in place" is not
meaningful at the container level. We therefore define a **canonical OOXML
package** at ingest: entries in a fixed (sorted) order, **stored (no compression)**,
fixed/zeroed ZIP metadata (mtime, external attrs), no data descriptors. The
canonical package bytes are what gets committed; each entry is one segment
(`segment_id = part name`, `segment_bytes = entry payload`). Redaction empties the
selected entry's payload and re-emits the canonical package, so every other
entry's payload — and therefore its leaf — is byte-identical. Pure Rust ZIP
read/write (`zip` crate, permissive); **no Office renderer, no native lib** (avoids
the RCE/licensing problems that sank ADR-0023/0024).

### 3. Object-level ingest commitment + manifest persistence

> **Greenfield — no active DB, no users.** There are no chunk-sealed records to
> preserve, so there is **no data-parity gap, no dual-write, and no legacy →
> object remap** (which would be impossible anyway — a chunk root cannot be
> recomputed as an object root without re-ingesting bytes we never store).
> Ingest commits object-level **from the start**, and the chunk path
> (`chunk.rs`, `redact.rs::redact_chunk_aligned`, the chunk branches of
> `api/redaction.rs`, the chunk root in `ingest/files.rs`) is **removed**, not
> deprecated. The schema change is purely additive, so rollback is just dropping
> the new table/column.

- At ingest of a supported document type, compute the **object-level root**
  (blinded leaves; canonicalising OOXML first) and store it as the ledger
  `original_root`. Detection is by content sniff: `%PDF-` → PDF; ZIP local-file
  header `PK\x03\x04` **and** a `[Content_Types].xml` entry → OOXML; otherwise
  treat as text if it is valid UTF-8. Unsupported/opaque binaries are committed
  but are **not object-redactable** (no segment manifest) — explicit, not silent.
- Persist the segment manifest so `/redaction/issue` (which only receives a
  `content_hash`) can rebuild the witness without the original bytes. **New
  migration** adds a `redaction_segment_manifests` table keyed by
  `(content_hash, shard_id)` storing `format`, `original_root`, and the ordered
  segment metadata (JSON: ids + offsets/lengths/leaves). The canonical OOXML / PDF
  bytes are **not** stored (privacy), and **blindings are not stored** — they are
  re-derived deterministically from `blind_secret + (content_hash, segment_id)`
  (§Decision 1), so the table holds no at-rest secret.
- **Re-ingest is idempotent.** Because `b_i` is deterministic, re-ingesting the
  same file yields the same `original_root`; the `(content_hash, shard_id)` row is
  written once (insert-or-ignore), so a retry never silently rewrites a committed
  root out from under an already-issued proof (resolves CodeRabbit item 4).

### 4. API + frontend contract

- `POST /redaction/redact` — body becomes `{ document_base64, format?, selection,
  recipient_id }` where `selection` is per-format: PDF object ids, OOXML part
  names, or text line ranges (`format` auto-detected if omitted). Server: detect →
  `extract` → `apply_redaction` → `witness_inputs` (1024) →
  `prove_redaction` → sign bundle → return `{ redacted_base64, bundle }`. The
  committed `content_hash` must already be on-ledger with a matching object root
  (you can only redact something committed object-level).
- `POST /redaction/issue` — body becomes `{ content_hash, selection, recipient_id }`;
  server resolves the stored manifest, builds the witness from it, proves. The
  `reveal_mask` is derived server-side from `selection` (revealed = all real
  segments except the selected; padding leaves stay unrevealed).
- **Bundle gains revealed-segment blindings (CodeRabbit item 3).** The
  `RedactionIssueResponse` adds `revealed_segments: [{ segment_id, b_i_hex }]`
  (one entry per revealed segment; `b_i_hex` = the 32-byte little-endian subgroup
  scalar). A recipient holding the redacted artifact recomputes, for each revealed
  segment, `content_i` from the artifact bytes, `C_i = commit(content_i, b_i)`,
  `leaf_i = Poseidon(C_i.x, C_i.y)`, then the `redactedCommitment` chain — and
  checks it against the proof's public signal. (`revealed_chunk_hashes` is removed
  with the chunk path.)
- **`POST /redaction/link` is removed.** It is a chunk-era endpoint that folds a
  caller-supplied 64-hash list (`MAX_LEAVES = 64` in `api/redaction.rs`) into a
  root that matches **neither** the old 16-leaf nor the new 1024-leaf circuit, so
  it can only emit structurally invalid commitments. It goes with the rest of the
  chunk path (resolves CodeRabbit item 2).
- Frontend: `useRedactionCreate` + the "Create a redaction" tab upload a document,
  show detected segments (objects / parts / lines), let the redactor pick which to
  hide, and call `/redaction/redact`. `api.ts` request/response types updated; the
  `/redaction/link` UI (`useRedactionLink`, `RedactionLinkPanel`) is removed.

### 5. Validation

A **happy-path prover integration test per format** (`zk_prove_redaction_*`) that
ingests a fixture document, issues a redaction through the producer, and verifies
the resulting Groth16 proof end-to-end — closing the CI gap that let the #1226
producer regression through.

Two required follow-on tasks the leaf change forces (CodeRabbit items 5–6),
called out so Phase 1's first commit doesn't red CI:

- **Regenerate the locked leaf/root fixtures.** The hiding leaf changes every
  `object_leaf` value and `original_root_hex`, so `pdf_objects.rs`'s
  `object_leaf_conformance_locked` test and the `emit_redaction_vectors` golden
  vectors (+ the JS verifier suite) must be regenerated in the same commit.
- **Update both offline verifiers** (`verifiers/rust`, `verifiers/javascript`) to
  the blinded computation: for a revealed segment, `content_i = reduce_l(blake3_xof(...))`
  → `C_i = commit(content_i, b_i)` → `leaf_i = Poseidon(C_i.x, C_i.y)`, using the
  published `b_i`. This is the normative spec the verifier legs must mirror
  byte-for-byte (single source of truth = `verifiers/test_vectors`).

## Security & invariant analysis

- **Leaf framing.** `object_leaf` length-prefixes `segment_id` and the bytes
  (ADR-0005), so part-name / line-index keys cannot collide by boundary shifting.
- **Hiding / low-entropy redacted segments — ADOPTED: blinded leaves from day
  one.** A Merkle root *pins* a single unknown leaf once all siblings are known;
  the redaction proof carries the true redacted leaf as a private input and binds
  it via `originalRoot`. For a **low-entropy** redacted segment (a one-line SSN,
  `/CreationDate`, a checkbox value, a small numeric object), an attacker holding
  `originalRoot` + the revealed leaves can solve for the redacted leaf and
  **brute-force its content** if the leaf is a *deterministic* commitment. Most
  real redaction targets are short and guessable, so this is not a corner case.
  **Decision:** the segment leaf is a **hiding commitment** —
  `leaf_i = Poseidon(C_i.x, C_i.y)` with `C_i = m_i·G + b_i·H` (Pedersen on Baby
  Jubjub; `m_i` = the content scalar, `b_i` = a per-segment random blinding), the
  exact `commit_tile` construction from ADR-0024. The `pedersen.rs` primitive and
  `babyjubjub-permissive` survived the prune, so the building blocks already exist.

  **This costs no circuit or ceremony change.** The circuit consumes
  `originalLeaves[maxLeaves]` as **opaque field elements** — content and blinding
  never enter it (verified: `redaction_validity.circom` only folds leaves →
  `originalRoot`, masks them, chains `redactedCommitment`, and checks the issuer
  sig). So hiding is an **off-circuit** property: it changes the leaf function in
  `olympus-crypto`, the producer (generate + persist `b_i`), the bundle (publish
  `b_i` for **revealed** segments only; redacted blindings stay secret), both
  offline verifiers (recompute revealed leaves from artifact bytes + published
  `b_i`), and the golden vectors. The 1024/10 circuit, public signals, vkey, and
  trusted setup are reused **unchanged**. Doing it now (vs. retrofitting) avoids
  re-sealing every record and regenerating vectors twice — the decisive reason to
  build it into Phase 1.
- **No new RCE surface / no GPL.** All extractors are pure-Rust byte parsers (PDF
  xref walker, `zip` read/write, UTF-8 line splitter). No PDF/Office renderer, no
  native lib, no `pdfium` — the explicit reason ADR-0023/0024 were rejected.
- **Issuer signature.** The in-circuit EdDSA-Poseidon issuer signature over the
  nullifier (audit M-2) is unchanged — it lives in the witness/circuit, not the
  producer.
- **Migration safety.** Greenfield (no active DB / users): no historical records,
  so nothing to keep parity with. The chunk scheme is removed, not retained. No
  global-root or schema change to `smt_leaves`; the only new state is the additive
  `redaction_segment_manifests` table.

## Phased implementation plan

1. **Foundation + blinded leaf + PDF (unblocks the broken producer).**
   Hiding leaf (`object_leaf` → Pedersen `commit_tile` form) in `olympus-crypto`
   + both verifiers + golden vectors; `RedactableDocument` trait +
   `SegmentManifest` (carrying per-segment `b_i`); PDF impl via `pdf_objects.rs`;
   ingest computes/stores the blinded PDF object root; `redaction_segment_manifests`
   migration; **remove** the chunk path; rewire `/redaction/issue` +
   `/redaction/redact` to object-level; UI + `api.ts`; happy-path PDF prover test.
2. **Plain text / Markdown.** Line-segment extractor (reuse `redact.rs` span
   logic); detection; UI line-range selection; prover test.
3. **OOXML.** Canonical-package builder + `zip` dep; part-segment extractor;
   detection; UI part selection; prover test.
4. **Google Docs.** Export-then-redact routing + UI affordance (export to PDF/docx
   client-side, then reuse 1/3); docs.

## Consequences

- Redaction works again, across PDF / text / OOXML / (exported) Google Docs, over
  the single unchanged 1024/10 circuit and existing trusted setup.
- Redacted segments are **cryptographically hidden** (blinded leaf), so the
  low-entropy brute-force is closed from day one — without a circuit or ceremony
  change.
- The ledger commitment becomes object-level; ingest changes and an additive DB
  migration is added. The chunk path is removed outright (greenfield).
- A real CI happy-path per format prevents a silent producer regression recurring.

## Alternatives considered

- **Fix the chunk producer instead.** Rejected — ADR-0025 already removed the
  16-leaf circuit/witness; the chunk producer is fundamentally incompatible with
  the 1024-leaf circuit, and the chunk scheme's binding never held for
  re-serialized documents (ADR-0023 Context).
- **PDF-only producer.** Rejected — narrows redaction below what the chunk scheme
  supported; the product requires text + OOXML + Google Docs.
- **Rasterize all formats to a canonical image (ADR-0023/0024).** Rejected there
  (renderer-fidelity trust boundary, in-process RCE, loss of byte/semantic
  provenance); not revisited.
