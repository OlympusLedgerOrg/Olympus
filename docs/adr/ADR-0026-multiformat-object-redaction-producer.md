# ADR-0026: Multi-format object-level redaction producer + object-level ingest commitment

- **Status:** **Proposed — 2026-06-09.**
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

Generalise ADR-0025's per-PDF-object leaf into a **per-segment** leaf. A
*segment* is a format-defined, independently-redactable unit of a document
(a PDF indirect object, an OOXML package part, a text line/paragraph). Each
segment yields exactly one circuit leaf via the **unchanged** ADR-0025 primitive:

```
leaf_i = object_leaf(segment_id_i, segment_bytes_i)
       = Poseidon( Poseidon(POSEIDON_DOMAIN_LEAF, content_i), 0 )
  where content_i = blake3("OLY:REDACTION:OBJ:V1" || lp(segment_id_i) || segment_bytes_i) mod p
```

Leaves are folded into the same domain-1 depth-10 / 1024-leaf Poseidon tree, with
zero-leaf padding. **No circuit, public-signal, domain-tag, vkey, or ceremony
change** — `object_leaf` and the fold are reused verbatim. `segment_id` is
length-prefixed (ADR-0005), so the binary `obj_id`-keyed framing already proven
for PDF objects carries over to part-name / line-index keys.

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

- At ingest of a supported document type, compute the **object-level root**
  (canonicalising OOXML first) and store it as the ledger `original_root` in place
  of the chunk root. Detection is by content sniff: `%PDF-` → PDF; ZIP local-file
  header `PK\x03\x04` **and** a `[Content_Types].xml` entry → OOXML; otherwise
  treat as text if it is valid UTF-8. Unsupported/opaque binaries keep the chunk
  root (and simply cannot be object-redacted — explicit, not silent).
- Persist the segment manifest so `/redaction/issue` (which only receives a
  `content_hash`) can rebuild the witness without the original bytes. **New
  migration** adds a `redaction_segment_manifests` table keyed by
  `(content_hash, shard_id)` storing `format`, `original_root`, and the ordered
  segment metadata (JSON). The canonical OOXML bytes themselves are **not**
  stored (privacy); only segment offsets/lengths/leaves + part names.

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
- Frontend: `useRedactionCreate` + the "Create a redaction" tab upload a document,
  show detected segments (objects / parts / lines), let the redactor pick which to
  hide, and call `/redaction/redact`. `api.ts` request/response types updated.

### 5. Validation

A **happy-path prover integration test per format** (`zk_prove_redaction_*`) that
ingests a fixture document, issues a redaction through the producer, and verifies
the resulting Groth16 proof end-to-end — closing the CI gap that let the #1226
producer regression through.

## Security & invariant analysis

- **Leaf framing.** `object_leaf` length-prefixes `segment_id` and the bytes
  (ADR-0005), so part-name / line-index keys cannot collide by boundary shifting.
- **Hiding / low-entropy redacted segments (open concern, inherited from
  ADR-0025).** A Merkle root *pins* a single unknown leaf once all siblings are
  known; the redaction proof carries the true redacted leaf as a private input and
  binds it via `originalRoot`. For a **low-entropy** redacted segment (e.g. a
  one-line SSN, a tiny PDF object), an attacker who has `originalRoot` + the
  revealed leaves can solve for the redacted leaf and **brute-force its content** —
  because `object_leaf` is a *deterministic* (non-hiding) commitment. This is the
  same weakness ADR-0024 fixed with a *hiding* Pedersen leaf, and it applies to the
  shipped ADR-0025 scheme too. **This ADR flags it for resolution in review**;
  options: (a) accept for coarse, high-entropy segments and document the limit;
  (b) add per-segment blinding to the leaf (a hiding commitment) — a circuit +
  ceremony change, out of scope here. **Recommendation:** do not claim
  "cryptographically hides redacted content" until (b) lands; until then position
  object-level redaction as *integrity of revealed content + structural binding*,
  not *confidentiality of low-entropy redacted content*.
- **No new RCE surface / no GPL.** All extractors are pure-Rust byte parsers (PDF
  xref walker, `zip` read/write, UTF-8 line splitter). No PDF/Office renderer, no
  native lib, no `pdfium` — the explicit reason ADR-0023/0024 were rejected.
- **Issuer signature.** The in-circuit EdDSA-Poseidon issuer signature over the
  nullifier (audit M-2) is unchanged — it lives in the witness/circuit, not the
  producer.
- **Migration safety.** Records sealed under the chunk scheme keep their chunk
  root and remain verifiable via the retained `chunk.rs`; only newly-ingested
  supported documents get object roots. No global-root or schema change to
  `smt_leaves`.

## Phased implementation plan

1. **Foundation + PDF (makes the existing PDF path actually work).**
   `RedactableDocument` trait + `SegmentManifest`; PDF impl via `pdf_objects.rs`;
   ingest computes/stores PDF object root; `redaction_segment_manifests` migration;
   rewire `/redaction/issue` + `/redaction/redact` to object-level for PDF; UI +
   `api.ts`; happy-path PDF prover test. **Unblocks the broken producer.**
2. **Plain text / Markdown.** Line-segment extractor (reuse `redact.rs` span
   logic); detection; UI line-range selection; prover test.
3. **OOXML.** Canonical-package builder + `zip` dep; part-segment extractor;
   detection; UI part selection; prover test.
4. **Google Docs.** Export-then-redact routing + UI affordance (export to PDF/docx
   client-side, then reuse 1/3); docs.
5. **Hiding-leaf decision.** Resolve the §"Hiding" concern (accept-and-document vs.
   blinded leaf); if blinded, that is its own ADR + ceremony.

## Consequences

- Redaction works again, across PDF / text / OOXML / (exported) Google Docs, over
  the single unchanged 1024/10 circuit and existing trusted setup.
- The ledger commitment for supported documents becomes object-level; ingest and a
  DB migration change accordingly. Chunk path stays only for legacy replay.
- A real CI happy-path per format prevents a silent producer regression recurring.
- The low-entropy hiding limitation is documented and explicitly deferred, not
  silently shipped.

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
