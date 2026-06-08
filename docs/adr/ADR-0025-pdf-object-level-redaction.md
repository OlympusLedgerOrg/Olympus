# ADR-0025: PDF object-level redaction commitment

- **Status:** **Accepted — 2026-06-08.**
- **Date proposed:** 2026-06-08
- **Supersedes:** **ADR-0023** (rasterized tile redaction — *Rejected*) and
  **ADR-0024** (hybrid ZK tile redaction — *Rejected*). Both were rejected
  because rasterization shifts the verifiable property from *facts about the
  bytes the issuer committed* to *facts about images of those documents*,
  losing byte/semantic provenance and introducing an in-process PDF-renderer
  RCE surface.
- **Builds on / replaces:** the chunk-based `redaction_validity` scheme
  (`proofs/circuits/redaction_validity.circom`, `src-tauri/src/zk/chunk.rs`,
  `src-tauri/src/zk/witness/redaction.rs`, `/redaction/issue`). This ADR
  replaces the *commitment construction* (16 raw-byte chunks → per-PDF-object
  leaves) while **keeping the circuit template, public-signal surface, and
  domain tags unchanged**.
- **Related invariants:** ADR-0005 (structured leaf prefix / length-prefix
  framing), ADR-0009 (Poseidon suite — MUST NOT change), and the
  Critical-Invariant rule that a commitment-format change moves
  `olympus-crypto` + both verifiers + golden vectors in one commit, plus the
  ceremony-manifest atomicity rule.

## Context

The shipped `redaction_validity` circuit commits a document as **16
length-proportional raw-byte chunks** (`chunk_size = ceil(filelen / 16)`,
`src-tauri/src/zk/chunk.rs`). ADR-0023 established with measurements that this
cannot model real document redaction:

1. **Chunk boundaries are length-dependent.** `ceil(n/16)` shifts every
   boundary when the file length changes, so a redacted artifact of a different
   size binds to nothing — even its unmodified regions.
2. **Editor redaction re-serializes the whole file.** Producing a redacted PDF
   in any editor rewrites the xref table, object offsets, and streams;
   essentially no byte range survives, so the revealed-bytes binding can never
   match the original. (Observed in ADR-0023: a 578.3 KB original vs a 559.8 KB
   editor-redacted copy shared no chunk hashes.)
3. **Zero bytes survive a real redaction**, so the surviving-region binding the
   circuit relies on is information-theoretically empty for re-rendered files.

ADR-0023 and ADR-0024 tried to fix this by **rasterizing** the document and
committing image tiles. Both were rejected (see their *Rejection rationale*):
rasterization migrates the trust boundary to "canonical renderer fidelity,"
runs an in-process PDF parser as an unmitigated RCE surface, and discards the
document's byte/semantic provenance — the very thing a redaction proof for a
journalist workflow needs to preserve.

The root cause is unchanged from ADR-0023's diagnosis: **Olympus does not own
the redaction operation.** The correct fix is *not* rasterization. It is for
Olympus to own the transformation and commit at the **PDF object level**, so
that non-redacted objects are byte-identical between the original and the
redacted artifact and their commitments survive unchanged — with **no
rasterizer, no native renderer, and no new RCE surface**.

## Decision

Commit a PDF as **one Poseidon leaf per indirect PDF object**, fold the leaves
into a depth-`N` Poseidon Merkle tree (the same node hash the circuit already
uses), and redact by **zero-filling** selected objects in place — preserving
file length and every byte offset, so the xref table and all non-redacted
objects are byte-for-byte identical.

### Commitment scheme

**Seal (original ingestion):**

1. Parse the PDF's cross-reference table (xref) to enumerate all indirect
   objects.
2. For each object `i`, extract its raw bytes `obj_bytes[i]` (from its xref
   offset through the `endobj` marker, inclusive).
3. Compute leaf `i`:

   ```
   content_i = blake3_mod_p( OBJ_DOMAIN || lp(obj_id) || obj_bytes[i] )
   leaf[i]   = Poseidon( Poseidon(POSEIDON_DOMAIN_LEAF, content_i), 0 )
   ```

   where `OBJ_DOMAIN = "OLY:REDACTION:OBJ:V1"`, `lp(x)` is the 4-byte
   big-endian `u32` length prefix (the Olympus standard, ADR-0005), and
   `blake3_mod_p` is the existing `blake3_hex_to_poseidon_leaf`-pattern
   reduction (`BLAKE3(domain || …) mod p`). The outer
   `Poseidon(Poseidon(domain, content), 0)` reuses the domain-separated node
   form already in `olympus-crypto::poseidon`.

4. Build a depth-`N` Poseidon Merkle tree over the object leaves, padding with
   zero-leaves to `MAX_OBJECTS = 2^N`. The root is `originalRoot` — this
   **replaces the 16-chunk root** as the ledger leaf, and continues to compose
   with `document_existence` over the shared `originalRoot` public signal.
5. Persist: object count and per-object `(obj_id, byte_offset, byte_length,
   leaf_hex)` in a new JSONB column `object_leaves` on the record. The raw PDF
   bytes are stored via the existing `raw_bytes` path.

**Redact:**

1. The operator selects objects to redact (the UI shows per-object bounding
   boxes / labels extracted from the content streams; coordinates only — no
   crypto in the frontend).
2. Rust reads the sealed original bytes and zero-fills the content-stream bytes
   of each selected object to exactly `byte_length` bytes, **preserving every
   offset and the xref table** — no re-serialization.
3. Output: a new PDF where redacted objects contain only null bytes. **File
   length is identical to the original**; non-redacted objects are
   byte-for-byte identical.
4. Produce a `RedactionBundle`: `originalRoot`, `redactedCommitment` (the
   domain-tag-3 Poseidon chain over revealed leaves), `revealedCount`, the
   per-object reveal/redact flag, and the issuer EdDSA-Poseidon signature over
   `Poseidon(originalRoot, redactedCommitment, recipientId)` (the in-circuit
   nullifier digest, audit M-2).

**Verify (recipient):**

1. Parse the redacted artifact's objects at the offsets carried in the bundle.
2. Recompute leaf hashes for revealed objects from the artifact bytes — they
   MUST equal the stored `leaf_hex` values.
3. Redacted objects: leaf values are taken from the bundle (hidden — not
   recomputable by the recipient).
4. Reconstruct `originalRoot` from all leaves + Merkle paths.
5. Verify `redactedCommitment`, `revealedCount`, and the issuer signature.
   **Same Groth16 circuit as today** — only witness construction changes.

## Why the circuit is unchanged (no new ceremony for the other circuits)

`redaction_validity.circom` proves that N leaves are included in a Merkle tree
with root `originalRoot`, that `revealedCount = sum(revealMask)`, that
`redactedCommitment` is the domain-3 chain over the masked leaves, and that an
issuer EdDSA-Poseidon signature verifies over the nullifier. **None of that
cares whether a leaf is a byte-chunk hash or a PDF-object hash** — the leaf is
an opaque field element supplied as a private witness input. The public-signal
surface (`nullifier` output, then `originalRoot, redactedCommitment,
revealedCount, issuerAx, issuerAy`) is byte-for-byte identical.

> **⚠ Constraint-budget caveat (must be resolved at the `--inspect` gate).**
> The unchanged template runs **one Merkle-inclusion proof per leaf** (the
> L4-C hardening forces *all* leaves through inclusion), so its cost scales
> ~`maxLeaves × depth` Poseidon hashes. At 16/depth-4 that is tiny; at
> 1024/depth-10 it is on the order of several million constraints — which does
> **not** fit the shared power-20 ptau (and is larger than ADR-0024's
> *flat-fold* ~1.35M estimate, because flat-fold is a template change this ADR
> forbids). Before the v1.0 ceremony the exact count MUST be measured with
> `circom redaction_validity.circom --inspect`; expect to either (a) download a
> larger Hermez Phase-1 ptau (power 23+), or (b) drop `REDACTION_MAX_LEAVES`
> to 512/depth-9 and re-measure. This caveat was raised because `circom` was
> not available in the implementation environment to measure directly.

The **template body is untouched.** Only `parameters.circom` changes
(`REDACTION_MAX_LEAVES 16 → 1024`, `REDACTION_MERKLE_DEPTH 4 → 10`) to fit a
typical PDF's object count. A parameter change recompiles `redaction_validity`
to a new R1CS and therefore a new vkey, so **the redaction circuit alone needs
a fresh Phase-2 contribution** before v1.0. The `document_existence`,
`non_existence`, and `unified_canonicalization_inclusion_root_sign` circuits
are **completely unaffected** — their vkeys and manifests do not change.

## Security analysis

- **Object isolation (why zero-fill preserves non-redacted byte identity).**
  Redaction overwrites only the *content-stream payload bytes* of the targeted
  objects, to exactly the same length, in place. The xref offset table, every
  object's `N G obj … endobj` framing, and every non-redacted object's bytes
  are untouched. Therefore each non-redacted object's `obj_bytes` — and hence
  its `leaf_hex` — is identical in the original and the artifact, and the
  recipient recomputes them exactly. This is the property the chunk scheme
  could never provide for a re-serialized file.
- **Hiding property (why a recipient can't recover redacted content).** A
  Merkle root over N leaves pins any single unknown leaf once all siblings are
  known, so a *recipient cannot recompute* a redacted leaf — but a low-entropy
  redacted object (e.g. a short name) could in principle be **brute-forced**
  against the published leaf, because the object-content leaf is a deterministic
  function of the object bytes only. **This is an explicit limitation of v1**
  (see *Consequences*): for low-entropy redacted objects, object-level
  commitment provides binding but only *computational* hiding bounded by the
  object's entropy. Where perfect hiding of low-entropy fields is required, the
  Pedersen-blinded leaf from ADR-0024's analysis (`leaf = Poseidon(C.x, C.y)`,
  `C = m·G + b·H`, `b` withheld) is the upgrade path and is recorded as a
  follow-up. For typical PDF content objects (streams of compressed content,
  fonts, images) the brute-force surface is negligible.
- **Domain separation.** The object content hash is domain-tagged with
  `OBJ_DOMAIN = "OLY:REDACTION:OBJ:V1"` and length-prefixes `obj_id` and the
  object bytes (ADR-0005 injection prevention), so an object commitment can
  never collide with any other BLAKE3 use, and two objects cannot be made to
  hash equal by shifting field boundaries. The Merkle node hash (domain 1), the
  leaf wrap (`POSEIDON_DOMAIN_LEAF`), and the redacted-commitment chain (domain
  3) are the unchanged ADR-0009 tags.
- **Replay / recipient binding.** Unchanged from audit M-2: the issuer signs
  the nullifier digest `Poseidon(originalRoot, redactedCommitment,
  recipientId)`, so a recipient holding cleartext cannot re-prove the same
  redaction for a different recipient.

## Consequences / limitations

- **PDF-only for v0.9.** The extractor targets PDF indirect objects. Other
  formats are out of scope; the redaction commitment surface is unchanged for
  them.
- **Object granularity.** Redaction is whole-object, not sub-object: you redact
  an entire content object, not a glyph range within it. Operators select the
  objects whose content covers the sensitive region.
- **Traditional xref tables only (v1).** PDF 1.5+ *cross-reference streams*
  (compressed xref) are **not supported** in v1. `extract_objects` returns a
  typed `NotTraditionalXref` error so the caller can surface a clear message.
  Object streams (`/ObjStm`) inside such files are likewise out of scope.
- **Low-entropy hiding** is computational, bounded by object entropy (see
  *Security analysis*); Pedersen-blinded leaves are the recorded upgrade.
- **Object count bound.** `MAX_OBJECTS = REDACTION_MAX_LEAVES = 1024`
  (depth 10). A PDF with more than 1024 indirect objects is restricted to the
  first 1024 content objects (metadata objects may be excluded); this bound is
  a named constant and is `log()`-surfaced, never silently truncated. If the
  measured constraint count for N=1024 exceeds the power-20 ceremony
  (2²⁰ = 1,048,576 constraints), the bound drops to `MAX_OBJECTS = 512`
  (depth 9) — documented at the constant.

## Rejected alternatives

- **Rasterization (ADR-0023 / ADR-0024).** Rejected — migrates trust to
  renderer fidelity, in-process RCE surface, loses byte/semantic provenance.
- **Byte-range container (zero opaque byte ranges, length-preserving).**
  Trustless and length-preserving, but commits opaque byte ranges with no
  relationship to document structure; object-level commitment subsumes it with
  meaningful, recipient-recomputable units.
- **Keep the 16-chunk scheme.** Rejected — length-dependent boundaries bind
  nothing for any real (re-serialized or length-changing) redaction.

## Implementation plan (phases)

1. **Crypto primitive** — `POSEIDON_DOMAIN_OBJ_LEAF` constant +
   `object_leaf()` in `olympus-crypto`.
2. **Extractor/redactor** — `src-tauri/src/zk/pdf_objects.rs`: traditional-xref
   parse, `extract_objects`, `apply_redaction`, typed errors, unit tests.
3. **Witness** — `witness/redaction.rs` leaves built from `PdfObjectManifest`;
   `MAX_LEAVES`/`REDACTION_DEPTH` → 1024/10; `chunk.rs` deprecated (retained for
   existing sealed records, decoupled to local 16/4 constants).
4. **Circuit parameters** — `parameters.circom` → 1024/10; rerun
   `setup_circuits.sh` for `redaction_validity` only; record the required new
   Phase-2 contribution in `CEREMONY*.md`.
5. **Verifiers + vectors** — object-leaf computation in `verifiers/rust` and
   `verifiers/javascript`; regenerate `verifiers/test_vectors/redaction_vectors.json`
   from the Rust reference; JS reproduces byte-for-byte.
6. **Docs** — CHANGELOG, CLAUDE.md, endpoint docs.
7. **(Separate PR)** — wire `/redaction/issue` end-to-end onto the object path,
   then remove the chunk path and `chunk.rs`.
