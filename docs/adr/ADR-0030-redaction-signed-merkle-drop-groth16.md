# ADR-0030: Redaction via signed Merkle fold (drop the Groth16 circuit) + lower the ceremony to power 17

- **Status:** **Proposed — 2026-06-14.** *(Spec-hardened by a second adversarial review the same day — see "Second hardening pass" below. Decisions ratified 2026-06-15: SR-DEC-1 ratified; SR-DEC-2 (nullifier) and SR-DEC-3 (canonical-text signing) reverted.)*
- **Builds on:** ADR-0025/0026/0028 (the per-segment **hiding-leaf** commitment +
  the `Segmenter` abstraction), ADR-0029 (visual text-run redaction — *unblocked*
  by this ADR because the 1024-leaf cap disappears), and ADR-0005 (the
  length-prefix / structured-binary framing — `lp(x)`, the normative source for
  every byte encoding in §2).
- **Supersedes (for the redaction producer only):** the **Groth16
  `redaction_validity`** proof. The circuit's *commitment* (per-segment hiding
  leaves folded to a root, committed on the ledger) is **kept**; only the
  *proof mechanism* changes from a SNARK to a **signed Merkle fold**.
- **Leaves ZK in place where it earns its keep:** `document_existence` and
  `non_existence` (privacy-preserving ledger inclusion / non-inclusion) stay on
  Groth16. They are small (~8k and ~70k constraints), so dropping
  `redaction_validity` (~466k–983k, the largest *production* circuit) lets the
  production ceremony drop from **power 20 → power 17**.

## Context

Redaction must let a recipient verify four things about a redacted artifact:

1. **Binding** — it derives from the original committed on the ledger.
2. **Selective disclosure** — *exactly* these segments were removed; the rest is
   unchanged.
3. **Issuer authorization** — the authority key sanctioned this redaction, for
   this recipient.
4. **Hiding** — removed content is unrecoverable from the bundle / root.

None of these need zero-knowledge. The leaves are **already** hiding Pedersen
commitments (ADR-0026 — hiding), the bundle is **already** Ed25519-signed
(authorization), and binding + selective disclosure are a Merkle property. The
SNARK's only extra is hiding the **recipient id** and the **count/positions** of
redacted segments — and the threat model (court-evidence / press-freedom, known
recipient, largely-visible structure) does not require that.

Meanwhile the SNARK imposes two real costs: a hard **1024-leaf cap** (blocks
fine-grained text-run redaction) and a **power-20 trusted-setup ceremony**.
`redaction_validity` is the largest *production* circuit; `unified` /
`federation_quorum` (the other power-20 circuits) are **gated, not shipped**.

## Decision

### 1. Commitment: uncapped per-document segment Merkle tree

At ingest, fold the document's segment leaves into a **variable-depth**
domain-2 Poseidon Merkle tree. The fold is **fully pinned** (it is the only
binding mechanism now that the circuit is gone — no SNARK oracle pins it for us):

> **Variable-depth fold (normative).** Let `N = segment_count`.
> - **`N` must be ≥ 2.** A document that segments to `N < 2` redactable units
>   offers no meaningful reveal/hide partition (you can neither reveal-all nor
>   hide-all and disclose anything) and is **not object-redactable** — it routes
>   to the chunk fallback (committed, not redactable), exactly as the text
>   segmenter already does for single-line / empty files
>   (`segment/text.rs::extract`). The producer and the verifier both reject
>   `N = 0` and `N = 1`.
> - **`N` must be ≤ `MAX_REDACTION_SEGMENTS` (= 2²⁰ = 1,048,576).** This pinned
>   constant *replaces* the deleted 1024 cap (it does not vanish): it bounds the
>   fold at ~2.1M Poseidon hashes / depth 20 so a malicious or pathological
>   document cannot force unbounded work / OOM on the producer *or* on the
>   (deliberately cheap) offline verifiers. The producer rejects over-cap
>   documents **before** folding (the existing `TooManySegments` guard, retuned
>   to the new bound); the verifiers reject any signed `N > MAX_REDACTION_SEGMENTS`
>   **before** allocating leaves. The constant is migration-class: a change must
>   land in `segment.rs`, both verifiers, and the cross-language vectors together.
> - **Depth:** `depth = ⌈log2 N⌉` (for `N` an exact power of two this is
>   `log2 N` — e.g. `N = 1024 → 10`, `N = 2 → 1`, `N = 3 → 2`).
> - **Padding leaf:** pad the `N` hiding leaves (in ascending `segment_id` order,
>   each placed at its array index) up to `2^depth` with the **BN254 scalar-field
>   zero, `Fr(0)`** — byte-for-byte the value `segment.rs::fold_root` and
>   `poseidon::empty_doc_existence_root` use today. **This is NOT the
>   `OLY:EMPTY-LEAF:V1` BLAKE3 sentinel** (`olympus_crypto::empty_leaf()`), which
>   is a distinct value belonging only to the 256-depth ledger SMT. The two trees
>   are disjoint; their pad/empty values must never be cross-used.
> - **Internal nodes:** `node = domain_node(2, left, right)` (domain tag 2) at
>   every level (`src-tauri/src/zk/poseidon.rs::domain_node`).

The root is committed on the ledger as `original_root`, exactly as today; the
per-segment leaves are persisted in `redaction_segment_manifests`, as today. The
leaf function (`olympus_crypto::redaction` hiding commitment) is **unchanged**.

> **Implementation note — circuit cap removed; normative cap retained.**
> The Groth16 `redaction_validity` circuit imposed 1,024 as a *hard circuit
> constraint* (the circuit was sized for exactly `REDACTION_MAX_LEAVES = 1024`
> inputs). ADR-0030 removes that circuit constraint by dropping the circuit
> entirely. `MAX_REDACTION_SEGMENTS = 2²⁰` above is the *protocol-level
> replacement*: a normative cap that is also the bundle verifier's
> implementation DoS guard (`src-tauri/src/api/redaction/bundle_v3.rs`).
> The two are distinct: the old cap was a *circuit implementation detail*
> you could not raise without a new trusted-setup ceremony; this cap is an
> operational bound that a future ADR may raise without any ceremony change.

> **Root incompatibility (intentional).** This variable-depth root is **not
> equal** to the ADR-0025 fixed-1024/depth-10 root for the same document
> (different number of pad levels, different node chain). Existing V2 manifests'
> roots are not reproducible under V3. Disposition: greenfield / pre-v1 DB wipe
> (see §Security). This is a breaking commitment-layout change in the sense of
> the Critical-Invariants leaf-layout rule, not merely a redaction-manifest
> concern — see the snapshot-chain blast-radius note in §Security.

### 2. Bundle: `V3` signed Merkle fold + **signed segment table**

The bundle carries the **full per-segment table** so the verifier can both fold
to the root *and* know exactly which segments the issuer sanctioned redacting.
Crucially, byte ranges are **into the redacted artifact the recipient holds** (not
the original), so the verifier reconstructs revealed leaves from those bytes (see
§Red-team refinements, finding RT-2, and the per-format reconstruction table in
§3 — most formats reconstruct by a plain slice, two need a minimal byte locator).

```jsonc
{
  "original_root", "format", "segment_count": N, "recipient_id",
  "segments": [            // EVERY segment, ASCENDING UNIQUE segment_id
                           // (sparse for PDF object numbers; dense 0..N-1 only for ooxml-part)
    {
      "segment_id",
      "redacted": <bool>,
      "artifact_offset", "artifact_length",   // byte range IN THE REDACTED ARTIFACT
      "label"?,                                // present for ooxml-part (the part name, bound into the leaf)
      "blinding_decimal"?,                     // revealed only: recipient recomputes the leaf from the slice
      "leaf_hex"?                              // redacted only: the committed blinded leaf (content-safe)
    }
  ],
  "nullifier",      // BLAKE3("OLY:REDACTION:NULLIFIER:V1" || original_root || table_hash || lp(recipient_id_dec)); verifier recomputes + checks
  "signature_hex"   // Ed25519 over the V3 payload below
}
```

> **`content_hash` is intentionally NOT carried** (SR-DEC-1, **ratified
> 2026-06-15**) — `BLAKE3(original plaintext)` was a whole-document confirmation
> oracle. The **`nullifier` IS carried** (SR-DEC-2 **reverted** on ratification):
> it is a derived, recompute-and-check field (§3.4), available as a stable id for
> future issuer-side double-issue detection.

The **signed payload** binds everything a verifier relies on. Per the ratified
SR-DEC-3 revert, values are signed as their **canonical text** renderings
(`lp(...)`-framed), V2-style; malleability is closed by the canonical-form reject
rules in "Encoding conventions" below, not by raw-byte encoding:

```
OLY:REDACTION_BUNDLE:V3 || lp(original_root_hex) || lp(format) || u32_be(N) || lp(recipient_id_dec) || table_hash
table_hash = BLAKE3( "OLY:REDACTION:TABLE:V3"
  || for each segment in ascending segment_id:
       u32_be(segment_id) || u8(redacted) || u64_be(artifact_offset) || u64_be(artifact_length)
       || lp(label) || lp(redacted ? leaf_hex : blinding_decimal) )
```

#### Encoding conventions (normative — pinned for byte-exact cross-language conformance)

Every implementation (Rust producer, Rust + JS offline verifiers) MUST hash the
identical preimage. The signed message is a function of the *committed values*,
not their JSON rendering:

- **`lp(x) := u32_be(len(x)) || x`**, `0 ≤ len(x) ≤ 2³²−1` — this is
  `olympus_crypto::length_prefixed` (ADR-0005). All multi-byte integers
  (`u32_be`, `u64_be`) are **big-endian**.
- **Values are signed as canonical TEXT** (SR-DEC-3 **reverted** on ratification,
  2026-06-15), `lp(...)`-framed — *not* a raw-byte encoding. Soundness against
  hex-case / leading-zero malleability comes from the **canonical-form reject
  rules** (mandatory regardless of encoding), not from raw bytes:
  - **`original_root`** → `lp(original_root_hex)`, **64-char lowercase-hex** ASCII
    (reject any other rendering).
  - **`recipient_id`** → `lp(recipient_id_dec)`, canonical base-10 ASCII (matching
    the producer's `fr_to_decimal`); reject a leading zero (except `"0"`), a sign,
    or value `≥ r`.
  - **`leaf_hex`** (redacted segments) → `lp(leaf_hex)`, 64-char lowercase-hex
    ASCII; reject anything not exactly 64 lower-hex chars / not a canonical field
    element (`< r`).
  - **`blinding_decimal`** (revealed segments) → `lp(blinding_decimal)`, canonical
    base-10 ASCII; reject non-canonical or value `∉ [0, l)` (the BJJ subgroup
    order).
  - **`format`** → `lp(...)` over the ASCII tag (`pdf-object` | `pdf-xref-stream` |
    `text-line` | `ooxml-part`).
  - **`label`** → `lp(...)` over the UTF-8 bytes; an absent label is `lp(empty) =
    u32_be(0)`. Present only for `ooxml-part`.
  - **`u8(redacted)`** → exactly `0x01` (redacted) or `0x00` (revealed); any other
    byte is rejected before hashing.
  - **`table_hash`** → the raw 32 BLAKE3 bytes, appended **un-length-prefixed** as
    the terminal field of the payload (fixed width).
- **`nullifier`** = `BLAKE3("OLY:REDACTION:NULLIFIER:V1" || original_root_raw32 ||
  table_hash_raw32 || lp(recipient_id_dec))` — the two 32-byte values are the
  **raw** root/digest bytes here (not hex), and `recipient_id` is its decimal
  rendering. The verifier recomputes it from the signed inputs and checks the
  bundle field matches (§3.4). It is **not** in the signed payload (it is a pure
  function of signed fields) and is **not** replay protection on its own.
- **Reject, do not reduce.** Every "reject …" rule above is a hard reject *before*
  folding/hashing — a verifier that silently `mod r` / `mod l` reduces an
  out-of-range value is **non-conformant** (the JS reference path's `% l` decode
  must be replaced by a range check). These rejects are conformance-pinned by the
  canonical-form negative vectors in §Security, and they are what make the textual
  signing non-malleable.

These canonical-**form** rules kill hex-case / `0x`-prefix / decimal-leading-zero
malleability: only the canonical rendering of a value hashes (a non-canonical one
is rejected), so the signed message is still a function of the *committed values*,
not an attacker-chosen rendering. The three new domain tags
(`OLY:REDACTION_BUNDLE:V3`, `OLY:REDACTION:TABLE:V3`, `OLY:REDACTION:NULLIFIER:V1`)
are added to `olympus-crypto` constants alongside the existing redaction tags (the
"constants live only in `olympus-crypto`" law).

### 3. Verification (slice / minimal-locator + hash)

A recipient, holding the redacted artifact + the bundle:

1. **Structural checks.** `N == segments.len()`, `2 ≤ N ≤ MAX_REDACTION_SEGMENTS`,
   and the `segment_id`s are **strictly ascending and unique**. The verifier MUST
   NOT assume density: PDF object numbers are intrinsically **sparse**
   (e.g. `{1, 2, 4, 7}`; object 0 is the free-list head; redaction can drop
   objects). For `ooxml-part` **only**, additionally require ids dense `0..N-1`
   and every entry carry a `label` (the OOXML redactor indexes parts by canonical
   sorted position). The `(segment_id, label)` pair is bound together in
   `table_hash`; the verifier treats `label` as the **authoritative** canonical
   part name and `segment_id` as an opaque dense index (it does NOT re-derive the
   id by re-sorting the ZIP — the signed table fixes both). The producer assigns
   `segment_id` = position in the canonical sorted-unique part order, for producer
   determinism only. Every entry's `[artifact_offset, artifact_offset+
   artifact_length)` must lie within the artifact. Reject otherwise.
2. **Reconstruct each leaf.**
   - **revealed** → `slice = artifact[offset .. offset+length]`; the leaf is
     `redaction_leaf(content_scalar(segment_id, content_bytes), blinding)` where
     `content_bytes` is derived from `slice` by the **per-format rule below**
     (the *same* rule each segmenter used to commit the leaf — so the leaf is
     reproduced byte-for-byte). **No re-segmentation.**
   - **redacted** → use the published `leaf_hex` (**authoritative**) for the leaf.
     Redacted artifact bytes are never used to open that leaf, but the artifact
     itself MUST still carry the single deterministic destroyed representation for
     the format (`text-line` re-emits `[REDACTED]\n`, `pdf-object` NUL-fills the
     object body in place, `ooxml-part` emits an empty part body,
     `pdf-xref-stream` rebuilds with the literal token `null`, and `pdf-textrun`
     omits the redacted word bytes). The verifier checks that canonical form only
     to rule out alternate hidden payload bytes; it does not derive redacted leaf
     material from the destroyed bytes.

   **Per-format `content_bytes` for a revealed leaf** (keyed off the signed
   `format` tag — each row mirrors the shipping segmenter exactly):

   | `format` | `content_bytes` | verifier needs |
   |---|---|---|
   | `pdf-object` | the **full untrimmed object span** `artifact[offset..offset+length]` (the literal `N G obj … endobj` bytes — `pdf_objects.rs` commits the whole span, **no** `trim_body`) | plain slice |
   | `text-line` | `artifact[offset..offset+length]` **including the trailing `\n`** (`line_spans` owns it; no trim) | plain slice |
   | `pdf-xref-stream` | the signed range covers the **full `N G obj … endobj` span**; `inner = slice[find("obj")+3 .. rfind("endobj")]`, then `content_bytes = trim(inner)` using the **exact whitespace set `{0x20, 0x09, 0x0d, 0x0a, 0x0c, 0x00}`** (matches `pdf_xref.rs::is_ws`; it includes NUL `0x00` and form-feed `0x0c`, which Rust `is_ascii_whitespace` and the JS regex whitespace class both EXCLUDE, so both verifiers MUST hardcode this set). `rfind("endobj")` is unambiguous because redacted bodies are the literal token `null`, never a raw stream that could embed `endobj`. | minimal PDF `obj…endobj` framing locator |
   | `ooxml-part` | `lp(label) || payload`, `payload = artifact[offset..offset+length]` — the producer sets `artifact_offset` to the local-file **DATA** offset, so the slice IS the raw uncompressed Stored payload | plain slice |

   > **"No parser" claim, corrected.** `text-line`, `pdf-object`, **and
   > `ooxml-part`** reconstruct by a direct slice with no parser — for `ooxml-part`
   > the producer commits the local-file **DATA** offset (§2a), so the signed
   > range is already the raw Stored payload and the verifier never reads a ZIP
   > header. Only **`pdf-xref-stream`** needs a *minimal byte locator* (the PDF
   > `obj`/`endobj` framing above) — **not** a full renderer / FlateDecode / ObjStm
   > decoder. The earlier blanket "no PDF/ZIP parser in the verifier" overstated
   > the case for `pdf-xref-stream` and is replaced by this row-specific statement.
   > (Alternative deferred to the author: have the producer ship each revealed
   > segment's pre-extracted `content_bytes` in the bundle and bind its hash in
   > `table_hash`, making `pdf-xref-stream` a pure slice too at the cost of a
   > larger bundle — a design change, not a spec edit.)
3. **Fold** all `N` leaves — each keyed by its **own** `segment_id`
   (`content_scalar`/`derive_blinding` over `segment_id.to_be_bytes()`) and placed
   at its array position — by the **variable-depth fold of §1** (pad `Fr(0)` to
   `2^⌈log2 N⌉`, `domain_node(2, …)`), and assert the result equals
   `original_root`, **and** that `original_root` is committed on the ledger
   (resolve the on-ledger record **by `original_root`**).
4. **Re-derive `table_hash`** from the bundle's `segments` (the reveal/redact mask
   comes **solely** from each entry's signed `redacted` flag), recompute the V3
   payload, **verify the Ed25519 issuer signature**, and **recompute the
   `nullifier`** from the signed inputs and check it equals the bundle's field (a
   well-formedness check; the nullifier is also the stable id an issuer MAY persist
   for double-issue detection — not replay protection absent a spent-set, see the
   decisions section).

The verifier MUST perform steps 1–3 (structural → reconstruct → fold ==
`original_root`) **before** step 4 (signature). On a fold mismatch it SHOULD
report the **lowest `segment_id`** whose recomputed leaf differs as a diagnostic
— the binding guarantee is the aggregate root equality, not a per-leaf check.

A signature-valid **all-redacted** *or* **none-redacted** bundle is structurally
valid and MUST verify — the verifier does **not** reject on mask cardinality.
Only the *producer* refuses to *mint* an all-redacted / none-redacted disclosure
(`api/redaction/manifest.rs::build_reveal_mask`).

#### Verifier hardening and trust boundary (June 2026)

The offline verifier is the security boundary for post-Groth16 redaction. A
recipient MUST validate a redacted artifact without trusting bundle-supplied byte
ranges as authorities:

1. Parse the redacted artifact with the format-specific replay parser.
2. Reconstruct the deterministic segment table from the artifact itself.
3. Reject duplicate segment ids, malformed ordering, parser/format mismatch,
   unknown format tags, and bundle segment entries absent from the artifact.
4. Cross-check each signed `artifact_offset`, `artifact_length`, and OOXML
   `label` against the artifact-derived value before using the span.
5. Recompute every revealed leaf from artifact bytes plus the published
   `blinding_decimal`.
6. Check every redacted span has the deterministic destroyed form for its format
   (`text-line`: exactly `[REDACTED]\n`; `pdf-object`: NUL / PDF-whitespace body
   between `obj` and `endobj`; `pdf-xref-stream`: logical body `null`;
   `ooxml-part`: empty payload; `pdf-textrun`: omitted bytes / zero-length span).
   This canonical destroyed form is an artifact-integrity check only; redacted
   leaves still come solely from the signed `leaf_hex`.
7. Fold exactly the verified `N` leaves with the pinned variable-depth
   `Fr(0)` padding and node-domain separation, and require equality to
   `original_root`.
8. Recompute `table_hash`, verify the Ed25519 signature over the V3 payload, and
   recompute the nullifier.

What is cryptographically proven:

- The original root is a binding Pedersen/Poseidon Merkle commitment to the
  original segment leaves.
- The Ed25519 signature authorizes the exact disclosure table: root, format,
  segment count, recipient id, signed offsets/lengths/labels, redaction flags,
  and the per-segment opening material (`blinding_decimal` for revealed leaves,
  `leaf_hex` for redacted leaves).
- The local fold proves that revealed artifact bytes and redacted committed
  leaves reconstruct the signed `original_root`.

What is verified by deterministic replay:

- The artifact parses under the signed format and yields the same segment ids,
  labels, and byte spans that the signed table claims.
- Revealed bytes are byte-for-byte the committed revealed segments.
- Redacted regions have exactly one deterministic destroyed representation for
  their format and cannot carry alternate payload bytes in their segment body.
- Text-line redaction re-emits the fixed `[REDACTED]\n` token, preserving line
  delimiters so the verifier can recover line-block boundaries without trusting
  signed offsets.

What is trusted:

- The issuer Ed25519 public key and its key custody.
- The ledger lookup that establishes `original_root` is the root committed for
  the original record.
- The correctness and version pinning of the replay parsers and cryptographic
  primitives in each verifier implementation.
- The producer's policy decision that these are the segments it intended to
  disclose or withhold; the signature attests authorization, not policy wisdom.

Residual assumptions:

- The original ingest segmenter determines what bytes are content leaves versus
  format structure. Replay rejects hidden bytes in covered content regions and
  format-specific obvious slack (for example non-whitespace after PDF `%%EOF`),
  but container syntax bytes are verified as parser structure, not separate
  content leaves.
- `redacted` flags and redacted-artifact offsets are post-ingest disclosure
  metadata. They cannot be inside the original Merkle leaf without precommitting
  every future disclosure; instead they are covered by the signed table and
  checked against deterministic replay.
- V3 does not hide recipient identity, segment count, redaction positions, or
  redacted segment sizes.

Why each property holds: **binding/no-tamper** — a revealed leaf is recomputed
from the artifact bytes and must match what the root commits (Pedersen binding +
fold-to-on-ledger-root). **No partition downgrade** — the `redacted` flag of every
segment is inside `table_hash`, so relabelling a revealed segment as redacted (or
adding phantom segments / changing `N`/`format`) breaks the signature (closes
RT-1/RT-3/RT-5). **No over-disclosure** — a holder cannot reveal a segment the
issuer marked redacted: the signed table fixes the mask, and the redacted leaf is
a Pedersen commitment the holder cannot open without the withheld blinding.
**Hiding** — redacted blindings are withheld; the published `leaf_hex` is a blinded
Pedersen commitment, unrecoverable even for low-entropy content.

#### Leaf construction (normative — reconstructible from this ADR alone)

With `content_bytes` from the per-format table above, a leaf is:

- `content  = reduce_l( BLAKE3_XOF("OLY:REDACTION:OBJ:V1"  || lp(u32_be(segment_id)) || content_bytes)[..64] )`
- `blinding = reduce_l( BLAKE3_XOF("OLY:REDACTION:BLIND:V1" || lp(blind_secret) || lp(content_hash) || lp(u32_be(segment_id)))[..64] )` — server-side only; the verifier uses the published `blinding_decimal` for revealed segments
- `C    = content·B8 + blinding·H` — Pedersen on the Baby JubJub prime-order subgroup; `B8` = circomlib base point
- `leaf = Poseidon(C.x, C.y)`

where `reduce_l(64 bytes)` interprets big-endian then reduces **mod `l`** (the
Baby JubJub subgroup order — **not** mod the BN254 field `p`); `u32_be(segment_id)`
is itself `lp()`-wrapped inside the preimage; and `H` is the pinned
nothing-up-my-sleeve generator from `OLY:PEDERSEN:H:V1` (the same Pedersen `H` the
SBTs use). All three tags already exist in `olympus-crypto` — reference them, do
not add new ones. (`content_hash` here is the producer's internal blinding key, an
input to the *server-only* `blinding` derivation — it is **not** carried in the
bundle; see SR-DEC-1.)

### 2a. Producer rule for redacted-artifact byte ranges

The `artifact_offset` / `artifact_length` are **into the redacted artifact**, so
they cannot come from the persisted manifest (which stores ranges into the
*original* for extraction formats such as `pdf-object` and `text-line`, while
some re-emit formats use placeholders until the artifact is produced):

- The bundle, **not** the DB, carries `{redacted, artifact_offset,
  artifact_length}` per segment. `redaction_segment_manifests` is unchanged — no
  new migration.
- The V3 producer is **`/redaction/redact`** (it holds the original bytes and
  produces the redacted artifact). `/redaction/issue` returns no artifact and is
  **not** a recipient-verifiable V3 producer; retire it for V3 or document that
  its output is unverifiable without the artifact.
- `Segmenter::apply_redaction` (or a new `apply_redaction_with_spans`) MUST
  **return each segment's output byte span in the produced artifact** alongside
  the bytes, so producer and verifiers agree byte-exactly. Per format:
  `pdf-object` (in-place) → output span == original span; `text-line` re-emits
  each redacted block as the fixed `[REDACTED]\n` token, so spans are the produced
  artifact offsets from `apply_redaction_with_spans`; `pdf-xref-stream` → spans
  come from `rebuild_traditional`'s per-object output offsets; `ooxml-part` → the
  span is the local-file **DATA** offset (= local-header start `+ 30 +
  filename_len + extra_field_len`) and the payload length in the canonical Stored
  ZIP, computed by the producer so the verifier never parses a ZIP header.

### 4. Drop `redaction_validity`; lower the ceremony to power 17

Removing `redaction_validity` is a **compile-gated, atomic** edit — `verify.rs`
embeds its vkey/manifest via `include_str!`, and `build.rs` / `startup.rs`
enumerate the circuit by name, so deleting the artifact files alone breaks the
build. Do all of the following in **one** commit:

- **`src-tauri/src/zk/verify.rs`** — remove the `include_str!` vkey/manifest
  consts, the `REDACTION_VERIFIER` `OnceLock`, and `redaction_verifier()`.
- **`src-tauri/src/api/zk/mod.rs`** — remove the `redaction_verifier` import, the
  `/zk/verify` `"redaction_validity"` arm (with its M-2 issuer-trust-anchor
  block), the name→`Circuit` map entry, and the `/zk/prove` `"redaction_validity"`
  arm.
- **`src-tauri/build.rs`** — drop `"redaction_validity"` from `CIRCUITS`.
- **`src-tauri/src/zk/mod.rs`** — remove `Circuit::RedactionValidity`, its
  `name()` arm, and the `all_circuits` test entry.
- **`src-tauri/src/startup.rs`** — drop `"redaction_validity"` from the
  placeholder-detection lists and the `verify_ceremony_manifests` set.
- **Artifacts & circuit source** — delete
  `proofs/keys/{redaction_validity.wasm,.r1cs,.ark.zkey}`,
  `verification_keys/redaction_validity_vkey.json`,
  `manifests/redaction_validity_manifest.json`, **and**
  `proofs/circuits/redaction_validity.circom` (it is otherwise still hashed into
  `setup_circuits.sh`'s build fingerprint); the redaction params in
  `parameters.circom` become dead (optional cleanup). Prune the redaction
  witness/prover/segment-circuit modules.
- **`proofs/setup_circuits.sh`** — remove `"redaction_validity"` from the **bash
  `CIRCUITS` array**, delete its `REQUIRED_POWER=20` case row and `--O2` force
  block, and fix the now-stale header / dev-fallback comments that name
  `redaction_validity` / "unified needs power 20". Regenerate keys at **power 17**
  for the only remaining production circuits, `document_existence` (~8k) +
  `non_existence` (~70k) — both fit `2¹⁷ = 131,072` (`non_existence` is the floor;
  the dev-fallback table already pins it to power 17).
- **`proofs/phase2_ceremony.sh`** (the multi-party v1.0 release path — *was missing
  from the original list*) — remove **both** `redaction_validity` **and** the
  gated `unified_canonicalization_inclusion_root_sign` from its `CIRCUITS` array,
  and switch its hardcoded ptau (file name + header + provenance echoes) to the
  power-17 file, so the release path realizes the same saving and uses the same
  ptau as `setup_circuits.sh`. *Normative decision (not "pick one"):* since
  `unified`/`federation_quorum` are gated-not-shipped, they are dropped here too;
  re-introducing either later is a deliberate ceremony change that re-adds the
  power-20 ptau to this script only.
- **`proofs/CEREMONY_INTEGRITY.md`** — update the manifest ptau example to the
  power-17 file/power/blake2b, remove `redaction_validity` from the operator
  runbook sanity-check loop, and drop the now-moot ADR-0025 power-20 sizing
  section.
- **Tests (same commit — both `cargo test --workspace` *and*
  `--features prover,zk-test-utils` must compile; redaction symbols are referenced
  from the un-gated lean target too, so this is build-breaking):** remove
  `pub use redaction::RedactionWitness` from `zk/witness/mod.rs`; delete
  `tests/zk_prove_redaction.rs` + its `[[test]]` stanza in `Cargo.toml`; strip the
  redaction imports/cases from `tests/zk_witness_proptest.rs`,
  `tests/zk_soundness.rs`, `tests/zk_soundness_false_statement.rs`,
  `tests/zk_fixtures/mod.rs`; and delete the in-module
  `redaction_verifier_loads_from_embedded_vkey` test in `verify.rs`.
- **Cross-language vectors (same commit)** — regenerate
  `verifiers/test_vectors/redaction_vectors.json` to the V3 variable-depth shape
  (drop `redacted_commitment`/`reveal_mask`/`max_leaves`/`tree_depth`; add
  `segment_count`, per-segment `redacted` + `artifact_offset/length`,
  `table_hash`, `signature`) and update its consumers in the same commit:
  `verifiers/javascript/test_redaction.js` (today hard-asserts `max_leaves==1024` /
  `tree_depth==10` and decodes via `% l`) and the Rust verifier (which currently
  has **no** redaction code).

> **PTAU resolved — power 17.** Power 17 is the floor (`non_existence` ~70k needs
> `2¹⁷ = 131,072`; `document_existence` ~8k fits) and requires a **distinct,
> smaller Phase-1 file** — `powersOfTau28_hez_final_17.ptau` (~289 MiB vs the
> power-20 ~2.4 GB) from the same Hermez bucket
> (`https://storage.googleapis.com/zkevm/ptau/`), with its **own BLAKE2b-512
> checksum** (it is *not* the power-20 bytes truncated). Set `PTAU_POWER=17` and
> add a pinned `PTAU_CHECKSUMS[17]` entry (the map has only 19/20 today; the
> operator computes `b2sum` on the downloaded file — never leave it empty).
> **Prerequisite bug fix (same commit):** `setup_circuits.sh`'s checksum guard is
> **fail-open** — it gates the mismatch check on a *non-empty* expected checksum,
> so a power with no pinned entry silently *skips* verification yet prints
> "verified ✓" (contradicting its own comment). Harden it to hard-fail on an empty
> checksum for a non-local ptau **before** flipping the power, or the migration
> can disable Phase-1 integrity verification. Keeping the power-20 file works
> (groth16 accepts any `power ≥ circuit`) but yields zero saving — fallback only.
> `generate_manifest` needs no change (it auto-detects power from the on-disk
> file). Operator precondition: `snarkjs r1cs info` confirms both circuits
> `≤ 131,072` before regen; bump to power 18 if a future circuit edit exceeds it.

> **Invariant unaffected:** the `treeSize=0` guard (`verify.rs`) is scoped to
> `document_existence` and the unified circuit only — the redaction branch never
> invoked it, so dropping redaction is invariant-safe there.

### 5. Visual text-run redaction falls out for free

With the cap raised to `MAX_REDACTION_SEGMENTS` (effectively uncapped for real
documents), ADR-0029's `pdf-textrun` segmenter can commit one leaf per text run
with no grouping hack — the only reason the old 1024 cap mattered.

## What is lost vs. the SNARK (accepted)

- The bundle reveals the **recipient id** and the **count/positions** of redacted
  segments (never their content). `recipient_id` is, by convention, the
  recipient's Baby JubJub public-key X coordinate — a **stable per-recipient
  identifier**, bound into the signed payload. Anyone who later obtains the bundle
  (forwarded, leaked, or filed as court evidence) learns the recipient's
  cryptographic identity and can **correlate every redaction issued to that
  recipient across all documents** — a distinct linkage axis from the
  same-document linkability below. Acceptable for the stated court-evidence /
  press-freedom threat model (known recipient). If unlinkable recipients are ever
  required, replace `recipient_id` with a per-bundle pseudonym `H(recipient_pk ||
  nonce)`; deferred.
- The signed table ships `artifact_offset` / `artifact_length` for **every**
  segment, including redacted ones, so the **exact size and byte position of each
  withheld region** is disclosed (not its content). Acceptable for the stated
  threat model (structure is largely visible); documented here so it is not a
  surprise.
- Because blindings are deterministic per `(document, segment)`, the same
  document redacted for two recipients yields **identical published redacted
  `leaf_hex`** — the two bundles are linkable as the same original (content stays
  hidden). The SNARK did not expose this. Acceptable here; documented.
- Proof size grows from ~constant (~200 B) to O(N) hashes. Negligible: the
  recipient already holds the whole document.
- **`content_hash` is no longer carried (and this is a fix, not a loss).** The V2
  bundle carried `content_hash = BLAKE3(original artifact)`. Handed to a recipient
  who holds only the *redacted* artifact, that was a **whole-document confirmation
  oracle**: anyone who could guess or independently obtain a candidate original
  (a leaked draft) confirmed it with one hash — full content recovery for any
  guessable/leaked document, exactly the press-freedom scenario. V3 **drops it**
  from both the bundle and the signed payload and re-keys the ledger lookup on
  `original_root` (see SR-DEC-1). `original_root` resists the plaintext oracle
  **only while `blind_secret` is independent of the signing identity**: its leaves
  fold in per-segment blindings `derive_blinding(blind_secret, content_hash,
  segment_id)`, and `content_hash = BLAKE3(plaintext)` is itself recomputable from
  a guess — the *only* secret input is `blind_secret`. By default `blind_secret`
  is **not** independent: it derives from the BJJ authority key
  (`state.rs::derive_redaction_blind_secret`), the same root the signing key
  derives from. A production deployment MUST set `OLYMPUS_REDACTION_BLIND_SECRET`
  to an independent secret; otherwise a single key compromise restores exactly the
  oracle this fix removes (see the key-custody note below).
- **Issuer Ed25519 key compromise — the single largest residual trust assumption,
  and strictly worse than V2.** With the Groth16 proof dropped (§4), a V3 bundle's
  authenticity rests entirely on the Ed25519 signature over `(original_root,
  format, N, recipient_id, table_hash)`. A leaked signing key lets an attacker
  mint a signature-valid disclosure bundle for **any** `original_root` on the
  ledger, with any `recipient_id` and any reveal/redact mask — including a
  maximally-revealing mask the legitimate issuer never sanctioned (revealed
  segments need no withheld secret; the attacker supplies the slice + blinding).
  This is worse than V2, which paired the same signature with a Groth16 proof
  binding the circuit-enforced `redacted_commitment`, so a leaked key alone could
  not fabricate a verifying bundle. V3 has no SNARK backstop; the mitigations are
  persisted-key custody, the operator-controlled single-issuer model, and ledger
  anchoring (which bounds *which* roots exist but authorizes no particular
  disclosure). Accepted under the threat model; documented so an auditor can weigh
  it.
- **Key-custody trust root (combined).** In the default config the BJJ authority
  key is the *sole* trust root for V3 redaction — it derives both the dev Ed25519
  signing key and `blind_secret`. One key compromise therefore yields **both**
  bundle forgery (above) **and** the `original_root` confirmation oracle (the
  blinding qualification above). Production decouples the *signing* key
  (`OLYMPUS_INGEST_SIGNING_KEY` required) but **not** `blind_secret` by default, so
  a hardened deployment MUST set **both** `OLYMPUS_INGEST_SIGNING_KEY` and
  `OLYMPUS_REDACTION_BLIND_SECRET` to independent secrets. Document both as
  production-required in the §4 operator runbook.

## Security & invariants

- Same hiding-leaf primitive, same domain-2 fold, same Ed25519 signing key
  (persisted). **Domain-separated** new bundle tag `OLY:REDACTION_BUNDLE:V3`
  (disjoint from any prior bundle tag and the SBT tags), plus
  `OLY:REDACTION:TABLE:V3` for the segment-table hash. Both new tags are added to
  `crates/olympus-crypto` constants (canonical-constants law).
- **Pad-value disjointness:** the redaction fold pad is `Fr(0)` (the BN254 scalar
  zero); the ledger-SMT empty leaf is `blake3(OLY:EMPTY-LEAF:V1)`. These trees are
  disjoint; their pad/empty values must never be cross-used.
- No GPL; no new ZK. The offline verifiers (`verifiers/{rust,javascript}`)
  **gain `content_scalar` + `redaction_leaf`** (BLAKE3-XOF → subgroup scalar,
  Pedersen on Baby JubJub, Poseidon) on top of their existing Merkle + Ed25519 +
  Pedersen code, plus the two minimal byte locators for the re-emit formats (§3).
- **Cross-language V3 vectors** (`verifiers/test_vectors`) MUST include, at
  minimum: a revealed segment for **each of the four formats** (pins each
  per-format `content_bytes` rule); fold roots for **N=2, N=3 (non-power-of-two
  → `Fr(0)` padding actually exercised), and N=1024** (must equal today's
  fixed-1024 root for the same leaves); an **all-redacted** and a **none-redacted**
  bundle (both verify); a **byte-dump fixture** (segment-table input bytes →
  `table_hash` → final payload → signature) so a from-spec verifier self-checks
  the byte layout; and **negative** vectors: `N=0`/`N=1` rejected,
  `N>MAX_REDACTION_SEGMENTS` rejected, and one that **flips a single segment's
  revealed/redacted flag** on an otherwise-valid bundle and asserts the signature
  check **fails**. Add three **canonical-range** negatives (pin the canonical-form
  reject rules across both verifiers): a `leaf_hex` decoding to exactly BN254 `r` is rejected while
  `r-1` is accepted; a `blinding_decimal` equal to the BJJ subgroup order `l` is
  rejected while `l-1` is accepted; a `recipient_id` equal to `r` is rejected
  while `r-1` is accepted (bounds: leaf/recipient `< r` via
  `validate_be_bytes_to_fr`; blinding `< l` via `check_subgroup`; both gated
  **before** folding — a `mod r`/`mod l` reduction is non-conformant). And a
  **tampered-revealed-bytes** vector: alter a revealed segment's artifact bytes
  and assert the fold `!= original_root` (parity with the existing per-leaf
  assertion in `verifiers/javascript/test_redaction.js`).
- **Greenfield migration (pre-v1, DB wipe): V2 Groth16 bundles are not retained.**
  *Blast radius (do not understate):* the segment fold root is committed both as
  `ingest_records.original_root` **and** as the per-record **leaf** of the
  depth-20 BJJ-signed snapshot tree
  (`api/ingest/files/snapshot.rs` → `zk/snapshot.rs::snapshot_new_record`, which
  signs `snapshot_root`). Switching the fixed-1024 fold to the variable-depth fold
  therefore changes `original_root`, every downstream `snapshot_root`, and the
  entire BJJ `snapshot_sig` chain for the shard — a breaking layout change in the
  sense of the Critical-Invariants leaf-layout rule, not merely a
  redaction-manifest concern. Disposition: pre-v1 DB wipe, no backfill. The fold
  change MUST land together with regenerated committed golden vectors (at minimum
  `verifiers/test_vectors/redaction_vectors.json`, today pinned to
  `max_leaves:1024 / tree_depth:10` and a fixed-fold `original_root_hex`, plus any
  snapshot vectors) so the verifiers do not silently keep validating the old root.

## Red-team refinements (29-agent adversarial review, 2026-06-14)

The initial V3 design was red-teamed before implementation. **No content-recovery
or tamper-passes-as-authentic attack survived** — Pedersen binding + fold-to-on-
ledger-root hold. Six confirmed findings, all design-time, folded into the spec
above:

- **RT-1 / RT-5 (HIGH) — partition unbound.** The root pins leaf values/positions
  but *not* the revealed/redacted labelling, so a holder could downgrade an
  authorized disclosure (hide more than sanctioned). **Resolved:** the per-segment
  `redacted` flag is inside `table_hash`, which the signature covers; the verifier
  derives the mask solely from the signed table.
- **RT-3 (MEDIUM) — `N`/format/padding reinterpretation.** Variable-depth zero
  padding + unsigned `N` allowed phantom "redacted" padding slots. **Resolved:**
  `N` and `format` are signed; `table_hash` covers every segment; the verifier
  folds **exactly the N supplied leaves** (each keyed by its own `segment_id`) and
  asserts the root == `original_root`. A phantom slot raises `N` and changes
  `table_hash` (signature breaks); a dropped/extra segment changes the fold.
  *(Corrected by SR-1: the original "require dense ids `0..N-1`" rule was
  impossible for the sparse-object-number PDF formats — see below. Density is now
  required for `ooxml-part` only; binding comes from the fold + signed `N`/table,
  not from density.)*
- **RT-4 / RT-5 (MEDIUM) — `redacted_commitment` undefined without the circuit.**
  It was a Groth16 public signal with no V3 definition. **Resolved:** dropped
  entirely; the signature binds the segment table directly. *(SR-DEC-2 went
  further and also dropped the `nullifier`, which was likewise an unconsumed
  field.)*
- **RT-2 / RT-6 (MEDIUM) — verifiability gap.** The bundle shipped no byte ranges
  and §3 implied re-segmenting the artifact, which is unsound. **Resolved:** ship
  per-segment byte ranges **into the redacted artifact** + bind them in
  `table_hash`; the verifier reconstructs revealed leaves from those bytes.
  *(Refined by SR-2/SR-3: most formats slice directly, but `pdf-xref-stream` and
  `ooxml-part` need a minimal byte locator — the blanket "no parser" claim was
  inaccurate and is corrected in §3.)*
- A mandatory regression: a cross-language negative vector that flips one
  segment's revealed/redacted role on an otherwise-valid bundle and asserts the
  signature check **fails**.

## Second hardening pass (independent review, 2026-06-14)

A second adversarial review (8-lens fan-out + skeptic verification) went *beyond*
RT-1…RT-6 to attack the *spec precision* an implementer would rely on. No new
forgery / content-recovery attack was found; the issues are **spec gaps that would
break a correct, byte-exact, cross-language implementation**, plus three design
decisions. (The `verifier-implementability`, `threat-model-honesty`,
`ceremony-operational`, and part of the `fold-spec` verification batches hit a
session limit on the first run; a **follow-up confirmation pass** — recorded
below — re-ran them against this hardened doc and confirmed 16 residual findings,
all folded into the spec above.)

**Spec-precision fixes folded into the spec above:**

- **SR-1 (HIGH) — dense-id rule was impossible for PDF.** RT-3's "ids exactly
  `0..N-1` dense" contradicts the PDF/xref scheme where `segment_id` *is* the
  sparse indirect-object number the leaf is keyed by. **Fix:** §3.1 now requires
  strictly-ascending-unique ids (dense only for `ooxml-part`); binding comes from
  folding exactly the `N` signed leaves.
- **SR-2 (HIGH) — reconstruction rule was wrong/ambiguous per format.** §3.2's
  single "`trim_body(slice)` for the PDF formats" mismatched `pdf-object` (commits
  the **untrimmed** span) and conflated the four formats. **Fix:** the per-format
  `content_bytes` table in §3.
- **SR-3 (HIGH) — "no parser" claim was inaccurate.** True only for `text-line` /
  `pdf-object`; the re-emit formats need a minimal locator. **Fix:** §3 "No parser
  claim, corrected."
- **SR-4 (BLOCKING→resolved) — pad value was ambiguous.** "zero/empty-leaf
  sentinel" conflated `Fr(0)` with `blake3(OLY:EMPTY-LEAF:V1)`. **Fix:** §1 pins
  `Fr(0)` + the disjointness note in §Security.
- **SR-5 (HIGH) — no upper bound on `N`** (u32 → DoS). **Fix:** `MAX_REDACTION_SEGMENTS
  = 2²⁰` in §1.
- **SR-6 (MEDIUM) — `lp()` and every field's byte encoding were unstated.**
  **Fix:** the "Encoding conventions" block in §2.
- **SR-7 (MEDIUM) — `N=0/1` / edge cases undefined.** **Fix:** §1 requires `N ≥ 2`
  (else chunk fallback), aligned with the text segmenter.
- **SR-8 (MEDIUM) — destroyed-bytes check unspecified / not a control.** **Fix:**
  §3.2 makes `leaf_hex` authoritative for redacted leaves while treating the
  destroyed bytes as a canonical artifact-integrity check, not leaf material.
- **SR-9 (MEDIUM) — schema/producer gap for redacted-artifact ranges.** **Fix:**
  §2a.
- **SR-10 (MEDIUM) — snapshot-chain blast radius understated.** **Fix:** §Security
  greenfield note.
- **SR-11 (LOW) — `drop redaction_validity` edit list incomplete.** **Fix:** the
  atomic checklist in §4.
- **SR-12 (LOW) — `recipient_id` correlation weight unstated.** **Fix:** §What is
  lost.

**Design decisions — RATIFIED 2026-06-15: SR-DEC-1 ratified; SR-DEC-2 and SR-DEC-3
reverted.** These shape the wire format; nothing has shipped, so the
`OLY:REDACTION_BUNDLE:V3` tag is kept (no V3 exists in the wild to disambiguate
from); bump to V4 only if you prefer a clean boundary. The §2/§3 text above
reflects the ratified outcome.

- **SR-DEC-1 — drop `content_hash`; re-key the ledger lookup on `original_root`.**
  Removes the whole-document confirmation oracle (§What is lost). Implementation
  note: the producer (`issue.rs`/`redact.rs`) currently resolves its manifest by
  `content_hash`; it must resolve by `original_root` instead (the loader already
  cross-checks the leaf fold equals `original_root`, so the binding is preserved).
  *If you instead want a content binding, specify a **salted, non-shipped**
  commitment `BLAKE3("OLY:REDACTION:CONTENT:V3" || lp(server_salt) ||
  original_bytes)` — never put the salt in the bundle.*
- **SR-DEC-2 — drop the `nullifier`. → REVERTED (2026-06-15): the `nullifier` is
  KEPT.** It is the derived `BLAKE3("OLY:REDACTION:NULLIFIER:V1" || original_root ||
  table_hash || lp(recipient_id_dec))`, recomputed-and-checked by the verifier
  (§3.4). Honest scope: it is a stable per-`(original_root, table_hash,
  recipient_id)` identifier an issuer MAY persist for double-issue detection, but
  with **no spent-set wired yet it is not replay protection** (it cannot stop a
  recipient re-presenting one valid bundle). Wiring a spent-set is a separate,
  additive step; until then "recompute and check" is a well-formedness check only.
- **SR-DEC-3 — sign canonical raw bytes. → REVERTED (2026-06-15): sign the
  canonical TEXT renderings** (`lp(original_root_hex)` / `lp(recipient_id_dec)` /
  `lp(leaf_hex)` / `lp(blinding_decimal)`), V2-style, per §2 Encoding conventions.
  This is sound because the **canonical-form reject rules** (mandatory regardless)
  reject any non-canonical rendering *before* hashing, so malleability is closed
  without raw-byte encoding — and it minimizes churn for the existing
  decimal-handling verifiers. *(The raw-byte alternative is equivalent on security;
  it was not chosen.)*

**Follow-up confirmation pass (2026-06-14, second run).** The three batches that
died on the session limit were re-run against this hardened doc; 16 residual
findings confirmed and folded in (no new forgery/recovery attack):

- *Ceremony (CO-1…9):* PTAU resolved (power-17 = a distinct smaller file with its
  own checksum; the `setup_circuits.sh` fail-open checksum guard must be hardened);
  the §4 atomic checklist extended to **both** bash `CIRCUITS` arrays, the
  `REQUIRED_POWER` row, `redaction_validity.circom`, the four redaction test files +
  the `witness/mod.rs` re-export, `CEREMONY_INTEGRITY.md`, and the cross-language
  vectors; `phase2_ceremony.sh` also drops the gated `unified` circuit.
- *Implementability (VI-2…8):* `recipient_id` / `leaf` / `blinding` canonical-form
  rules pinned (§2); `ooxml-part` reduced to a pure slice and the `pdf-xref-stream`
  trim charset pinned (§3); a normative leaf-construction block added (§3);
  canonical-range + tampered-bytes negative vectors added (§Security).
- *Threat model (TMH-1/2 + combined):* the `original_root` oracle is **conditional**
  on an independent `blind_secret` (which defaults to the BJJ key in production);
  the issuer-Ed25519-key-compromise blast radius (strictly worse than V2) and the
  combined single-key trust root are now stated (§What is lost). Net new
  production requirement: set **both** `OLYMPUS_INGEST_SIGNING_KEY` and
  `OLYMPUS_REDACTION_BLIND_SECRET` to independent secrets.

## Phased implementation

1. **Commitment**: variable-depth fold (§1, pad `Fr(0)`, `N∈[2, MAX_REDACTION_SEGMENTS]`)
   in the segmenter/ingest path (replace the 1024 pad; keep the fail-closed
   over-cap guard at the new bound). Golden-test the root **and regenerate the
   committed cross-language redaction/snapshot vectors** (`verifiers/test_vectors`).
2. **Producer**: `V3` bundle (fold + sign per §2/§2a), drop the Groth16 prove call;
   return per-segment redacted-artifact spans from `apply_redaction`.
3. **Verifiers** (Rust + JS) + cross-language vectors: verify `V3` (per-format
   reconstruction table + the two minimal locators + all the §Security vectors).
4. **FE** (`api.ts` + RedactTab) for the `V3` shape.
5. **Ceremony**: drop `redaction_validity` (§4 atomic checklist); resolve the ptau
   question, then regenerate power-17 keys/manifests (operator step —
   `setup_circuits.sh`).
6. **ADR-0029 Phase B** now unblocked (uncapped text runs).

## Alternatives considered

- **Keep Groth16 + add a parallel Merkle path** — double the producer / verifier
  / audit surface for marginal benefit; rejected.
- **Rebuild ZK redaction on SMT inclusion (uncapped + ZK)** — only if recipient/
  structure privacy becomes a hard requirement; deferred.
- **Rasterized tiles (ADR-0023/0024)** — rejected previously; unrelated.
