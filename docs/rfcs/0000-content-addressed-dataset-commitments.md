# RFC-0000: Content-addressed dataset commitments with near-duplicate proofs

| Field      | Value                                                              |
|------------|--------------------------------------------------------------------|
| Status     | **Draft**                                                          |
| Author(s)  | Olympus maintainers                                                |
| Date       | 2026-11-26                                                         |
| Tracking   | Ligetron feasibility prototype (`olympus-ligetron-prototype`, items 1–4) |
| Supersedes | None. Adds a format next to ADR-0027; does not replace it.        |

## Summary

A specification, without code, for committing an AI training dataset version
so that anyone holding a copyrighted work can get a verifiable answer to:

1. **Exact:** is this work, after a stated canonicalization, in dataset `D`
   version `v`? (membership / non-membership)
2. **Near-duplicate:** does the committed fingerprint index hold a candidate
   *close to* this work in `D` version `v`, even if its bytes differ?
   (similar-membership; similar-non-membership is specified but outside v1,
   see §Guarantee classes)

Each dataset version is committed as a content-keyed sparse Merkle tree of
items plus a similarity index of locality-sensitive fingerprints. Both are
bound into one global root. A versioned header carries that root and is
signed with an ADR-0035 `SignatureEnvelopeV3`. The header names its suite:
v1 ships on the existing `ed25519` suite and moves to the hybrid Ed25519 +
ML-DSA-65 suite once an ML-DSA-65 implementation is accepted (§7). Proofs exist in
two forms over the same bytes. A *plain* proof is a Merkle path. It is cheap,
and checking it against a known root needs no signature, so its strength
against a quantum adversary is that of BLAKE3's second-preimage and
collision resistance. Trusting *which* root is the dataset's still rests
on the header signature and its ledger inclusion. A *zero-knowledge* proof
runs in Ligetron and reveals nothing beyond the yes/no answer. Every hash,
including those inside the zero-knowledge statements, is BLAKE3.

## Guarantee classes

This format provides three kinds of guarantee. They differ in strength and
MUST be specified, documented and described to users separately. A tool or
report built on this format MUST NOT present a weaker class as if it were a
stronger one.

| Class | What it establishes | Strength | Statements |
|---|---|---|---|
| **A. Commitment** | Which exact canonical items a signed dataset version contains, and which it does not. Which items changed between two versions. | Cryptographic: reduces to BLAKE3 and the header signature | M1, N1, D1, D2 |
| **B. Candidate retrieval** | That the committed fingerprint index holds a segment within a stated distance of the query (M2), or holds none among the buckets the query maps to (N2). | Cryptographic *about the committed index*. Whether a fingerprint match means a human-recognizable copy is an **operating characteristic** with measured recall and precision, not a guarantee. | M2, N2 |
| **C. Recorded statements** | What the committer stated about each occurrence: source, license, retrieval time, opt-out status, repetition count. | Attributable: signed and included in the insert-only ledger. **Not** evidence that the statement is true. | M1-open with metadata |

Consequences that every implementation and document MUST respect:

- **N2 claims less than its name suggests.** A valid N2 proof means *no
  candidate was found under this fingerprint index*. It does **not** mean
  *no item satisfying a similarity predicate exists*. LSH buckets are a
  probabilistic retrieval structure, so a near-duplicate can sit in
  buckets the query does not touch (§9 gives the miss rates). N2 also
  relies on the committer having indexed every item honestly (trust
  assumptions 1–2). For this reason **N2 is not part of v1** (§Scope). It
  stays specified so that its encoding is fixed, and it may be enabled
  later under the label "no candidate under index", never "no
  near-duplicate".
- **Thresholds are operating parameters.** `m ≥ 84` of 120 and Hamming `≤ 31`
  are published with their measured recall and precision on named
  evaluation sets (§Unresolved 2). They are not security parameters, and a
  proof that a fingerprint passes or fails them says nothing about whether a
  court or a person would call the two works copies.
- **Class C is evidence, not compliance.** `opt_out_status = 1` records
  that the *committer's own records* marked the source as opted out. It is
  not proof that a valid opt-out request was made, and `0` is not proof that
  none was. No statement in this format decides a legal question. It fixes,
  attributably and in time, what the committer held and what it said.
- **Wording in derived documents.** Compliance mappings, product copy and
  reports MUST describe class C results as "evidence of recorded provenance"
  or "evidence of recorded opt-out state", never as "proof of provenance". A
  D1 result may be described as "evidence the work was removed from the
  committed dataset" only when its header chain and fork check also passed
  (§10). It is never "proof an opt-out was honoured".

## Scope

This RFC fixes the encoding of everything below, so that later stages need
no format change. Only the **v1** column may ship as a supported feature.

| Area | v1 | Later, gated |
|---|---|---|
| Statements | M1, M1-open, N1, D1, D2 (class A); M2, plain only (class B) | N2 as "no candidate under index"; every zero-knowledge statement |
| Extraction | `file/whole`, `jsonl/field` | `parquet/column`, `webdataset/member` (dependency and license review first) |
| Canonicalization | `bytes/raw`, `text/utf8-nfc` | `image/rgba8` (pinned decoder, license review first) |
| Fingerprints | `text/minhash-120`, after the threshold study (§Unresolved 2) | `image/pdq-256` |
| Signing | `ed25519` suite | `hybrid-ed25519-ml-dsa-65`, plus re-signing. This is a separate cryptographic milestone that needs an accepted, independently tested ML-DSA-65 implementation (§7). |
| Audit | full rebuild, sampled audit | — |
| Verifiers | Rust, JavaScript, Python, verify-only, against shared vectors | — |

Zero-knowledge work proceeds in this order, and each step starts only if
the previous step's measurements justify it:

1. Benchmark Ligetron path cost at depths 30–40 on real hardware.
2. Fix the exact public/private boundary (§8) from those numbers.
3. Prototype M1/N1, behind a cargo feature and not in production.
4. Only then consider M2.

N2 in zero knowledge stays deferred. The image estimate alone is about
2.6 h per query (§8), and N2 is out of v1 scope in any form.

## Motivation

ADR-0027 already commits datasets, but it keys each record by
`record_key("olympus.dataset-record", record_id, version)`, with `record_id`
chosen by the committer. A rights holder does not know the committer's
`record_id`, so "is *my work* in this dataset?" cannot be asked. Exclusion in
ADR-0027 means "no record with this ID", not "no copy of this content".

A copy also rarely matches byte for byte. It may be re-encoded, resized,
reformatted, or embedded as an excerpt in a larger web page. An exact-hash
commitment alone answers the question rights holders care about almost
never.

The Ligetron prototype (items 1–4) established:

- Merkle membership and non-membership statements prove at depth 20.
- BLAKE3 can be computed inside a Ligetron relation. Each additional
  compression cost between about 0.4 s and 1.6 s on software Vulkan; these
  are single noisy samples.
- Proving over raw document bytes grows linearly with size, about 15 s per
  KiB, so whole items must **never** be hashed in-circuit.

This RFC is shaped by those results. Items are hashed outside any proof.
Proofs only touch fixed-size digests and fingerprints, so proof cost depends
on dataset size (tree depth) and never on item size.

## Terms

| Term | Meaning |
|---|---|
| item | One training example (a text, an image, …) |
| extraction profile | A pinned function from a stored dataset file (a JSONL file, a Parquet file, a WebDataset tar, …) to the sequence of raw items it contains, with per-occurrence provenance; identified by `(extraction_id, extraction_version)` plus its parameters |
| occurrence | One appearance of an item in the source files. Several occurrences can canonicalize to the same bytes. |
| canonicalization profile | A pinned function from raw item bytes to canonical bytes; identified by `(profile_id, profile_version)` |
| fingerprint profile | A pinned function from an item to one or more fixed-size similarity fingerprints, plus its LSH banding |
| partition | One of `2^p` top-level subtrees selected by the first `p` bits of a content key. The user-facing term "shard" in this RFC means partition. |
| ledger shard | The Olympus ledger shard (ADR-0005, `shards` registry) into which the signed header is committed. Distinct from a partition. |
| `lp(x)` | `u32_be(len(x)) ‖ x` — Olympus's existing length-prefix framing |
| `H_name(m)` | `BLAKE3.keyed_hash(K_name, m)` with `K_name` from the domain table (§11) |

All integers are big-endian and fixed-width. All strings are UTF-8, NFC,
non-empty unless stated otherwise, and always framed with `lp`.

## Detailed design

### 0. Item extraction

Before anything is canonicalized, the committer must say what an item *is*.
Training data is rarely stored one item per file. It is stored as JSONL
lines, Parquet rows or tar members, and two committers reading the same
files with different field choices would commit different items. An
extraction profile pins that step.

v1 extraction profiles:

| `extraction_id` | v | Parameters | Items | Occurrence provenance |
|---|---|---|---|---|
| `file/whole` | 1 | none | Each file is one item. | `source_uri` = the file's path within the dataset |
| `jsonl/field` | 1 | `field` (a JSON Pointer, RFC 6901), `uri_field`, `license_field` (both optional pointers) | Each line is parsed as one JSON object. The item is the UTF-8 encoding of the string at `field`. A line that is not an object, or whose `field` is absent or not a string, is rejected. | values at `uri_field` / `license_field`, else empty |
| `parquet/column` | 1 | `column`, `uri_column`, `license_column` (optional) | Each row is one item. The item is the `column` value, which must be `BYTE_ARRAY` (`STRING` or binary). A null is rejected. | values in `uri_column` / `license_column`, else empty |
| `webdataset/member` | 1 | `extension` (for example `jpg`, `txt`) | Each tar member whose name ends in `.extension` is one item, grouped by WebDataset key | `source_uri` = `<tar path>#<key>` |

Rules:

- Rejections at this step are counted in `rejected_count`, together with
  canonicalization rejections (§1). They are never silently skipped.
- Parameters are part of the profile entry and are bound into the global
  root through `extraction_table_digest` (§5). Changing a field name is a
  different table entry, not a hidden configuration change.
- A dataset version may use several extraction profiles, one per group of
  source files. The sidecar file list maps each source file to its
  extraction table index. That list is committed only by reference, like
  ADR-0027's record index, and an auditor uses it for the full rebuild
  (Security §2).
- Extraction is a committer-side step. A rights holder never runs it, because
  they query with their own copy of the work, starting at §1.

`jsonl/field` v1 parsing rules, so that two parsers cannot disagree on which
items a file holds:

- Lines are split on LF only. One trailing CR on a line is removed. A single
  empty line at end of file is ignored. Any other empty line is rejected.
- Each line is parsed as RFC 8259 JSON. A line that is not an object, has a
  duplicate key at any depth, nests deeper than 128, or contains an unpaired
  surrogate escape (`\uD800`–`\uDFFF` without its pair) is rejected.
- The item is the decoded string value, re-encoded as UTF-8 with no further
  normalization. Normalization happens in §1.

### 0a. Profile reproducibility

Every profile, whether extraction (§0), canonicalization (§1) or
fingerprint (§1a), is defined by two separate things:

- **`(id, version)` names the output function.** It is the bytes a
  conforming implementation must produce, and the inputs it must reject.
  Any change to output or to rejection behaviour is a new `version`.
- **`implementation_id` names the software that computed it.** It is a
  `;`-separated list, sorted by name, of `name=version` pairs naming every
  component whose behaviour reaches the output. Examples are the Olympus
  crate, the normalization library, the Unicode version (`unicode=17.0.0`),
  the JSON parser, and the image decoder with its exact build. It is bound
  into the table digests (§5), so a commitment always says which software
  produced it.

Rules (MUST):

1. **Conformance vectors.** No profile version may be used in a header until
   its conformance vectors are published in `verifiers/test_vectors/`. These
   are inputs paired with their expected output bytes *or* expected
   rejection, and must include every rejection rule. A new
   `implementation_id` for an existing profile version is acceptable only if
   it reproduces every vector byte for byte. If it does not, the
   implementation is defective. The profile is not redefined.
2. **Pinned Unicode.** A profile that normalizes or classifies text names its
   Unicode version in its definition, not only in `implementation_id`. An
   implementation built against a different Unicode version does not
   conform, even if it happens to pass the vectors.
3. **Platform independence.** Output must not depend on locale, time zone,
   OS line endings, filesystem path encoding, thread count, hash-map
   iteration order, or floating-point arithmetic. Path-like fields (tar
   member names, file paths within the dataset) are taken as stored bytes,
   and rejected if they are not valid UTF-8. Parallel builds must produce the
   same roots as a single-threaded build, and the test suite checks this.
4. **Parameter serialization.** Parameters are UTF-8 strings. Integers are
   written in decimal with no sign or leading zeros. JSON Pointers are
   written exactly in RFC 6901 form. Names are sorted by byte value and
   appear once, and an absent optional parameter is omitted (§5).
5. **Rejection is behaviour.** Changing what is rejected, or what is
   repaired instead of rejected, changes the profile version. Silent repair
   is never allowed (§1).

### 1. Canonical dataset-item bytes

A canonicalization profile maps raw bytes to canonical bytes, or **rejects**
them. A rejected item is never silently repaired: it is excluded from the
version and counted in the header's `rejected_count`. Each profile pins its
implementation. A decoder change, such as a different JPEG IDCT, is a new
`profile_version`, because the canonical bytes would differ.

v1 profiles:

| `profile_id` | v | Canonical bytes |
|---|---|---|
| `bytes/raw` | 1 | The raw bytes, unchanged. |
| `text/utf8-nfc` | 1 | Reject invalid UTF-8. Strip one leading U+FEFF. Convert CRLF and lone CR to LF. Apply Unicode 17.0.0 NFC. No trimming, case change or whitespace collapsing. |
| `image/rgba8` | 1 | Decode with the pinned decoder. Reject multi-frame images. Apply EXIF orientation. Convert to 8-bit sRGB RGBA (opaque if there is no alpha). Discard all metadata. Bytes = `"RGBA8\0" ‖ u32_be(width) ‖ u32_be(height) ‖ pixels, row-major, top-to-bottom`. |

Exact matching is defined only over canonical bytes. Two items are the "same"
exactly when one profile produces identical canonical bytes for both. Any
looser notion belongs to §1a and §9–10.

### 1a. Fingerprints (the near-duplicate layer)

A fingerprint profile emits zero or more **segment fingerprints** per item.
Using segments rather than one fingerprint per item is what catches an excerpt
inside a larger item, such as a book chapter embedded in a crawled page.

| `fp_profile_id` | v | Fingerprint | Distance | Default threshold |
|---|---|---|---|---|
| `text/minhash-120` | 1 | 120 × u32 MinHash per segment | matching slots `m` (Jaccard ≈ m/120) | `m ≥ 84` (J ≈ 0.7) |
| `image/pdq-256` | 1 | 256-bit PDQ hash, one segment | Hamming | `≤ 31` |

`text/minhash-120` v1:

- Normalize with Unicode 17.0.0 NFKC, then full case folding (same version). Replace every maximal
  run of characters outside Unicode categories L* and N* with one U+0020,
  then trim.
- Split into tokens on U+0020. Segments are windows of 256 tokens with stride
  128. An item shorter than 256 tokens is one segment. An item with fewer than
  5 tokens gets no fingerprint.
- Shingles are each run of 5 consecutive tokens, joined with U+0020. Each
  shingle maps to
  `x = u64_be(BLAKE3.derive_key("olympus 2026-11 dataset minhash-shingle v1", shingle)[0..8]) mod (2^61−1)`.
- Slot `i ∈ [0,120)` holds the minimum over the segment's shingles of
  `((a_i·x + b_i) mod (2^61−1)) mod 2^32`. The coefficients `(a_i, b_i)` are
  read in order from the BLAKE3 XOF of
  `derive_key("olympus 2026-11 dataset minhash-coefficients v1", "")`, as
  u64 values reduced mod `2^61−1`, with `a_i ≠ 0` (skip zeros).
- The fingerprint is the 120 slots in order, each `u32_be` (480 bytes).

`image/pdq-256` v1 is the reference PDQ algorithm, with the implementation
pinned by the profile. Items whose PDQ quality score is below 50 get **no**
fingerprint, because flat or near-blank images cluster and would flood the
buckets. The fingerprint is 32 bytes, MSB first. The committer stores only
the PDQ hash of the canonical orientation. A *querier* SHOULD compute the
eight dihedral variants (rotations and mirror images) of their image's hash,
which PDQ derives cheaply from one DCT, and query each one, because mirroring
is a common transformation that PDQ does not absorb.

An item with no fingerprint is still committed exactly. The header counts
these items (`unfingerprinted_count`) so that a verifier can see how much of
the dataset falls outside near-duplicate coverage.

### 2. Dataset-item commitment

```text
content_digest  = BLAKE3(canonical_bytes)                        -- plain, unkeyed: any BLAKE3 tool reproduces it
fp_leaf_j       = H_fp(u16_be(fp_profile_index) ‖ u32_be(segment_index) ‖ fingerprint_bytes)
fp_set_root     = binary Merkle over fp_leaf_j in (fp_profile_index, segment_index) order,
                  internal node H_fpnode(left ‖ right), odd node promoted unchanged,
                  empty set = H_fp("")                           -- never equal to a 1-element root
meta_entry      = blinding ‖ u16_be(extraction_index) ‖ lp(source_uri) ‖ lp(license) ‖
                  u64_be(retrieved_at_unix_s) ‖ u8(opt_out_status)
                                                                 -- blinding: 32 bytes from a CSPRNG (lifecycle below)
meta_leaf       = H_meta(meta_entry)
meta_root       = binary Merkle over the n = occurrence_count meta_leaf values, at positions
                  j = 0 .. n−1 in strictly ascending blinding order,
                  internal node H_metanode(left ‖ right), odd node promoted unchanged,
                  empty set = H_meta("")                         -- never equal to a 1-element root
item_commitment = H_item(u16_be(profile_index) ‖ u64_be(len(canonical_bytes)) ‖ content_digest ‖
                         fp_set_root ‖ u64_be(occurrence_count) ‖ meta_root)
```

`profile_index`, `fp_profile_index` and `extraction_index` index the tables
in the header. Those tables are bound into the global root (§5), so an index
cannot be reinterpreted. The commitment preimage has a fixed width of 114
bytes (two BLAKE3 compressions) and needs no framing.

**Duplicates.** Every occurrence whose canonical bytes are identical under
one canonicalization profile has the same `content_key` (§3), and so becomes
**one** leaf. The builder merges them: `occurrence_count ≥ 1` is the number
of merged occurrences, and their fingerprints are identical by construction
because fingerprints are computed from the canonical item. The count is
committed because repetition matters. A work that appears ten thousand times
is far more likely to be memorized than one that appears once. `item_count`
in §5 counts leaves; the header's `occurrence_total` (§6) is the sum of every
leaf's `occurrence_count`.

**Provenance metadata.** `meta_root` commits per-occurrence provenance: the
source URI, the license string as found, the retrieval time, and an
opt-out status (`0` none recorded, `1` opted out, `2` opted in; other
values are invalid). The metadata set is either empty or has exactly
`occurrence_count` entries. A builder MUST NOT commit a partial set, because
a partial set would let a committer keep a damaging source URI out of view
while appearing to disclose provenance. Strings are NFC; an absent value is
the empty string, which is allowed here as the one exception to the
non-empty rule. Occurrences with identical provenance are kept as separate
entries, not merged, so that `len(meta set) = occurrence_count` holds. They
never collide, because their blinders differ.

*Ordering and position.* An entry's position `j` is its rank by `blinding`.
Blinders are unique within an item (see lifecycle below), so the order is
strict and needs no tie-break. The sidecar stores each item's entries in
that order, and a disclosure names `j`. Ordering by a random value is
deliberate. Position then reveals nothing about extraction order, source
file or extraction group, which ordering by any metadata field would leak.
A verifier folds a metadata path using `n = occurrence_count` from the
item commitment. The path's shape, meaning which levels have a sibling and
on which side, is computed from `(j, n)`, never taken from the proof.

*Completeness.* No single proof can show that the set is complete. A
committer could have built `meta_root` over fewer than `occurrence_count`
entries, and a disclosure of one entry would not reveal that. A full rebuild
or a sampled audit (Security §2–3) checks completeness, and is **required**
before anyone may rely on the absence of an undisclosed source.

*Blinder lifecycle (MUST).*

1. **Generate before building.** Each item's blinders come from a CSPRNG
   when the item's metadata set is first assembled, before `meta_root` is
   computed. They are never derived from entry content, the item, or a
   seed that is reused.
2. **Unique.** No two entries anywhere in a dataset version share a
   blinder. The builder checks this, and the audit rebuild checks it again.
3. **Persist atomically.** Blinders are written to the sidecar in the same
   atomic step that records the version's roots. A builder MUST NOT publish
   or ledger-commit a header whose blinders are not already durably stored.
4. **Never regenerate.** A blinder is fixed once the header is signed. A
   rebuild for audit reads blinders from the sidecar. It never draws new
   ones, because that would produce a different `meta_root`.
5. **Secret witness material.** Blinders are as confidential as the entries
   they hide, and are released only by disclosing their entry (MD1) or under
   the auditor level.
6. **Loss is not invalidity.** Losing a blinder makes disclosure of that
   entry impossible for ever. It does not change or invalidate `meta_root`,
   the item commitment or any other proof, because all of those are already
   fixed.

`opt_out_status = 1` on a committed item is not a violation of this format.
It is a signed record, included in the ledger, that the committer's *own records*
marked the source as opted out when it included the item. It is not proof
that a valid opt-out request was made (§Guarantee classes, class C).

**Metadata privacy.** Source URIs, license strings and retrieval times can
contain personal data, embedded credentials (`https://user:token@…`),
private hostnames, or reveal how a corpus was collected. The format treats
them as confidential by default:

- **Committed, not published.** Only `meta_root` enters the commitment. The
  entries live in the committer's sidecar. Neither the header nor the
  ledger contains any of them.
- **Blinded leaves.** Each entry carries a 32-byte random `blinding`.
  Without it, a disclosed `meta_root` path would hand out its sibling leaf
  hashes, and anyone could confirm a guessed URI for another occurrence by
  hashing candidates. With it, a sibling hash reveals nothing about its
  entry (lifecycle above).
- **Disclosure levels.** The committer chooses per request:
  (a) none, which is M1 or M1-open without metadata;
  (b) *selective*, where one entry is opened through MD1 (§10), and other
  entries stay hidden;
  (c) *auditor*, where the full sidecar for a sampled or complete set of
  items is given to an auditor under the audit terms (§Unresolved 4).
  Publishing everything is not a level this format defines.
- **Sanitize before committing.** Every v1 extraction profile applies the
  fixed policy `uri-sanitize/1` (below) to `source_uri`. The policy is part
  of the extraction profile's definition, so it is bound through
  `extraction_version` and covered by the conformance vectors (§0a). Changing
  it is a new extraction version, never a builder setting. Once committed, a
  value can never be changed: the ledger is insert-only, and changing it
  would change every root above it.

`uri-sanitize/1`:

1. If the value parses as an absolute URI under RFC 3986 (a scheme
   followed by `:`), then:
   - remove the userinfo subcomponent together with its trailing `@`;
   - remove every query parameter whose name, after percent-decoding and
     ASCII lowercasing, is in the fixed list below. Parameters are split on
     `&`, and a name is the part before the first `=`;
   - drop the `?` if no parameters remain.
   Everything else is kept byte for byte. That includes the order and
   spelling of the remaining parameters and the fragment. Nothing is
   re-encoded or case-normalized.
2. Otherwise the value is kept as stored. Relative dataset paths, such as
   those from `file/whole`, are not URIs.
3. Fixed list: `access_token`, `api_key`, `apikey`, `auth`, `auth_token`,
   `client_secret`, `code`, `credential`, `jwt`, `key`, `passwd`,
   `password`, `pwd`, `secret`, `session`, `session_id`, `sessionid`, `sig`,
   `signature`, `token`, `x-amz-credential`, `x-amz-security-token`,
   `x-amz-signature`, `x-goog-credential`, `x-goog-signature`.

The policy is a floor, not a guarantee that no secret survives. Secrets in
a path segment or under an unlisted parameter name pass through. A
committer with such sources must remove them before extraction, or leave
the URI out of the metadata.

### 3. SMT key — sorted by construction

```text
content_key = BLAKE3.derive_key("olympus 2026-11 dataset content-key v1",
                                lp(profile_id) ‖ u32_be(profile_version) ‖ content_digest)
```

The key depends only on the canonicalization profile and the content. It
does **not** depend on the dataset, the version or the committer, so a rights
holder computes it once from their own copy and can query any dataset
version that lists the profile. Unlike the ledger's 192-bit key suffix, all
256 bits are used, which keeps quantum (BHT) collision resistance near 2^85.

The tree is a keyed sparse Merkle tree: an item's position is determined by
the bits of its key, so an in-order traversal is sorted by key. Nobody has to
prove that the tree is sorted, and nobody has to prove it is full. This
removes the external sortedness and fullness preconditions in the
prototype's boundary modes (prototype item 5). Non-membership never needs
neighbouring items.

### 4. Leaf and node encodings (`olympus-dataset-tree/v1`)

This is a hoisted (path-compressed) sparse Merkle tree over 256-bit keys:

```text
E                = H_empty("")                                   -- empty subtree, every height
leaf(k, c)       = H_leaf(k ‖ c)                                 -- k = content_key, c = item_commitment; 64 bytes
node(l, r)       = H_node(l ‖ r)                                 -- 64 bytes
subtree(S, pfx)  = E               if S empty
                 = leaf(k, c)      if S = {(k, c)}                 -- hoisted to the highest level where it is alone
                 = node(subtree(S0, pfx‖0), subtree(S1, pfx‖1))   otherwise
```

Each `leaf` and `node` hash is exactly **one** BLAKE3 compression, because a
64-byte keyed-hash input is a single block. That is why `keyed_hash` is used
here instead of the ASCII-prefix framing (`OLY:NODE:V1|`), which costs two
compressions. In-circuit cost per level is the dominant term (§8).

Verifier rules (MUST):

- **Prefix check.** A terminal `leaf(k, c)` reached at depth `d` along path
  bits `b_0..b_{d−1}` is accepted only if the first `d` bits of `k` equal
  `b_0..b_{d−1}`. Without this check a key could appear at two positions with
  different commitments.
- **Canonical shape, where visible.** Reject a proof whose terminal is a
  leaf, or is `E`, when the sibling at the deepest level is `E`. In both
  cases the subtree should have been hoisted or collapsed. Other
  non-canonical shapes, such as a terminal `E` beside a lone leaf, cannot be
  seen in a single path, because a sibling hash does not reveal whether it
  is a leaf or a node. They do not affect soundness: each position holds
  exactly one value, so the prefix check alone makes membership and
  non-membership sound. They break determinism, and the auditor's full
  rebuild (Security §2) detects that. Builders MUST emit the canonical tree.
- **Depth.** Accept `0 ≤ d ≤ 256 − p` below the partition root.

The similarity index (§9) uses the same tree with its own domains
(`H_sleaf`, `H_snode`, `E_s`) so that an item proof and an index proof can
never be swapped.

### 5. Shard (partition) and global root encodings

A version has `2^p` partitions, `0 ≤ p ≤ 16`. Partition `i` holds the items
whose content-key first `p` bits equal `i`. Hoisting stops at the partition
boundary.

```text
partition_root_i = H_part(u8(p) ‖ u32_be(i) ‖ u64_be(item_count_i) ‖ subtree_i)
top_root         = full binary Merkle over partition_root_0 .. partition_root_{2^p−1},
                   node H_top(left ‖ right); p = 0 ⇒ top_root = partition_root_0
item_root        = top_root
global_root      = H_global(
                     lp("olympus-dataset-tree/v1") ‖ lp(dataset_id) ‖ u64_be(version) ‖
                     u8(p) ‖ u64_be(item_count) ‖ u64_be(occurrence_total) ‖
                     extraction_table_digest ‖ profile_table_digest ‖ fp_profile_table_digest ‖
                     item_root ‖ similarity_root )
```

`profile_table_digest` is `H_ptable(u16_be(n) ‖ for each entry: lp(profile_id) ‖ u32_be(profile_version) ‖ lp(implementation_id))`,
and `fp_profile_table_digest` is the same construction under `H_fptable`,
whose entries append `u16_be(b) ‖ u16_be(r) ‖ u32_be(threshold)` after `lp(implementation_id)` (the threshold in its profile's unit: matching slots for MinHash, Hamming distance for PDQ).
`extraction_table_digest` is `H_xtable(u16_be(n) ‖ for each entry: lp(extraction_id) ‖ u32_be(extraction_version) ‖ lp(implementation_id) ‖ u16_be(k) ‖ k × (lp(param_name) ‖ lp(param_value)))`,
with parameters sorted by name and each name appearing once. An unused
optional parameter is omitted, not written as an empty value. Partition
roots carry per-partition counts, so partition sizes are committed. The global
root binds the dataset ID, version, every profile and every parameter. Any
proof checked against a `global_root` is therefore also checked against those
values. A proof for version 3 cannot be replayed against version 4, and a
proof under one canonicalization cannot be replayed under another.

### 6. Header payload (`olympus-dataset-header/v1`)

The authoritative form is binary, so no JSON canonicalizer sits in the trust
path. A JSON rendering is display-only, and it MUST round-trip to these bytes.

```text
header = lp("olympus-dataset-header/v1") ‖
         lp(ledger_shard_id) ‖ lp(dataset_id) ‖ u64_be(version) ‖
         lp(parent_header_digest)            -- 0 bytes for the first version, else 32
         u64_be(created_at_unix_s) ‖
         lp(parser_id) ‖ lp(canonical_parser_version) ‖ lp(model_hash) ‖   -- ADR-0003/0004 provenance
         extraction_table ‖ profile_table ‖ fp_profile_table ‖              -- the exact preimages of §5's digests
         u8(p) ‖ u64_be(item_count) ‖ u64_be(occurrence_total) ‖
         u64_be(rejected_count) ‖ u64_be(unfingerprinted_count) ‖
         global_root ‖ item_root ‖ similarity_root ‖
         lp(suite) ‖                                                        -- ADR-0035 suite wire name (§7)
         lp(ed25519_key_id) ‖ lp(ml_dsa_65_key_id)                          -- ML-DSA key ID is 0 bytes for suite "ed25519"
header_digest = H_header(header)
```

The verifier MUST recompute `global_root` from the header fields and the two
sub-roots, and reject the header on mismatch. The header carries partition
roots only by reference: a sidecar lists all `2^p` of them, and each one is
checked against `item_root`.

**Ledger binding.** The signed header bundle (`header ‖ envelope`, §7) is
committed through `POST /ingest/files` into `ledger_shard_id`. The resulting
ledger leaf binds `ledger_shard_id` via ADR-0005 and the bundle's BLAKE3
content hash as `value_hash`. It is covered by the shard's
`SmtRootAttestation` and the checkpoint `TransitionAttestation`. That gives
the version an append-only **inclusion position** in the shard. The
attestations bind roots and sizes, not times. A time exists only through a
checkpoint that signs one: a V2 ledger snapshot signs `signed_at_unix`, and a
V1 snapshot signs no time at all. Verification establishes only that the
checkpoint authority signed that value. It is a wall-clock bound only to the
extent that the authority's clock and honesty are trusted. Under that trust,
inclusion shows that the bundle existed no later than the `signed_at_unix` of
the first V2 checkpoint covering it. Without it, inclusion gives order, not
time.

`created_at_unix_s` is a value the committer chose. It is signed, but no rule
in this RFC compares it with an authenticated time, and no verifier reads
it. It is therefore display metadata and MUST NOT be presented as a
timestamp. A backdated `created_at_unix_s` is not detectable by this format.
What the format does make visible is a header *re-signed later over an
earlier version*: it appears after the original in inclusion order.
Relating `created_at_unix_s` to checkpoint time is left open
(§Unresolved 10). `parent_header_digest` chains versions; a fork appears as
two headers naming the same parent.

### 7. Signed-message envelope

The header uses the existing `SignatureEnvelopeV3` (ADR-0035) unchanged. The
suite is a header field, so it is covered by `header_digest`:

| Header `suite` | Envelope suite | Verification mode | Status |
|---|---|---|---|
| `ed25519` | `ed25519` | `ClassicalRequired` | available now; the v1 launch suite |
| `hybrid-ed25519-ml-dsa-65` | `hybrid-ed25519-ml-dsa-65` | `HybridRequired`: both legs must verify | blocked until an ML-DSA-65 implementation is accepted and audited (prototype item 6) |

Both cases use domain separator `OLY:DATASET:HEADER:V1` and payload digest
`header_digest` (32 bytes).

Verifier rules (MUST):

- The envelope's suite equals the header's `suite`. Otherwise reject.
- For `ed25519`, `ml_dsa_65_key_id` is empty. For the hybrid suite, both key
  IDs are non-empty.
- A hybrid-declared header is verified only with `HybridRequired`. There is
  no Ed25519-only fallback for it, and today such a header fails closed with
  `UnsupportedAlgorithm(MlDsa65)`.
- Keys are resolved from the authenticated key directory by the key IDs in
  the header, never inferred from signature length.

**Why this is not a downgrade path.** ADR-0035 binds the suite name and the
algorithm list into the signed message, and the header binds the suite a
second time. Neither the suite of an existing header nor the leg set of a
hybrid envelope can be changed without invalidating the Ed25519 signature. What
the `ed25519` suite does *not* give is post-quantum strength. An adversary
who can forge Ed25519 could sign a *new* `ed25519` header. Two things limit
that. Every honest header already has a position in the insert-only ledger
(§6), so a forged header cannot take an *earlier inclusion position* than
the real one. That is the whole of the protection: it is about ledger
inclusion order, and it says nothing about the `created_at_unix_s` either
header claims. And a relying party sets its own minimum suite, and SHOULD require
the hybrid suite for any version created after hybrid signing becomes
available. Committers SHOULD re-sign their live versions under the hybrid
suite once it ships. A re-signed header is a new header over the same
`global_root`, and old proofs stay valid against it.

### 8. Ligetron public/private input boundary

All four statements share these rules:

- **Public:** the `global_root` fields needed to recompute it in-circuit
  (`dataset_id`, `version`, `p`, `item_count`, `occurrence_total`, the three
  table digests, and the sub-root not being opened), plus the query. The verifier checks
  the signed header outside the circuit and takes these values from it.
- **Private:** paths, terminals, commitments, fingerprints of committed
  items and bucket contents.
- Byte-length checks use the argument layout (`args_len_get`), as in the
  prototype's `doc.cpp`. A shape violation fails a constraint and returns
  before any fixed-size buffer is read.
- No item bytes enter any circuit.

Estimated BLAKE3 compressions per statement, for `N` items and `2^p`
partitions. The path below a partition root has expected depth about
`log2 N − p + 1` for random keys. Above it sit one partition-root hash and
`p` top-tree levels, so the partition count cancels out. The leaf costs 1,
`item_commitment` 2 (114 bytes) and `global_root` about 4 (about 250 bytes,
depending on `dataset_id`):

| Statement | Compressions (≈) | Notes |
|---|---|---|
| exact membership / non-membership | `log2 N + 9` | path, partition, top tree, leaf, item commitment, global root |
| similar membership | `log2 N + log2 S + 9 + ⌈L_fp / 64⌉` | `S` = the item's segment count; `L_fp` = fingerprint-leaf preimage, 486 B text / 38 B image |
| similar non-membership | `b · (log2 N' + 2) + ⌈Σ bucket bytes / 64⌉ + 4` | `b` bands; `N'` = distinct band keys; bucket entry 518 B text / 70 B image |

Worked figures at `N = 10^9`, using a conservative 1.5 s per compression on
software Vulkan (the upper end of prototype item 4's samples):

| Statement | Assumptions | Compressions | Time |
|---|---|---|---|
| exact (M1, N1) | — | ≈ 39 | ≈ 1 min |
| similar membership (M2), text | `S ≈ 4` | ≈ 49 | ≈ 1.2 min |
| similar non-membership (N2), text | about 4 segments per item, so `N' ≈ 20 · 4·10^9 ≈ 2^36`; buckets hold ≈ 1 entry | ≈ 20 · 38 + 20 · 9 + 4 ≈ 950 | ≈ 25 min |
| similar non-membership (N2), image | every 24-bit band value occupied, so `N' ≈ 64 · 2^24 = 2^30`; ≈ 60 entries per bucket (§9) | ≈ 64 · 32 + ⌈64 · 60 · 70 / 64⌉ + 4 ≈ 6,250 | ≈ **2.6 h** |

The image N2 figure is dominated by bucket contents, not paths, so it grows
linearly with dataset size, at roughly 4,200 compressions per 10^9 items.
These are **estimates** extrapolated from prototype measurements.
§Unresolved 1 requires measuring them.

### 9. Similarity index

For each fingerprint profile with `b` bands of `r` units:

```text
band_value(F, β) = text:  slots [β·r, (β+1)·r) of F, each u32_be                (r = 6, b = 20)
                   image: the r = 24 bits at positions perm_β[0..24) of F, MSB-first, zero-padded to 3 bytes
                          (perm_β drawn without replacement per band from the BLAKE3 XOF of
                           derive_key("olympus 2026-11 dataset pdq-bands v1", ""); bands may overlap; b = 64)
band_key(F, β)   = BLAKE3.derive_key("olympus 2026-11 dataset band-key v1",
                                     lp(fp_profile_id) ‖ u32_be(fp_profile_version) ‖ u16_be(β) ‖ band_value(F, β))
bucket(key)      = all (content_key, fp_profile_index, segment_index, fingerprint) whose band_key = key,
                   sorted by (content_key, fp_profile_index, segment_index); no duplicates
bucket_commit    = H_bucket(u32_be(count) ‖ for each entry: content_key ‖ u16_be(fp_profile_index) ‖ u32_be(segment_index) ‖ fingerprint)
similarity_root  = olympus-dataset-tree/v1 over (band_key → bucket_commit), with the s-domains (§4), no partitions
```

Detection probability for a near-duplicate is the chance that it shares at
least one band with the query:

| text, b=20 r=6: Jaccard | 0.5 | 0.6 | 0.7 | 0.8 | 0.9 |
|---|---|---|---|---|---|
| P(detected) | 0.27 | 0.62 | 0.92 | 0.998 | > 0.9999997 |

| image, b=64 r=24: Hamming distance | 10 | 20 | 31 |
|---|---|---|---|
| P(detected) | ≈ 1 | 0.9999 | 0.92 |

These probabilities are taken over the content. They assume independent
MinHash slots, and uniformly distributed PDQ bits with each band's 24
positions sampled without replacement. With about 10^9 random-looking fingerprints, an unrelated item lands
in a given image bucket about `10^9 / 2^24 ≈ 60` times. Text buckets are
near-empty unless documents share boilerplate.

### 10. Proof statements

Below, *"opens to R"* means that the path folds, under §4–5's rules
including the prefix and canonical-shape checks, to root `R`.

**M1 — exact membership.** Public: global-root fields, `content_key`,
`profile_index`. Private: partition path, `item_commitment` preimage (minus
the content digest when hidden). Statement: `leaf(content_key, c)` opens to
`item_root`, and `c` commits `profile_index`. Variant M1-open makes
`content_digest`, `fp_set_root`, `occurrence_count` and `meta_root` public,
so a claimant can check the committed fingerprints against their own copy and
learn how often the work appears. Individual provenance entries are opened
only through MD1.

**MD1 — selective metadata disclosure.** There is no standalone metadata
path format. A metadata path on its own proves nothing about which item it
belongs to, so it could be transplanted from one item to another. MD1 is
always a composition, verified as a single object:

```text
MD1 = { header (verified, §6–7),
        content_key,
        M1-open for content_key          -- reveals item_commitment's preimage, incl. occurrence_count n and meta_root
        j, n,                            -- position and set size; n MUST equal the opened occurrence_count
        meta_entry_j,                    -- incl. its blinding
        meta_path_j }                    -- siblings only; shape derived from (j, n)
```

Verification: the header verifies. The M1-open path folds
`leaf(content_key, item_commitment)` to `item_root` and then to
`global_root`. `n` equals the opened `occurrence_count`, and `0 ≤ j < n`.
Then `H_meta(meta_entry_j)` folded along `meta_path_j`, with the shape
derived from `(j, n)`, equals the opened `meta_root`. Because `meta_root`
sits inside `item_commitment`, which sits under `content_key`, which sits
under a `global_root` that binds the dataset ID and version, an MD1 for one
item, version or dataset cannot be verified against another. The fields
are then validated. An `opt_out_status` outside {0, 1, 2}, or non-NFC
strings, are rejected. MD1 establishes a class C fact only: the committer
recorded this entry for one occurrence of this item.

**N1 — exact non-membership.** Public: global-root fields, `content_key`.
Private: the path along `content_key`'s bits. Statement: the path ends at
either (a) `E`, or (b) `leaf(k′, c′)` with `k′ ≠ content_key`, where `k′`
passes the prefix check; it opens to `item_root`. Because a position holds
exactly one value, (a) or (b) excludes `content_key` from the whole version.
No per-partition bundle is needed, because the partition is fixed by the
key's first `p` bits.

**M2 — similar membership.** Public: global-root fields, `fp_profile_index`,
query fingerprint `F_q`, threshold `τ`. Private: one item's leaf, path,
commitment, and one segment fingerprint `F` with its `fp_set_root` path.
Statement: the item opens to `item_root`, `F` is in its `fp_set_root`, and
`distance(F, F_q)` satisfies `τ` (matching slots `≥ τ`, or Hamming `≤ τ`).
This reveals that a close item exists, and nothing about which item it is.

**N2 — similar non-membership.** Public: global-root fields,
`fp_profile_index`, `F_q`, `τ`, and the `b` band keys of `F_q`. The verifier
recomputes the band keys from `F_q`, so they are not derived in-circuit.
Private: per band, a path in the similarity tree and, if present, the
bucket. Statement: for each band key, either (a) it is absent (N1 shape over
`similarity_root`), or (b) its `bucket_commit` opens to `similarity_root`
and **every** entry's fingerprint fails `τ` against `F_q`. Meaning:
*no committed segment that shares any LSH band with the query is within
`τ`*. This is a deterministic fact about the committed index, and it is
all an N2 proof may be reported as: "no candidate under index". §9's
detection probabilities estimate how often a real near-duplicate would
still be missed, assuming random-looking fingerprints and an honest,
complete index. They are a measured property of the fingerprint method,
not part of what the proof establishes (§Guarantee classes). **Not in v1.**

**D1 — removal between versions.** Public: two verified headers `h_old`
and `h_new` and `content_key`. Statement: M1 against `h_old`'s `item_root`
and N1 against `h_new`'s `item_root`, under the same canonicalization
profile. D1 establishes a class A fact: the canonical work was in the
committed old version and is in no position of the committed new one.
Together with a verified header chain (below), it is *evidence* that an
opt-out or takedown was reflected in the committed dataset. It is not proof
that the request was honoured in any wider sense. It says nothing about
copies that differ in canonical bytes (showing those removed would need N2,
which is outside v1), about other datasets
or versions outside the chain, or about models already trained (trust
assumption 5). **D2 —
addition** is the reverse (N1 old, M1 new). Neither needs a new primitive.
The verifier also checks the header chain: `h_new` must reach `h_old`
through `parent_header_digest` links. A committer could still answer a
removal request with a fork, a sibling version that drops the work while the
version actually used for training keeps it. Every header is in the
insert-only ledger, though, and a fork shows there as two headers naming the
same parent (§6). So a relying party also checks, from the ledger shard,
that each header on the chain is the only child of its parent, and treats a
fork as a finding in its own right. A *near-duplicate* removal is the same pairing
with M2 and N2.

The chain says that versions follow each other. It does not say which items
changed. A committer MAY publish a diff commitment beside the header, using
ADR-0027's construction under its own domain:
`diff_root = H_diff(u64_be(removed) ‖ u64_be(added) ‖ sorted (u8(op) ‖ content_key) entries)`,
with `op` = 0 for removed and 1 for added. That lets an auditor check the
diff against both trees in one pass. It is optional because D1 and D2 do
not depend on it.

A long work, such as a book, is queried per segment. A whole-work claim is a
bundle of per-segment proofs against one `global_root`: a few hundred plain
proofs, which is cheap, or the same number of zero-knowledge proofs, which
is expensive (§Drawbacks).

### 11. Domain-separation rules

- Each key is
  `K_name = BLAKE3.derive_key("olympus 2026-11 dataset <name> v1", "")`, and
  each derived identifier uses its own context string. Context strings are
  globally unique, never reused across object types, and never reused
  across versions.
- Contexts: `empty`, `leaf`, `node`, `s-empty`, `s-leaf`, `s-node`, `part`,
  `top`, `global`, `item`, `fp`, `fpnode`, `meta`, `metanode`, `bucket`,
  `xtable`, `ptable`, `fptable`, `header`, `diff`. Derived identifiers: `content-key`, `band-key`,
  `minhash-shingle`, `minhash-coefficients`, `pdq-bands`.
- These keys are disjoint from every existing Olympus domain (`OLY:NODE:V1`,
  the ADR-0005 leaf prefix, `OLY:EMPTY-LEAF:V1`, …), because BLAKE3
  `derive_key` contexts and keyed-hash keys live in separate input spaces
  from plain-hash prefixes. Nothing here changes a ledger hash.
- Signed objects use the ADR-0035 domain separator `OLY:DATASET:HEADER:V1`.
- **Versioning.** Every format carries a `/vN` string, either in the
  preimage or in the context. A verifier dispatches on that string, rejects
  unknown versions, and never falls back. A new layout means a new context
  string, and old versions stay verifiable forever under their own contexts.

### 12. Exact binding of shard, dataset, version and canonicalization

| Bound value | Where it is bound | What a substitution breaks |
|---|---|---|
| ledger shard | header field + ADR-0005 ledger leaf | header digest, ledger leaf |
| partition | `partition_root` (`p`, index, count); key prefix check | partition root, path fold |
| dataset ID | `global_root`, header | global root, header signature |
| version | `global_root`, header, parent chain | global root, signature, chain |
| extraction | `extraction_table_digest` in `global_root`; `extraction_index` in each metadata entry | global root, metadata leaf |
| multiplicity | `occurrence_count` in `item_commitment`; `occurrence_total` in `global_root` | item commitment, global root |
| per-occurrence provenance | `meta_root` in `item_commitment` | metadata leaf, item commitment |
| signature suite | header `suite` field; ADR-0035 signed message | header digest, signature |
| canonicalization | `content_key` (profile ID and version), `item_commitment` (profile index), profile table digest in `global_root` | key, commitment, global root |
| fingerprinting | `fp_leaf` (profile index), band key (profile ID and version), `fp_profile_table_digest` in `global_root` | fingerprint leaf, band key, global root |
| provenance | header (`parser_id`, `canonical_parser_version`, `model_hash`) | header signature |

### 13. Required vectors

The shared vector file (`verifiers/test_vectors/`) MUST include, besides
positive cases and the per-profile conformance vectors (§0a), the negative
cases below. Every negative case names the rule it violates, and an
implementation passes only if it rejects *for that reason*, not merely
rejects. Each case also says which party performs the check, because some
cannot be seen in a single proof.

| Case | Mutation | Expected rejection | Checked by |
|---|---|---|---|
| wrong blinder | MD1 with one byte of `blinding` flipped | metadata path does not fold to `meta_root` | every verifier |
| swapped entry | MD1 opening entry `j′` at position `j` | path shape from `(j, n)` does not fold | every verifier |
| entry from another item | a valid `(meta_entry, meta_path)` of item B presented in an MD1 for item A | does not fold to A's opened `meta_root` | every verifier |
| wrong set size | MD1 with `n ≠` opened `occurrence_count` | `n` mismatch | every verifier |
| out-of-range position | `j ≥ n` | position out of range | every verifier |
| invalid field | `opt_out_status = 3`; non-NFC `source_uri` | field validation | every verifier |
| guessed URI | a valid MD1 for entry `j`, plus a sibling leaf whose entry's URI the tester guesses correctly, but without its blinder | the guessed entry's hash does **not** equal the sibling hash. This is a positive test of hiding: it must fail to confirm the guess. | test suite |
| reused blinder | a dataset version in which two entries share a blinder | duplicate blinder | builder, audit rebuild |
| incomplete set | `meta_root` built over `n′ < occurrence_count` entries | set size ≠ `occurrence_count` | audit rebuild |
| sanitization | a URI carrying userinfo and each listed parameter, with mixed case and percent-encoding | output equals the vector byte for byte | builder conformance |
| item/version transplant | an M1 or N1 proof verified against a header with a different `dataset_id`, `version` or profile table | `global_root` mismatch | every verifier |
| prefix check, canonical shape, depth | §4's three rules, each violated once | the specific rule | every verifier |

## Security & invariant impact

No change to any ledger leaf, node, key, checkpoint, circuit or ceremony. The
dataset tree is a separate, client-built structure, as in ADR-0027. The only
ledger touchpoint is an ordinary file ingest. Signatures reuse
`SignatureEnvelopeV3` without modification.

**What a verifier must still trust.** These limits are part of what the
format means, and are not bugs to be fixed later:

1. **Honest fingerprints.** Proofs show that committed fingerprints are, or
   are not, near the query. They do not show that a committed fingerprint
   was computed correctly from its item. A committer could store a wrong
   fingerprint for a work it holds. The defences are that a wrong
   fingerprint is *attributable* (it sits under a signed header and a
   ledger inclusion), that M1-open lets a holder of an exact copy check it,
   and that sampled audits (3 below) check it. Removing this trust needs
   in-circuit fingerprint recomputation from canonical bytes. That looks
   feasible for short text and is impractical for decoded images (§Unresolved 3).
   **Provenance metadata and occurrence counts are trusted the same way.**
   The format proves what the committer *stated* about sources, licenses,
   opt-out status and repetition, not that the statement is true. A false
   statement is signed, included in the ledger and attributable, and a sampled audit
   that re-runs extraction (§0) over the opened source files detects it.
2. **Complete index.** N2 shows absence only from `similarity_root`. The
   index is a deterministic function of the item set and its fingerprints,
   so an auditor holding the record index rebuilds both roots bit for bit,
   which the canonical-shape rule makes possible. Nobody else can check
   completeness.
3. **Sampled audits.** An auditor picks `k` random content keys or positions
   from the published partition roots. The committer must open those items,
   meaning canonical bytes and an M1-open proof, so their fingerprints and
   bucket entries can be checked. Undetected cheating on a fraction `f` of
   items survives with probability `(1 − f)^k`.
4. **Ordinary transformations only.** LSH guarantees cover re-encoding,
   resizing, formatting and light edits. A committer who deliberately alters
   works to evade public, fixed fingerprint functions will succeed. No
   hash-based scheme prevents that. It is misconduct the signed record
   makes attributable after the fact.
5. **Commitment, not training.** A signed root identifies which dataset
   version was committed. It does not by itself say when. Timing comes only
   from ledger inclusion order and, for V2 checkpoints, a signed time that is
   as reliable as the checkpoint authority's clock (§6). Nor does it prove a
   model was trained on exactly that set.

**Query exposure.** Content keys are deterministic and independent of the
dataset, which is what lets a rights holder compute one. The same property
makes every answer an oracle. Anyone who can obtain an M1 or N1 answer for
an arbitrary work learns whether the dataset contains it. That can reveal
confidential contents, collection strategy, or the use of sensitive
material. Even a non-membership proof gives away information: a plain N1
proof discloses one neighbouring `content_key`, which a holder of that work
can recognize. This RFC defines proofs, not a query service, and treats
exposure as follows:

- **Proofs are produced by the committer.** The committer alone holds the
  record index. No Olympus node answers content queries for a dataset it
  did not build, and the ledger holds only the header.
- **A query service is a deployment decision**, and is expected to
  authenticate requesters, rate-limit them, and log queries. A committer may
  instead distribute proofs for a list of works, such as a rights holder's
  catalogue, without running any interactive service.
- **Leaked neighbours.** Where a disclosed neighbouring key is itself
  sensitive, the committer answers with a zero-knowledge proof (once one
  exists) instead of a plain one. The salted-key mode (§Unresolved 5) would
  remove the oracle for outsiders entirely, at the cost of rights holders
  needing the committer's help to compute their key.
- **Refusal is not denial.** A committer that declines to answer has made no
  claim. A committer that answers must answer truthfully: the proof cannot
  lie, and the signed header cannot be swapped.

## Alternatives considered

- **Reuse ADR-0027 unchanged.** Its keys are chosen by the committer, so it
  cannot answer content questions. Its 256-level fixed-depth tree with
  ASCII-prefixed nodes costs about 512 compressions per in-circuit path,
  against about 39 for a whole exact statement here (§8). ADR-0027 stays the right tool for "is record ID X
  in the set?".
- **Sorted-leaf tree with adjacent-pair non-membership** (the prototype's
  modes 1–3). This needs proof of global sortedness and, at the boundaries,
  fullness. A keyed tree gets both by construction.
- **Poseidon in-circuit tree (prototype).** Cheaper per hash in a SNARK, but
  it would need a second tree beside the BLAKE3 one, and a proof that the two
  agree. Prototype measurements put an extra BLAKE3 compression at 0.4–1.6 s
  against about 1.2 s per Poseidon level (depth 8 → 20). That is close enough
  that one BLAKE3 tree wins. To be confirmed (§Unresolved 1).
- **Embedding-based semantic similarity.** It catches paraphrase and style,
  but thresholds are contestable, models change, and approximate
  nearest-neighbour indexes have no sound non-membership. Out of scope; it
  could be a separate profile later with weaker, clearly labelled claims.
- **Pigeonhole banding for deterministic image recall** (`τ+1` bands). At
  `τ = 31` the bands are 8 bits wide, so every bucket holds millions of items
  at 10^9 scale. Rejected.

## Drawbacks & risks

- Zero-knowledge similar-non-membership and whole-work bundles are slow on
  current hardware. The estimate is about 25 minutes per text segment proof
  and about 2.6 hours per image query at 10^9 items, and the image figure
  grows linearly with dataset size (§8). Plain proofs cover most uses.
  Zero-knowledge is for committers who must not reveal neighbouring items.
- v1 headers are signed with Ed25519 only, until ML-DSA-65 is accepted (§7).
  Their protection against a future quantum forger rests on ledger
  inclusion order and on re-signing under the hybrid suite, not on the signature
  itself.
- Per-occurrence metadata makes the record index larger: about 100–300
  bytes per occurrence, depending on URI length. It lives in the
  committer's sidecar, not in the header or the ledger.
- Plain proofs leak: an N1 proof shows a neighbouring `content_key`, and an
  N2 proof shows bucket contents, including other items' fingerprints.
  Anyone holding a candidate item can test it against leaked keys.
- Image canonicalization pins a decoder, so a decoder security fix forces a
  new profile version and a re-commit.
- New verifier surface: the Rust and JavaScript verifiers and the Python SDK
  each need the tree, header and statement checks, plus cross-language vectors.

## Unresolved questions

1. Measure in-circuit BLAKE3 path cost at depths 30–40, and the N2 cost at
   `b = 20` and `b = 64`, ideally on real GPU hardware (prototype item 3),
   before accepting the zero-knowledge half.
2. Whether the default thresholds (`m ≥ 84`, Hamming `≤ 31`) and band
   parameters fit real corpora. They need false-positive and recall
   measurements on labelled near-duplicate sets.
3. Whether to require in-circuit MinHash recomputation for short text items,
   which would remove trust assumption 1 for text.
4. Sampled-audit protocol details: who chooses the sample, which randomness
   beacon, and the response deadline.
5. An optional salted-key mode that keeps outsiders from testing guessed
   items against leaked keys, with the salt committed and the key derivation
   proven in-circuit.
6. More profiles: audio (Chromaprint-style), source code (winnowing), and
   cropped-image robustness (PDQ is weak against crops).
7. Reducing image N2 cost, which is dominated by bucket contents (§8).
   Options include wider bands (`r > 24`) with more of them, or committing a
   per-bucket sub-tree so that a proof opens only the entries it has to rule
   out. Each option changes the detection-probability table in §9 and needs
   re-deriving.
8. Whether `license` should be normalized to an SPDX expression where one
   applies, with the raw string kept alongside, so licenses can be compared
   across datasets. v1 commits the string as found.
9. Extraction profiles beyond v1: HuggingFace `datasets` Arrow shards,
   multi-field items (an image–caption pair as one item), and conversation
   formats.
10. Whether to add a verifier rule tying `created_at_unix_s` to an
    authenticated time, for example rejecting a header whose claimed time is
    later than the `signed_at_unix` of the first V2 checkpoint that includes
    it, or earlier than its parent's. Without such a rule the field is
    display metadata (§6).
