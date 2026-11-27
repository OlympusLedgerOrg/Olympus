# RFC-0000: Content-addressed dataset commitments

| Field | Value |
|---|---|
| Status | **Draft** |
| Author(s) | Olympus maintainers |
| Date | 2026-11-26 |
| Supersedes | None. Complements ADR-0027. |

## Summary

A rights holder can derive a content key from their copy of a work and verify
whether that exact canonical item appears in a signed dataset version. The
committer builds a BLAKE3 sparse Merkle tree. The verifier checks a compact
binary path against the signed header. One offline bundle can share the
header and ledger evidence across many answers.

ADR-0027 keys records by a committer-chosen record ID. This RFC keys items by
their content and canonicalization profile, so the claimant can compute the
key independently.

## Guarantee classes and scope

- **A — commitment.** M1-open and N1 establish exact membership and absence
  under a selected canonicalization profile. D1 and D2 compose these answers
  across versions. Ledger evidence establishes inclusion of the signed header.
- **B — candidate retrieval.** See the [similarity companion](dataset-similarity.md)
  for fingerprint profiles, plain M2, and the limits of approximate matching.
- **C — recorded statements.** MD1 proves what the committer recorded about
  one occurrence. Recorded provenance, licenses and opt-out state remain
  attributable statements. D1 is evidence of removal from the committed
  dataset only after the version chain check passes. It does not establish
  the absence of a fork (§10).

The core v1 profiles are `file/whole`, `jsonl/field`, `bytes/raw` and
`text/utf8-nfc`. Ed25519 is the launch signing suite. The hybrid suite needs
a separate implementation and review. The Rust implementation in
`olympus-manifest` is the only dataset verifier today. JavaScript and Python
dataset verifiers are planned. Before either is relied on, it MUST pass the
same vector files in `verifiers/test_vectors/` as the Rust verifier. Only the
compact exact-proof vectors (§13) are published so far. [Research notes](dataset-proof-research.md) track
additional profiles, private proofs and measurements.

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

Core v1 extraction profiles:

| `extraction_id` | v | Parameters | Items | Occurrence provenance |
|---|---|---|---|---|
| `file/whole` | 1 | none | Each file is one item. | `source_uri` = the file's path within the dataset |
| `jsonl/field` | 1 | `field` (a JSON Pointer, RFC 6901), `uri_field`, `license_field` (both optional pointers) | Each line is parsed as one JSON object. The item is the UTF-8 encoding of the string at `field`. A line that is not an object, or whose `field` is absent or not a string, is rejected. | values at `uri_field` / `license_field`, else empty |

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
  (Security and audit).
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
fingerprint (see the [similarity companion](dataset-similarity.md)), is defined by two separate things:

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
implementation. A change to the canonical bytes requires a new `profile_version`.

Core v1 profiles:

| `profile_id` | v | Canonical bytes |
|---|---|---|
| `bytes/raw` | 1 | The raw bytes, unchanged. |
| `text/utf8-nfc` | 1 | Reject invalid UTF-8. Strip one leading U+FEFF. Convert CRLF and lone CR to LF. Apply Unicode 17.0.0 NFC. No trimming, case change or whitespace collapsing. |

Exact matching is defined only over canonical bytes. Two items are the "same"
exactly when one profile produces identical canonical bytes for both. Any
looser notion belongs to the [similarity companion](dataset-similarity.md).


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
because fingerprints are computed from the canonical item when enabled.
Exact-only versions use an empty fingerprint table, `H_fp("")` for each
item's fingerprint root, and `H_s-empty("")` for the similarity root.
`item_count` in §5 counts leaves. The header's `occurrence_total` (§6) sums
the leaves' occurrence counts.

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
or a sampled audit (Security and audit) checks completeness, and is **required**
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
that a valid opt-out request was made (Guarantee classes and scope).

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
  (a) none, which is M1-open without a metadata opening;
  (b) *selective*, where one entry is opened through MD1 (§10), and other
  entries stay hidden;
  (c) *auditor*, where the full sidecar for a sampled or complete set of
  items is given to an auditor under the audit terms.
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
prototype's boundary modes (prototype item 5). A non-membership path can reveal one neighboring key and commitment.

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
compressions. The [research notes](dataset-proof-research.md#private-proof-experiments)
detail the impact on private proofs.

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
  rebuild detects these shapes. Builders MUST emit the canonical tree.
- **Depth.** Accept `0 ≤ d ≤ 256 − p` below the partition root.

The [similarity index](dataset-similarity.md#similarity-index) uses the same tree with its own domains
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

*Status: design, not implemented.* `olympus-manifest` does not yet encode,
sign, ledger-commit or chain headers. Its verifiers take `item_root` and the
tables from a header the caller has already verified. `parent_header_digest`,
`created_at_unix_s`, the §7 envelope and the §10 chain check are
specification only.

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
`SmtRootAttestation` and the checkpoint `TransitionAttestation`. These
attestations bind roots and sizes. A V2 ledger snapshot also signs
`signed_at_unix`. If the checkpoint authority and its clock are trusted,
the first V2 checkpoint covering the bundle provides an upper bound on when
the bundle existed. V1 snapshots carry no signed time.

`created_at_unix_s` is signed display metadata chosen by the committer.
The format does not compare it with an authenticated time, so it cannot
detect a backdated claim. A later re-signing appears after the original in
ledger inclusion order. `parent_header_digest` chains versions, and a fork
appears as two headers naming the same parent.

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
that. An honest header already in the insert-only ledger retains its earlier
inclusion position (§6). A relying party sets its own minimum suite and
SHOULD require the hybrid suite for any version created after hybrid signing becomes
available. Committers SHOULD re-sign their live versions under the hybrid
suite once it ships. A re-signed header is a new header over the same
`global_root`, so a verifier can use the same proof body with the new authenticated header.
A bundle referencing the old header digest must update its reference.

### 8. Compact proof bodies (`olympus-dataset-proof/v1`)

The enclosing format selects the proof version. Raw digests and sibling
hashes are exactly 32 bytes. The verifier uses the authenticated header's
`p` and recomputes the intended query key from the work and profile when it
has the work. It checks any supplied query key against its intended query.

```text
M1-open  = u8(1) ‖ key ‖ item_preimage ‖ path
N1       = u8(2) ‖ query_key ‖ terminal ‖ path
terminal = u8(0) for E, or u8(1) ‖ neighbor_key ‖ neighbor_commitment
path     = u64_be(partition_count) ‖ u16_be(d) ‖ bitmap
           ‖ present_partition_siblings ‖ top_siblings
```

- `item_preimage` is the 114-byte preimage in §2. M1-open reconstructs the
  terminal from the key and preimage, so it sends neither a second key nor a
  terminal commitment. The verifier derives the key again from the opened
  digest and the header's named profile.
- `bitmap` is `ceil(d/8)` bytes. Bit 7 of byte 0 represents the first
  in-partition level, with bits consumed most-significant first. A zero bit
  substitutes `E`; a set bit consumes one raw sibling hash. Hashes appear
  in root-to-terminal order below the partition boundary. The exactly `p`
  top-tree siblings follow in terminal-to-root order and carry no bitmap.
  Directions come from the corresponding key bits.
- Reject unknown tags, depth beyond `256 − p`, nonzero unused bitmap bits,
  explicit `E` at a set bit, missing bytes and trailing bytes. Fold using
  all §4 checks. An N1 neighbor must differ from the query key. A plain
  N1 neighbor opening reveals the neighbor's key and commitment. Plain
  M1-open reveals the commitment preimage, including the occurrence count
  and the fingerprint and metadata roots.
- Exact verification takes the signed header's `item_root` as its expected
  root. Authenticating a path against a supplied root and authenticating
  that root as a specific dataset version are both required for a dataset
  answer.
- A body names no header, dataset or version. It is reusable: it verifies
  against every header whose `item_root` it folds to. Two versions with the
  same items and partition counts have the same `item_root` and accept the
  same bodies, although their `global_root`s differ. A re-signed header (§7)
  relies on this. The binding to a dataset version is therefore the
  verifier's, not the body's. The relying party authenticates the header it
  intends (its `dataset_id`, `version`, `ledger_shard_id` and profile table),
  checks that the answer references that header, and only then folds the
  body against that header's `item_root`.

#### Bundle sharing and multiproofs

An offline bundle includes each signed header and its ledger evidence once.
Each answer references a header by `header_digest`. D1/D2 also require the
version-chain inputs described in §10. Header and evidence framing
remains a draft transport detail and is outside the single-body encoding
above. Caching a verified header is an optional transport optimization.

For a batch under one header, use a Merkle multiproof. Sort opened terminal
addresses by key prefix, group them by partition and build their union of
paths. The frontier consists of the child positions immediately outside
that union. Traverse left before right, using one hash per frontier
position. Below a partition boundary a bitmap omits frontier hashes equal
to `E`. Use each partition count once. Fold the covered partition roots
through a shared top-tree frontier. Query answers may reference the same
terminal when each independently satisfies its membership or absence
condition. The verifier derives positions from the terminal depths and
query keys, rejects inconsistent or overlapping terminals, and checks
that each answer follows its own key path. The batch wire encoding and
vectors remain implementation work. [Compact Merkle Multiproofs](https://arxiv.org/abs/2002.07648)

### 10. Metadata and version change proofs

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
are then validated. The `extraction_index` must refer to an entry in the
authenticated extraction table. An `opt_out_status` outside {0, 1, 2}, or
non-NFC strings, are rejected. MD1 establishes a class C fact only: the committer
recorded this entry for one occurrence of this item.

**D1 — removal between versions.** Public: two verified headers `h_old`
and `h_new` and `content_key`. Statement: M1-open against `h_old`'s `item_root`
and N1 against `h_new`'s `item_root`, under the same canonicalization
profile. D1 establishes a class A fact: the canonical work was in the
committed old version and is in no position of the committed new one.
**D2 — addition** reverses the openings (N1 old, M1-open new).
For both statements, `h_new` must reach `h_old` through authenticated
`parent_header_digest` links within the same dataset and ledger shard.

*Forks are out of reach of the ledger alone.* The ledger shard is keyed by
each bundle's content hash (§6). It proves that a given header was committed,
but it has no authenticated index from a parent digest to its children, so no
proof can show that a parent has only one child. A removal claim therefore
establishes three things: the work was in `h_old`, it is absent from `h_new`,
and `h_new` descends from `h_old`. It does **not** establish that no other
child of a header on the chain still contains the work. A bundle carrying a
header chain supplies no evidence about omitted sibling headers either. A
relying party that needs fork absence must obtain it outside this format,
for example from a full audit of the committer's ledger shard. An
authenticated parent-to-children index would be a new ledger feature and a
new version of this RFC.

The chain says that versions follow each other. It does not say which items
changed. A committer MAY publish a diff commitment beside the header, using
ADR-0027's construction under its own domain:
`diff_root = H_diff(u64_be(removed) ‖ u64_be(added) ‖ sorted (u8(op) ‖ content_key) entries)`,
with `op` = 0 for removed and 1 for added. That lets an auditor check the
diff against both trees in one pass. It is optional because D1 and D2 do
not depend on it.

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
| header substitution, different items | a valid M1-open or N1 body verified against a header whose `item_root` differs | root mismatch | every verifier |
| header substitution, same items | a valid body whose answer references header B, presented to a relying party that intends header A with a different `dataset_id` or `version` but the same `item_root` | intended-header mismatch. The body itself still folds (§8), so the rejection must come from the header comparison. | every verifier |
| profile substitution | a valid M1-open checked with a profile table whose entry at the opened `profile_index` names another profile | content key mismatch | every verifier |
| prefix check, canonical shape, depth | §4's three rules, each violated once | the specific rule | every verifier |

The table's cases are required and not yet published, because the header
and MD1 wire formats are not implemented.

The compact encoding vectors are published in
`verifiers/test_vectors/dataset_compact_proof_vectors.json`, generated by
`cargo run -p olympus-manifest --example gen_dataset_proof_vectors`. They
cover both N1 terminals, depth 0 and 256, zero and nonzero (`p = 2`) top
paths, omitted empty siblings, nonzero bitmap padding, explicit empty
hashes, unknown tags, depth beyond `256 − p`, `p > 16`, an N1 neighbor equal
to the query, truncation, appended bytes, and the §4 prefix, shape and root
checks. Each negative case names its rule, the stage that rejects it and the
exact rejection. Positive bodies must re-encode byte for byte and fold to the
recorded `item_root`. The Rust tests replay the file. No other verifier
implements these bodies yet.

## Security and audit

The dataset tree is separate from the ledger. The design commits the signed
header through ordinary ingest and reuses `SignatureEnvelopeV3`. Neither step
is implemented yet (§6). A full audit rebuilds
the extraction, canonical items, sidecars and roots. A sampled audit
opens drawn items and their source data so an auditor can check fidelity.
The committed set documents the version that the committer identified.
It provides no evidence by itself about which data a model used in training.

Content keys are deterministic. A committer who answers arbitrary exact
queries exposes membership information, and a plain N1 answer may expose a
neighboring key. The committer holds the record index and supplies proofs.
A committer who declines to answer has made no claim.
