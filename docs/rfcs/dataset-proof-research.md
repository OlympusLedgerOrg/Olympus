# Dataset proof research

These proposals accompany [RFC-0000](0000-content-addressed-dataset-commitments.md)
and the [similarity companion](dataset-similarity.md).

## Private proof experiments

The depth-20 Ligetron prototype measured 6,135,942 compressed bytes for
membership and 10,609,599 bytes for non-membership. Those results used the
prototype relations. A later depth-50 run used the RFC's BLAKE3 item tree
and took 20.5 seconds for membership and 17.2 seconds for neighboring-leaf
absence on Intel Arc 140V. The compressed proofs totaled 13.24 MB.
[Depth-50 benchmark and reproduction commands](../../tools/ligetron-bench/README.md)

Prototype M1-open and N1 before extending to M2. Authenticate the header
and recompute its global root in ordinary verification. The private
relation takes the authenticated item root, partition exponent and exact
statement inputs as public inputs. Bind those inputs to the verifier's
intended query. For M2, also bind the authenticated profile and threshold,
and open the private item and fingerprint with the same commitment domains.
Use fixed-size digest and fingerprint inputs. Hash claimant work outside the
circuit. Check depth, key prefix, canonical shape and byte lengths inside
the relation.

At depths 30–40, measure compressed size, proving time, verification time,
and peak memory for 1, 16 and 128 queries. Compare one batched proof with
individual proofs and test public-input binding. The figures below are
historical cost estimates for the original relation with in-circuit header
hashing. Re-measure before choosing a proof backend or setting a size budget.

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
| similar non-membership (N2), image | every 24-bit band value occupied, so `N' ≈ 64 · 2^24 = 2^30`; ≈ 60 entries per bucket | ≈ 64 · 32 + ⌈64 · 60 · 70 / 64⌉ + 4 ≈ 6,250 | ≈ **2.6 h** |

The image N2 figure is dominated by bucket contents, not paths, so it grows
linearly with dataset size, at roughly 4,200 compressions per 10^9 items.
These are **estimates** extrapolated from prototype measurements.

## Candidate absence in the similarity index

**N2 — similar non-membership.** Public: global-root fields,
`fp_profile_index`, `F_q`, `τ`, and the `b` band keys of `F_q`. The verifier
recomputes the band keys from `F_q`, so they are not derived in-circuit.
Private: per band, a path in the similarity tree and, if present, the
bucket. Statement: for each band key, either (a) it is absent (N1 shape over
`similarity_root`), or (b) its `bucket_commit` opens to `similarity_root`
and **every** entry's fingerprint fails `τ` against `F_q`. Meaning:
*no committed segment that shares any LSH band with the query is within
`τ`*. This is a deterministic fact about the committed index, and it is
all an N2 result can establish. Label it "no candidate under index".
The similarity companion estimates retrieval probabilities under assumptions
about the fingerprints and index. N2 remains outside v1.

All entries in each queried bucket must fail the threshold. Merkleizing
bucket entries can reduce the cost of individual openings. An authenticated
subtree summary or a private proof would still need to establish that every
entry covered by it fails.

## Additional profile proposals

| Extraction profile | v | Parameters | Items | Occurrence provenance |
|---|---|---|---|---|
| `parquet/column` | 1 | `column`, `uri_column`, `license_column` (optional) | Each row is one item. The item is the `column` value, which must be `BYTE_ARRAY` (`STRING` or binary). A null is rejected. | values in `uri_column` / `license_column`, else empty |
| `webdataset/member` | 1 | `extension` (for example `jpg`, `txt`) | Each tar member whose name ends in `.extension` is one item, grouped by WebDataset key | `source_uri` = `<tar path>#<key>` |

| Canonicalization profile | v | Canonical bytes |
|---|---|---|
| `image/rgba8` | 1 | Decode with the pinned decoder. Reject multi-frame images. Apply EXIF orientation. Convert to 8-bit sRGB RGBA (opaque if there is no alpha). Discard all metadata. Bytes = `"RGBA8\0" ‖ u32_be(width) ‖ u32_be(height) ‖ pixels, row-major, top-to-bottom`. |

## Compact proof size benchmark

Run the Rust benchmark from the repository root.

```text
cargo run --locked -p olympus-manifest --example bench_dataset_proof_sizes
```

The benchmark builds a deterministic BLAKE3 item tree with 1,048,576
synthetic items and 16 partitions, and samples 4,096 answers per statement.
M1-open and N1 bodies round-trip through the Rust codec and verify against
the tree root. The text M2 fixture opens one 480-byte fingerprint from a
128-segment fingerprint set, which needs seven fingerprint siblings. The M2
body round-trips through the M2 codec and passes `verify_m2`. The
fingerprints are synthetic bytes of the profile's width, not MinHash output.

| Body | Median bytes | p95 bytes | Largest observed bytes |
|---|---:|---:|---:|
| M1-open | 800 | 864 | 960 |
| N1 | 718 | 783 | 847 |
| Text M2 fixture | 1,523 | 1,587 | 1,683 |

The proposed targets are under 2 KiB for exact proofs and under 4 KiB for
single text M2 openings. The figures are raw proof bodies. The signed header,
signature, ledger evidence, and outer bundle framing are additional shared
costs. The content module does not yet emit an end-to-end signed bundle.
The fixture measures size with uniform keys and one fingerprint tree
shape. These measurements do not set a maximum for every dataset.

## Unresolved questions

1. Measure in-circuit BLAKE3 path cost at depths 30–40, and the N2 cost at
   `b = 20` and `b = 64`, on hardware GPU.
2. Whether the default thresholds (`m ≥ 84`, Hamming `≤ 31`) and band
   parameters fit real corpora. They need false-positive and recall
   measurements on labelled near-duplicate sets.
3. Whether to require in-circuit MinHash recomputation for short text items
   to verify the committer's fingerprint computation.
4. Sampled-audit protocol details: who chooses the sample, which randomness
   beacon, and the response deadline.
5. An optional salted-key mode that keeps outsiders from testing guessed
   items against leaked keys, with the salt committed and the key derivation
   proven in-circuit.
6. More profiles: audio (Chromaprint-style), source code (winnowing), and
   cropped-image robustness (PDQ is weak against crops).
7. Measure whether wider image bands with a higher band count reduce
   bucket sizes enough to lower N2 cost. Recompute the detection
   probabilities for any change to the band parameters.
8. Whether `license` should be normalized to an SPDX expression where one
   applies, with the raw string kept alongside, so licenses can be compared
   across datasets. v1 commits the string as found.
9. Extraction profiles beyond v1: HuggingFace `datasets` Arrow shards,
   multi-field items (an image–caption pair as one item), and conversation
   formats.
10. `text/minhash-120` v1 keeps only L* and N* characters, so a combining
    mark (M*) that survives NFKC splits a word. Examples are Devanagari
    vowel signs and the U+0307 left after folding `İ`. Scripts written
    without spaces (Chinese, Japanese, Thai) normalize to very few tokens.
    A paragraph can then fall below five tokens and get no fingerprint.
    Either effect lowers recall for those languages. Measure both in the
    text-threshold study before v1 is fixed, and consider a v2 that keeps M*
    and segments unspaced scripts.
