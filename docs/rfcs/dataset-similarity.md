# Dataset similarity proofs

Companion to [RFC-0000](0000-content-addressed-dataset-commitments.md).
Plain M2 is a v1 extension after the text-threshold study. Image profiles
remain gated. N2 and private proofs are [research](dataset-proof-research.md).

**Implementation status.** `text/minhash-120` v1, fingerprint sets, the
similarity index and plain M2 are implemented in `olympus-manifest`
(`content::fingerprint`, `content::similarity`, `verify_m2`, and the M2 wire
codec). The profile has no published conformance vectors yet, so RFC-0000
§0a rule 1 still bars it from a header. The text-threshold study has not
been run. The default threshold is a parameter, not a measured operating
point.

An M2 result proves that a committed item carries a segment fingerprint
within the named threshold of the query fingerprint. Its relevance to
human-recognizable copying depends on measured recall and precision.
Verification assumes the committer computed the fingerprint correctly.
The committer's signed root makes any misstatement attributable, and an
exact copy or a sampled rebuild can check the computation.

## Fingerprint profiles

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
  128. Segment `k` is tokens `[128k, min(128k + 256, n))`, for
  `k = 0 .. K−1`, where `K = 1` if `n ≤ 256` and `K = 1 + ⌈(n − 256) / 128⌉`
  otherwise. This is the fewest windows that cover every token. The last
  window of a longer item can be shorter than 256 tokens, but never shorter
  than 129. An item with fewer than 5 tokens gets no fingerprint.
- Shingles are each run of 5 consecutive tokens, joined with U+0020. Each
  shingle maps to
  `x = u64_be(BLAKE3.derive_key("olympus 2026-11 dataset minhash-shingle v1", shingle)[0..8]) mod (2^61−1)`.
- Slot `i ∈ [0,120)` holds the minimum over the segment's shingles of
  `((a_i·x + b_i) mod (2^61−1)) mod 2^32`. The coefficients come from the
  extended output of
  `derive_key("olympus 2026-11 dataset minhash-coefficients v1", "")`, whose
  first 32 bytes are that key. The stream is read as consecutive `u64_be`
  values, each reduced mod `2^61−1`. For `i = 0, 1, …`, `a_i` is the next
  nonzero reduced value (a zero is skipped), and `b_i` is the value after it,
  where zero is allowed.
- The fingerprint is the 120 slots in order, each `u32_be` (480 bytes).
- The profile applies to items committed under `text/utf8-nfc`. Items under
  any other canonicalization profile are committed exactly and get no
  `text/minhash-120` fingerprint.
- The verifier resolves a header row to this profile only for
  `(text/minhash-120, 1)` with `b = 20`, `r = 6` and `1 ≤ threshold ≤ 120`.
  Any other row is rejected and never reinterpreted. `implementation_id` is
  not compared, because any conforming implementation may compute the
  fingerprints.

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
the dataset falls outside near-duplicate coverage. It counts leaves, not
occurrences. In an exact-only version it equals `item_count`.

## Similarity index

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
similarity_root  = olympus-dataset-tree/v1 over (band_key → bucket_commit), with the core RFC’s similarity domains (§4), no partitions
```

"No partitions" means the subtree is rooted at depth 0 and used as is, with
no `H_part` or `H_top` wrapper. An empty index is `E_s`. A bucket opening
(a path along a band key plus the full sorted bucket) shows what the
committed index files under that key. It is a class B fact about the index,
and it never shows that no similar item exists.

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

## Plain M2 — one candidate

```text
M2 = u8(3) ‖ lp(M1-open for candidate) ‖ u16_be(fp_profile_index)
     ‖ u32_be(segment_index) ‖ u32_be(leaf_index) ‖ u32_be(leaf_count)
     ‖ candidate_fingerprint ‖ fingerprint_siblings
```

Verify the candidate's compact M1-open body against the signed header and
open its fingerprint leaf against the resulting `fp_set_root`. The
fingerprint profile in the header determines the fingerprint width,
distance rule and threshold. Use the bottom-up odd-promotion shape from
`(leaf_index, leaf_count)`, require `leaf_index < leaf_count`, consume all
expected siblings and reject trailing bytes. Reject a candidate whose
fingerprint profile does not apply to its canonicalization profile, for
example a `text/minhash-120` fingerprint on a `bytes/raw` item. A
conforming builder never commits one. The shape fields guide
folding and do not attest to the total number of fingerprints. Check that
the candidate passes the signed profile's threshold against the query
fingerprint. The verifier obtains the query fingerprint from the claimant
or recomputes it from the claimant's copy.

The witness reveals the candidate key, preimage, fingerprint and segment
index. It needs no similarity bucket opening. A claim that the candidate
is also present in a particular search bucket would require evidence
against `similarity_root`. When batching a whole work against one header,
share the item multiproof, then share the fingerprint path frontier for
all opened segments of each item. One opening can answer multiple query
segments that independently pass the distance check.
