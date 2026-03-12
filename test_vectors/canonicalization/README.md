# Canonicalization Vectors

Canonicalization drift is prevented by the pinned TSV fixtures in
`verifiers/test_vectors/canonicalizer_vectors.tsv` (positive cases) and
`verifiers/test_vectors/canonicalizer_rejected.tsv` (negative cases). These are
generated from the Python reference canonicalizer and exercised by all
cross-language verifier suites.

Use these files to validate that:

- Raw inputs are transformed into the exact canonical bytes recorded in the TSV
- The canonical bytes hash to the pinned BLAKE3 digests

No additional copies are stored here to avoid divergence; consumers should read
the TSV files directly.
