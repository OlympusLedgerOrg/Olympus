# Merkle Vectors

Legacy binary-Merkle hashing and proof vectors live in
`verifiers/test_vectors/vectors.json` under the `merkle_leaf_hash`,
`merkle_parent_hash`, `merkle_root`, and `merkle_proof` sections. They are
exercised by the maintained Rust and JavaScript verifier suites.

Refer to that file for:

- Domain-separated legacy binary-Merkle leaf hashing (`OLY:LEAF:V1`)
- Domain-separated legacy binary-Merkle parent hashing (`OLY:NODE:V1`)
- Root construction (including odd-leaf duplication)
- Inclusion proof validity/invalidity cases

These are not the live parser-bound SMT leaf vectors. For the live
ADR-0005 structured leaf layout, use the SSMF/SMT sections in
`verifiers/test_vectors/vectors.json`.
