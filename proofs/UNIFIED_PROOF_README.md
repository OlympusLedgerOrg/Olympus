# Unified Section-Commitment Proof

The unified Groth16 artifact proves three linked statements:

1. Knowledge of private section field values and caller-supplied metadata whose
   structured Poseidon chain equals a public commitment.
2. Inclusion of that commitment in a depth-20 Poseidon Merkle tree.
3. Inclusion of that Merkle root at a supplied key in a depth-256 Poseidon SMT.

It does **not** prove document canonicalization, byte lengths, padding rules, or
checkpoint signatures. Canonicalization must be performed and verified before
the section fields are derived. Checkpoint signatures and quorum policy are
verified independently by the Rust federation layer.

## Names and compatibility

The public HTTP and verifier-CLI identifier is:

```text
unified_section_commitment_inclusion_root
```

The old public identifier, `unified_canonicalization_inclusion_root_sign`, is
retired because it asserted properties absent from the R1CS. The historical
string remains only as the circuit source and artifact stem so the existing
trusted-setup outputs remain byte-for-byte usable:

```text
proofs/circuits/unified_canonicalization_inclusion_root_sign.circom
proofs/keys/unified_canonicalization_inclusion_root_sign.{wasm,r1cs,ark.zkey}
proofs/keys/verification_keys/unified_canonicalization_inclusion_root_sign_vkey.json
```

Changing those filenames or regenerating constraints is not necessary for this
semantic correction.

## Statement

The five public signals retain their historical wire names:

| Signal | Proven meaning |
|---|---|
| `canonicalHash` | Structured section commitment; not proof of canonicalization |
| `merkleRoot` | Root reached by the supplied Merkle inclusion path |
| `ledgerRoot` | Root reached by the supplied SMT path |
| `treeSize` | Merkle-tree size used for the index bound |
| `ledgerKeyHash` | Poseidon commitment to the private 32-byte SMT key |

For each of eight section slots, the R1CS constrains:

```text
sectionHashes[i] = Poseidon(documentSections[i])
```

It then computes:

```text
acc = sectionCount
for i in 0..8:
    acc = DomainPoseidon(3)(acc, sectionLengths[i])
    acc = DomainPoseidon(3)(acc, sectionHashes[i])
canonicalHash = acc
```

`documentSections[i]` is an opaque BN254 field element. The circuit cannot
observe the source bytes and does not constrain `sectionLengths[i]` to their
actual length. It also does not require unused slots to be zero. These are input
conventions, not proven properties.

## Honest witness convention

`proofs/test_inputs/generate_unified_inputs.js` implements the supported
convention for independently canonicalized UTF-8 sections:

1. BLAKE3-hash the section bytes and reduce the digest into the BN254 scalar
   field to obtain `documentSections[i]`.
2. Set `sectionHashes[i]` to `Poseidon(documentSections[i])`.
3. Set `sectionLengths[i]` to the UTF-8 byte length.
4. Pad the field value and length with zero, and pad the hash with
   `Poseidon(0)` because every slot is constrained.

Earlier versions passed raw JavaScript strings as field inputs, used the BLAKE3
field directly as `sectionHashes[i]`, and padded hashes with zero. Those inputs
disagreed with the circuit and could not produce an honest witness.

## HTTP verification

Submit a proof bundle using the narrow identifier:

```bash
curl -X POST http://127.0.0.1:3737/zk/verify \
  -H "x-api-key: $OLYMPUS_API_KEY" \
  -H "content-type: application/json" \
  -d '{
    "circuit": "unified_section_commitment_inclusion_root",
    "proofJson": "{...}",
    "publicSignals": ["...", "...", "...", "...", "..."]
  }'
```

Requests using the retired identifier receive HTTP 410 rather than a misleading
verification result.

For offline verification, pass the same logical identifier to the Rust verifier
and explicitly provide the historical vkey file:

```bash
cargo run --release -p olympus-verifier -- verify \
  --circuit unified_section_commitment_inclusion_root \
  --vkey ../../proofs/keys/verification_keys/unified_canonicalization_inclusion_root_sign_vkey.json \
  --proof proof.json \
  --public-signals public.json
```

## Development

The artifact stem remains historical in build commands:

```bash
cd proofs
circom circuits/unified_canonicalization_inclusion_root_sign.circom \
  --r1cs --wasm --sym -o build/

node build/unified_canonicalization_inclusion_root_sign_js/generate_witness.js \
  build/unified_canonicalization_inclusion_root_sign_js/unified_canonicalization_inclusion_root_sign.wasm \
  test_inputs/unified_input.json \
  build/witness.wtns
```

Run the lightweight generator checks with:

```bash
cd proofs
npm run test:jsonpath
```

Run Rust witness and proving checks when the Rust toolchain and ceremony
artifacts are available:

```bash
cargo test -p olympus-desktop --features prover unified
cargo test -p olympus-desktop --features prover,zk-test-utils --test zk_soundness
```

Checkpoint integrity is outside this circuit. See `docs/federation.md` and the
federation verification modules for the signed checkpoint statement.
