# Unified Canonicalization and Inclusion Proof

The public composite protocol is identified as:

```text
unified_canonicalization_inclusion_root
```

It combines two independently verified proofs. A RISC Zero receipt proves that
the fixed Olympus guest image ran the exact
`olympus_crypto::canonical::canonicalize_bytes` JCS/NFC/decimal canonicalizer.
The existing unified Groth16 artifact then proves three linked statements:

1. Knowledge of private section field values and caller-supplied metadata whose
   structured Poseidon chain equals a public commitment.
2. Inclusion of that commitment in a depth-20 Poseidon Merkle tree.
3. Inclusion of that Merkle root at a supplied key in a depth-256 Poseidon SMT.

The Groth16 circuit alone does **not** prove document canonicalization, byte
lengths, padding rules, or checkpoint signatures. The combined verifier derives
its one-section witness from the authenticated receipt journal and requires the
resulting structured commitment to equal the Groth16 public `canonicalHash`.
Checkpoint signatures and quorum policy remain independent Rust-layer checks.

## Names and compatibility

The combined HTTP identifier is:

```text
unified_canonicalization_inclusion_root
```

The narrow Groth16-only identifier remains available for callers that need only
the raw section-commitment statement:

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

The receipt composition changes none of the executable circuit constraints,
R1CS, five public signals, proving key, verification key, or signed ceremony
manifest. Comment corrections do not require a Groth16 setup or ceremony run.

## Canonicalization receipt

The guest accepts private source JSON bytes and commits a fixed 96-byte journal
containing the source length, canonical length, a domain-separated BLAKE3 source
commitment, the BLAKE3 canonical digest, and `section_count = 1`. The verifier
accepts receipts only for the fixed, committed guest image and explicitly
rejects RISC Zero development-mode receipts.

For the combined statement, the host maps the journal to the existing eight-slot
Groth16 witness deterministically: slot zero contains the canonical digest
reduced into the BN254 scalar field, its length is the authenticated canonical
length, and the remaining seven slots use the circuit's zero-padding convention.
See [ADR-0040](../docs/adr/ADR-0040-risc-zero-canonicalization-receipts.md) for
the exact journal encoding and Poseidon binding.

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

## Standalone Groth16 witness convention

`proofs/test_inputs/generate_unified_inputs.js` implements the supported
convention for the narrow `unified_section_commitment_inclusion_root` route and
independently canonicalized UTF-8 sections:

1. BLAKE3-hash the section bytes and reduce the digest into the BN254 scalar
   field to obtain `documentSections[i]`.
2. Set `sectionHashes[i]` to `Poseidon(documentSections[i])`.
3. Set `sectionLengths[i]` to the UTF-8 byte length.
4. Pad the field value and length with zero, and pad the hash with
   `Poseidon(0)` because every slot is constrained.

Earlier versions passed raw JavaScript strings as field inputs, used the BLAKE3
field directly as `sectionHashes[i]`, and padded hashes with zero. Those inputs
disagreed with the circuit and could not produce an honest witness.

For `unified_canonicalization_inclusion_root`, callers do not choose these
fields: the Rust host overwrites them from the verified one-section receipt
claim before Groth16 proving.

## HTTP verification

Submit a combined proof bundle with the receipt and the expected source
commitment:

```bash
curl -X POST http://127.0.0.1:3737/zk/verify \
  -H "x-api-key: $OLYMPUS_API_KEY" \
  -H "content-type: application/json" \
  -d '{
    "circuit": "unified_canonicalization_inclusion_root",
    "proofJson": "{...}",
    "publicSignals": ["...", "...", "...", "...", "..."],
    "canonicalizationReceipt": "...",
    "sourceCommitment": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }'
```

Requests using the retired identifier receive HTTP 410 rather than a misleading
verification result. The combined verifier authenticates the receipt against
the fixed guest image, validates its one-section journal, matches
`sourceCommitment`, binds the derived section commitment to public signal zero,
and only then accepts the Groth16 proof. Receipt verification is available on
all supported desktop targets, including native Windows.

The standalone Rust verifier repeats the complete receipt-to-Groth16 binding.
Store the canonical base64 receipt without a trailing newline, then run from
the repository root:

```bash
cargo run --release --manifest-path verifiers/rust/Cargo.toml \
  --bin olympus-verifier -- verify-canonicalization \
  --vkey proofs/keys/verification_keys/unified_canonicalization_inclusion_root_sign_vkey.json \
  --proof proof.json \
  --public-signals public.json \
  --canonicalization-receipt-file receipt.b64 \
  --source-commitment 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

To inspect only the narrower historical Groth16 statement, use its honest
logical identifier explicitly:

```bash
cargo run --release --manifest-path verifiers/rust/Cargo.toml \
  --bin olympus-verifier -- verify \
  --circuit unified_section_commitment_inclusion_root \
  --vkey proofs/keys/verification_keys/unified_canonicalization_inclusion_root_sign_vkey.json \
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

Build the pinned RISC Zero guest with:

```bash
bash proofs/zkvm/build_canonicalization_guest.sh
```

Local receipt generation is compiled only with the `zkvm-prover` feature and
requires a supported Linux environment; Windows operators can use WSL2. Native
Windows still verifies combined proof bundles and never falls back to a fake,
host-only, or implicit remote proof.
