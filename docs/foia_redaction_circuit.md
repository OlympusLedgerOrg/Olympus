# FOIA Redaction Circuit — Architecture and Design

This document describes the design decisions behind the Phase 0.2 FOIA
selective-disclosure circuit (`proofs/selective_disclosure_merkle.circom`),
its parameter choices, and the agency workflow for generating and verifying
Groth16 proofs with `snarkjs`.

---

## Circuit Overview

The `SelectiveDisclosure` circuit proves that a set of *k* document
fragments (leaves) each belong to a Poseidon Merkle tree whose root is
the on-ledger document commitment, without revealing any redacted content.

Each revealed leaf is represented by a structured preimage of
`preimageLen` field elements:

| Index | Field element   | Purpose                                     |
|-------|-----------------|---------------------------------------------|
| 0     | `doc_id_fe`     | Document identifier (field element encoding)|
| 1     | `idx`           | Leaf index within the document tree         |
| 2     | `type`          | Content type tag (paragraph, header, etc.)  |
| 3     | `page`          | Source page number                          |
| 4     | `text_hash_hi`  | High 128 bits of the BLAKE3 text hash       |
| 5     | `text_hash_lo`  | Low  128 bits of the BLAKE3 text hash       |

The circuit:
1. Hashes each preimage with `Poseidon(6)` to reproduce the leaf hash.
2. Binds the computed hash to the public `leafHashes[i]` input.
3. Verifies each leaf's Merkle inclusion path against the shared `root`.

---

## Parameter Rationale

### `depth = 20` — Tree depth

A depth-20 Poseidon Merkle tree supports **2²⁰ = 1,048,576 leaves per
document**.  This is sufficient for line-by-line or paragraph-by-paragraph
decomposition of even the largest government PDFs (typical FOIA releases
contain tens of thousands of paragraphs).

Deeper trees impose a linear constraint cost per leaf proof: each
additional level of depth adds one `Poseidon(2)` gate (~240 R1CS
constraints) per proven leaf.  At `depth=20` and `k=8` the circuit
requires approximately **38,400 Poseidon constraints** for the Merkle
paths alone—comfortably within the 2¹⁵ Powers of Tau bound used in the
setup script, and fast enough for server-side proof generation in a
batch pipeline.

Shallower trees (e.g., depth=10) would support only 1,024 leaves—too few
for long documents.  Deeper trees (e.g., depth=32) would double the
constraint count without meaningful gain for FOIA use cases.

### `k = 8` — Maximum redactions per proof bundle

`k=8` is the maximum number of leaves that can be simultaneously proven
in a single Groth16 proof.  This value balances two competing concerns:

**Constraint count grows linearly with k.**  Each additional revealed
leaf adds `depth` Poseidon hash gates for the Merkle path plus one
`Poseidon(preimageLen)` gate for the preimage.  At `k=8` the circuit
has a manageable constraint budget while still covering the most common
FOIA redaction patterns (multi-paragraph exemption blocks rarely exceed
8 consecutive paragraphs in a single legal justification).

**Batching vs. circuit bloat.**  Agencies may batch multiple proof
bundles for larger redactions.  Each bundle proves up to 8 leaves
independently; the verifier checks each proof against the same root.
This is more efficient than a monolithic circuit with large `k`:

- A monolithic `k=64` circuit would require 8× more constraints and
  a proportionally larger Powers of Tau ceremony file.
- Sequential `k=8` bundles allow partial disclosure: an agency can
  release a first bundle immediately and add further bundles as
  review progresses, without rerunning the trusted setup.

`k=8` therefore represents the lowest constraint overhead that avoids
single-leaf proof spam (which would require 8× more proof verification
calls for an equivalent disclosure).

### `preimageLen = 6` — Leaf preimage width

Six field elements encode all structured metadata needed to uniquely
identify and audit a document fragment.  Poseidon is optimized for
small arities; `Poseidon(6)` requires fewer rounds than larger arities
while still providing 128-bit collision resistance over the BN128 scalar
field.

---

## Agency Workflow

### Prerequisites

- Node.js ≥ 18
- `circom` ≥ 2.1.6 ([installation guide](https://docs.circom.io/getting-started/installation/))
- `snarkjs` (installed via `npm install` in the `proofs/` directory)

### Step 1 — Compile the Circuit

```bash
cd proofs/
circom selective_disclosure_merkle.circom --r1cs --wasm --sym -o build/
```

This produces:
- `build/selective_disclosure_merkle.r1cs` — constraint system
- `build/selective_disclosure_merkle_js/` — WASM witness generator
- `build/selective_disclosure_merkle.sym` — symbol table

### Step 2 — Trusted Setup (run `tools/groth16_setup.sh`)

```bash
./tools/groth16_setup.sh
```

The script automates the full ceremony:

| Sub-step | Command | Output |
|----------|---------|--------|
| Phase 1 init | `snarkjs powersoftau new bn128 15` | `pot15_0000.ptau` |
| Phase 1 contribution | `snarkjs powersoftau contribute` | `pot15_0001.ptau` |
| Phase 1 finalise | `snarkjs powersoftau prepare phase2` | `pot15_final.ptau` |
| Phase 2 setup | `snarkjs groth16 setup` | `foia_redaction_0000.zkey` |
| Phase 2 contribution | `snarkjs zkey contribute` | `foia_redaction_final.zkey` |
| Export vkey | `snarkjs zkey export verificationkey` | `verification_key.json` |

> **Production note:** The single-contributor ceremony in this script is
> suitable for development and testing only.  A production deployment
> requires a Phase 2 multi-party computation (MPC) ceremony with at least
> three independent contributors using different machines and entropy
> sources.

### Step 3 — Generate a Proof (Agency)

For each redacted document the agency:

1. Constructs the witness JSON with the revealed preimages and Merkle paths.
2. Runs the WASM witness generator:
   ```bash
   node build/selective_disclosure_merkle_js/generate_witness.js \
        build/selective_disclosure_merkle_js/selective_disclosure_merkle.wasm \
        input.json witness.wtns
   ```
3. Generates the Groth16 proof:
   ```bash
   snarkjs groth16 prove build/foia_redaction_final.zkey witness.wtns \
        proof.json public.json
   ```

### Step 4 — Verify a Proof (Auditor / Requestor)

Any party with `verification_key.json` and the public inputs can verify:

```bash
snarkjs groth16 verify build/verification_key.json public.json proof.json
```

A `true` result cryptographically guarantees that:
- Each `leafHash` in `public.json` is a valid Poseidon hash of the
  disclosed preimage.
- Each leaf is included in the Merkle tree whose root matches the
  on-ledger document commitment.
- No content beyond what is disclosed was required to construct the proof.

---

## Security Properties

| Property | Guarantee |
|---|---|
| Soundness | An adversary cannot produce a valid proof for a leaf not in the tree (Groth16 knowledge soundness under the Generic Group Model). |
| Zero-knowledge | The proof reveals nothing about redacted leaves beyond their count (`k`). |
| Tamper-evidence | Any modification to `verification_key.json` or the on-ledger root invalidates verification. |

## Non-Goals

This circuit does **not**:
- Assert that the revealed content is legally correct or complete.
- Prevent an agency from omitting leaves that should be disclosed.
- Replace judicial review of redaction decisions.

These are policy questions outside the scope of the cryptographic protocol.
