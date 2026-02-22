Here’s a **full rewrite of your `proofs/README.md`** that matches the repo as it exists now (indexed `non_existence`, updated smoke inputs, and more accurate claims). I tightened wording so it’s “awesome” *and* honest about what’s proven.

**Put this file here:** `proofs/README.md` (overwrite)

````md
# Zero-Knowledge Proofs for Olympus

This directory contains the Circom circuits and Groth16 tooling used by Olympus to
generate and verify zero-knowledge proofs over Poseidon-based Merkle commitments.

These proofs are designed to let a prover demonstrate properties about a committed
document *without revealing private leaf values or Merkle path details*.

---

## Quick Start

```bash
# 1) Install npm dependencies (circomlib, snarkjs)
cd proofs/
npm install

# 2) Download PTAU, compile circuits, generate dev keys
#    Requires: circom compiler in PATH (circom or circom2)
bash setup_circuits.sh

# 3) Smoke test — end-to-end prove + verify for each circuit
bash smoke_test.sh
````

---

## Circuits

### `document_existence.circom`

Poseidon Merkle inclusion proof that exposes the **leaf index** as a public input
and keeps the **leaf value** private.

**Proves:** “A leaf exists at public `leafIndex` in the Poseidon Merkle tree with public `root`.”

---

### `redaction_validity.circom`

Selective redaction proof over a Poseidon Merkle tree.

**Proves (current implementation):**

* For each leaf where `revealMask[i] == 1`, the prover knows a leaf value that is included
  in the original tree with `originalRoot`.
* A public `redactedCommitment` is computed as a Poseidon chain over the masked leaf vector
  (revealed values; redacted slots contribute 0) and `revealedCount`.

**Important notes:**

* This circuit is a *reference implementation* for “subset authenticity + commitment”.
* It does **not** by itself guarantee a particular text-format redaction policy (e.g., FOIA rules),
  and it does not reconstruct or validate a rendered redacted document string.

---

### `non_existence.circom`

Indexed “absence-at-index” proof for an **indexed Merkle tree**.

**Proves:** “The leaf at public `leafIndex` is the empty value `0` in the Poseidon Merkle tree
with public `root`.”

**Not a full sparse Merkle keyed non-membership proof.**
This circuit does not accept a key/value pair or prove divergence; it proves emptiness at a specific index.

---

## Legacy Circuits

* `inclusion.circom` and `redaction_v1.circom` remain as reference baselines.

---

## Directory Layout

```
proofs/
├── circuits/
│   ├── lib/
│   │   ├── poseidon.circom       # Re-exports Poseidon from circomlib
│   │   └── merkleProof.circom    # Shared Merkle proof templates
│   ├── document_existence.circom
│   ├── redaction_validity.circom
│   ├── non_existence.circom
│   ├── inclusion.circom          # Legacy reference
│   └── redaction_v1.circom       # Legacy reference
├── keys/
│   └── verification_keys/        # Exported vkey JSON files
├── test_inputs/
│   └── generate_inputs.js        # Generates valid Poseidon Merkle inputs
├── build/                        # Compiled artifacts (git-ignored)
├── setup_circuits.sh             # PTAU download + compilation + key gen
├── smoke_test.sh                 # End-to-end prove + verify
└── package.json                  # npm dependencies
```

---

## Scripts

### `setup_circuits.sh`

* Downloads the Hermez/Polygon Hermez Powers of Tau file (`2^17`).
* Compiles all three main circuits with Circom (`.r1cs`, `.wasm`, `.sym`).
* Runs Groth16 Phase 2 setup with a **single dev contribution**.
* Exports verification keys to `keys/verification_keys/`.

If the PTAU download is unavailable, the script falls back to generating a dev PTAU locally.

> ⚠️ Dev keys are not production-safe. See Security Considerations below.

---

### `smoke_test.sh`

* Generates inputs via `test_inputs/generate_inputs.js`.
* For each circuit:

  1. generates the witness (`generate_witness.js` + WASM),
  2. creates a Groth16 proof (`snarkjs groth16 prove`),
  3. verifies the proof (`snarkjs groth16 verify`).

---

### `test_inputs/generate_inputs.js`

Node.js generator that:

* builds Poseidon Merkle trees using `circomlibjs`,
* extracts Merkle sibling paths,
* writes JSON inputs that the Circom WASM witness generators expect.

---

## Building Circuits Manually

```bash
# Compile (example: document existence)
circom proofs/circuits/document_existence.circom --r1cs --wasm --sym \
  -l proofs/node_modules -o proofs/build

# Groth16 setup
npx snarkjs groth16 setup proofs/build/document_existence.r1cs \
  proofs/keys/powersOfTau28_hez_final_17.ptau \
  proofs/build/document_existence_0000.zkey

npx snarkjs zkey contribute proofs/build/document_existence_0000.zkey \
  proofs/build/document_existence_final.zkey \
  --name="Dev contribution"

npx snarkjs zkey export verificationkey \
  proofs/build/document_existence_final.zkey \
  proofs/keys/verification_keys/document_existence_vkey.json
```

> Note: `setup_circuits.sh` automates the above for all circuits.

---

## Hash Boundary

* Circuits use **Poseidon** for in-circuit hashing (see `proofs/circuits/lib/poseidon.circom`).
* Python/ledger code uses **BLAKE3** (see `protocol/hashes.py`).

Witness generation must translate any external commitments into the field elements expected by the circuits.

---

## Security Considerations

These circuits are reference implementations used for protocol development and testing.

**Development keys are NOT suitable for production.** Production usage requires:

* Formal review / security audit
* A Phase 2 ceremony with ≥ 3 independent contributors
* Publicly published verification keys and ceremony transcript
* Parameter tuning / performance evaluation

---

## References

* Circom documentation
* snarkjs documentation
* Olympus Protocol Specification: `../docs/05_zk_redaction.md`

```

---

## Two tiny things you should update elsewhere (so docs never drift again)
1) In the repo root docs (if they mention `emptyLeaf`), change it to `leafIndex` for non-existence.  
2) In `Building Circuits Manually`, your PTAU filename was `_15` in the old text; your scripts use `_17`. I updated it above.

If you paste `proofs/circuits/redaction_validity.circom` *as it exists now* (post “Fix redaction validity constraints”), I can tighten that circuit description even further so it exactly matches the proved statement.
```
