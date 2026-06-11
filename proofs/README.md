# Zero-Knowledge Proofs for Olympus

This directory contains the Circom circuits and Groth16 tooling used by Olympus to
generate and verify zero-knowledge proofs over Poseidon-based Merkle commitments.

These proofs are designed to let a prover demonstrate properties about a committed
document *without revealing private leaf values or Merkle path details*.

---

## Quick Start

```bash
# 1) Dev/single-contributor path — produces .wasm/.r1cs/.ark.zkey + vkey JSON
#    for all 4 circuits in proofs/keys/.  Acceptable for v0.9, NOT for v1.0.
#
#    Runs npm ci internally; needs circom in PATH, Node ≥18, nasm, g++, make.
#    Will download Hermez ptau20 if proofs/keys/powersOfTau28_hez_final_20.ptau
#    is absent; either way the BLAKE2b checksum is verified before use.
bash proofs/setup_circuits.sh

# 2) Smoke test — end-to-end prove + verify for each circuit
bash proofs/smoke_test.sh

# 3) Constraint-level checks ("formal verification" fast lane)
bash proofs/formal_verify.sh

# 4) Static analysis of the circuit sources (no compilation needed)
cargo install circomspect            # once
bash proofs/circomspect.sh
````

> Circuit verification (circomspect / Ecne / Picus) and the dynamic test layers
> (adversarial soundness battery + property-based witness fuzzing) are described
> in [`FORMAL_VERIFICATION.md`](./FORMAL_VERIFICATION.md).

## Multi-Contributor Phase 2 Ceremony (required for v1.0)

For a production release the Phase 2 contribution chain must be ≥ 3
independent parties.  `phase2_ceremony.sh` splits the work into four
subcommands so each contributor runs their step on their own machine:

```bash
# Coordinator — produces round-0 zkey files from Phase 1 ptau:
bash proofs/setup_circuits.sh --compile-only         # produce r1cs/wasm only
bash proofs/phase2_ceremony.sh prepare ceremony/round0

# Distribute ceremony/round0/ to contributor 1, who runs:
bash proofs/phase2_ceremony.sh contribute ceremony/round0 ceremony/round1 \
    --name "Alice <alice@example.com>"
#   (no --entropy flag → snarkjs prompts interactively for a passphrase
#    and mixes /dev/urandom — preferred for live ceremonies)

# …forward ceremony/round1/ to contributor 2, etc.

# Coordinator after the chain returns — verify, optionally beacon, finalize:
bash proofs/phase2_ceremony.sh verify   ceremony/roundN
bash proofs/phase2_ceremony.sh finalize ceremony/roundN \
    --beacon "$(openssl rand -hex 32)" --beacon-iter 10
```

`finalize` writes:
- `proofs/keys/<circuit>.{wasm,r1cs,ark.zkey}` (runtime artifacts)
- `proofs/keys/verification_keys/<circuit>_vkey.json`
- `proofs/keys/PROVENANCE.md` (ptau hash + vkey fingerprints + full
  contribution chain extracted from the finalized zkey)

---

## Configuring Circuit Parameters

Default circuit sizes are defined in `proofs/circuits/parameters.circom`. For
production-scale trees, edit that file directly (the Python helper CLI that
used to regenerate it was retired with the Python stack in v0.9.0). After
updating the parameters file, re-run `bash setup_circuits.sh` to compile the
circuits and regenerate keys.

---

## Circuits

### `document_existence.circom`

Poseidon Merkle inclusion proof that exposes the **leaf index** as a public input
and keeps the **leaf value** private.

**Proves:** “A leaf exists at public `leafIndex` in the Poseidon Merkle tree with public `root`.”

**Does NOT prove:**
- That the leaf value corresponds to any specific document or canonicalization pipeline
- That the Poseidon root is anchored in the Olympus ledger (that linkage is external)

---

### `redaction_validity.circom`

Selective redaction proof over a Poseidon Merkle tree.

**Proves (current implementation):**

* For each leaf where `revealMask[i] == 1`, the prover knows a leaf value that is included
  in the original tree with `originalRoot`. Redacted leaves skip Merkle checks to reduce
  constraint pressure, so only revealed indices are fully enforced.
* A public `redactedCommitment` is computed as a Poseidon chain over the masked leaf vector
  (revealed values; redacted slots contribute 0) and `revealedCount`.

**Important notes:**

* This circuit is a *reference implementation* for “subset authenticity + commitment”.
* It does **not** by itself guarantee a particular text-format redaction policy (e.g., FOIA rules),
  and it does not reconstruct or validate a rendered redacted document string.
* It does **not** prove that the redacted commitment was anchored in the ledger; that linkage must
  be established via the Olympus verification bundle.

---

### `non_existence.circom`

Indexed “absence-at-index” proof for an **indexed Merkle tree**.

**Proves:** “The leaf at public `leafIndex` is the empty value `0` in the Poseidon Merkle tree
with public `root`.”

**Not a full sparse Merkle keyed non-membership proof.**
This circuit does not accept a key/value pair or prove divergence; it proves emptiness at a specific index.

**Does NOT prove:**
- Non-existence of an arbitrary key in a sparse Merkle tree
- Any linkage to an Olympus ledger entry without external validation

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
│   ├── parameters.circom         # Configurable circuit constants
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

* Downloads the Hermez/Polygon Hermez Powers of Tau file (`2^20`).
* Compiles all three main circuits with Circom (`.r1cs`, `.wasm`, `.sym`).
* Runs Groth16 Phase 2 setup with a **single dev contribution**.
* Exports verification keys to `keys/verification_keys/`.
* Writes `keys/PROVENANCE.md` with PTAU source, SHA-256 hashes, and verification key fingerprints.

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

### `formal_verify.sh`

* Generates fresh witness inputs for all primary circuits.
* Uses `snarkjs wtns check` to validate each witness against its `.r1cs`
  constraints.
* Acts as a deterministic "no accidental proof leakage path" guardrail by
  confirming only circuit-constrained relations are satisfied before proof
  generation.
* Optional passes: `--constraint-report` (per-circuit constraint counts),
  `--circomspect` (static analysis of the sources, see below), `--ecne` /
  `--picus` (under-constrained-signal SMT analysis when those binaries are on
  `PATH`).

### `circomspect.sh`

* Static analysis of every circuit **source** via Trail of Bits' `circomspect`
  — no compilation or ceremony artifact required.
* Flags under-constrained / unconstrained / unused signals.
* **Gating, strict by default**: fails on any finding not in
  `circomspect_baseline.txt` (the reviewed accepted-false-positive set). Pass
  `--advisory` to report-only, `--ci` to emit `build/circomspect_results.json`
  + per-circuit SARIF, `--update-baseline` to accept the current findings after
  an intentional circuit change (review the diff before committing).

See [`FORMAL_VERIFICATION.md`](./FORMAL_VERIFICATION.md) for the full
verification + dynamic-testing playbook (including the Rust adversarial
soundness battery and property-based witness tests).

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
  proofs/keys/powersOfTau28_hez_final_20.ptau \
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
* Ledger code uses **BLAKE3** (see `crates/olympus-crypto/src/lib.rs`).

Witness generation must translate any external commitments into the field elements expected by the circuits.

---

## Security Considerations

These circuits are reference implementations used for protocol development and testing.

**Development keys are NOT suitable for production.** Production usage requires:

* Formal review / security audit
* Constraint-audit workflow (`bash formal_verify.sh`) in addition to smoke proofs
* A Phase 2 ceremony with ≥ 3 independent contributors
* Publicly published verification keys and ceremony transcript
* Parameter tuning / performance evaluation

For higher-assurance proving systems, Halo2/KZG remains an explicit migration
path via the modular backend boundary (see `protocol/halo2_backend.py` and
`docs/adr/0002-halo2-proof-system.md`).

**Setup provenance (required):**

- Record PTAU source URL, SHA-256 hash, and download method.
- Record verification key fingerprints (SHA-256) for every circuit.
- Treat `.ptau`, `.zkey`, and generated witness artifacts as sensitive until audited.

---

## References

* Circom documentation
* snarkjs documentation
* Olympus Protocol Specification: `../docs/05_zk_redaction.md`

---

## Performance Tuning

### RapidSNARK (optional Linux x86-64 prover)

The default prover (`snarkjs groth16 prove`) runs inside a Node.js/V8 process and
is single-threaded for the expensive FFT/MSM steps. **RapidSNARK** is a C++ native
prover (Mysten Labs fork, Apache 2.0) that parallelises these steps across all
available CPU cores using hand-tuned Intel assembly.

RapidSNARK is an optional backend. Olympus ledger verification, Merkle proofs,
canonicalization, shard/global roots, replay verification, signed records, and
the independent verifier do not require RapidSNARK. It is only used when all of
the following are true:

* `OLYMPUS_ENABLE_RAPIDSNARK=1`
* the runtime platform is Linux x86-64
* a `rapidsnark` binary is present in `PATH`

Unsupported platforms, such as Windows native, macOS ARM, and non-x86 runners,
fall back to snarkjs. Normal CI does not build RapidSNARK; the dedicated
`.github/workflows/rapidsnark.yml` job validates the optional backend on
`ubuntu-latest` x86-64.

**Install RapidSNARK on supported Linux x86-64 hosts:**

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends build-essential g++ libgmp-dev libsodium-dev nasm pkg-config
git clone --recursive https://github.com/MystenLabs/rapidsnark.git /tmp/rapidsnark
cd /tmp/rapidsnark
npm install
git submodule update --init --recursive
npx task createFieldSources
npx task buildProver
sudo cp /tmp/rapidsnark/build/prover /usr/local/bin/rapidsnark
```

Enable it explicitly when running proof generation:

```bash
OLYMPUS_ENABLE_RAPIDSNARK=1 bash proofs/smoke_test.sh
```

If RapidSNARK is disabled, unavailable, or unsupported, the backend falls back to
snarkjs transparently.

**Expected speedups (GitHub standard 2-core runner):**

| Circuit | snarkjs | rapidsnark | Speedup |
|---------|---------|------------|---------|
| `document_existence` (~8k constraints) | ~10s | ~2s | ~5× |
| `redaction_validity` (~466k constraints) | ~30s | ~5s | ~6× |
| `non_existence` (~70k constraints) | ~60s | ~10s | ~6× |

> ✅ Rapidsnark produces **identical proofs** to snarkjs for the same witness.
> No circuit or key changes are required.  The same `.zkey` and `.wtns` files
> are used.

### Parallel proof generation (future)

With rapidsnark, each CPU core can be occupied with a different proof.  Batch
workflows that need multiple proofs (e.g., N redaction proofs for a large document
set) should launch independent `prove_circom` calls (`src-tauri/src/zk/prove.rs`)
on a worker pool (e.g. `tokio::task::spawn_blocking` per proof).

> ⚠️ API-level parallel proof generation is not yet implemented (requires
> endpoint changes).  The pattern above is documented for future use.
