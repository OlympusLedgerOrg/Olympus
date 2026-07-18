# Olympus ZK Proofs

This directory contains the Circom circuits, Groth16 tooling, and pinned RISC
Zero canonicalization guest used by the Olympus Rust/Tauri runtime. Runtime
verification happens in Rust; Groth16 uses arkworks artifacts exported from
snarkjs.

## Quick Start

```bash
# Dev/single-contributor path. Produces .wasm/.r1cs/.ark.zkey + vkey JSON in
# proofs/keys/. Suitable for development only; v1.0 requires a multi-party
# Phase 2 ceremony.
bash proofs/setup_circuits.sh

# End-to-end witness/prove/verify smoke checks for generated smoke circuits.
bash proofs/smoke_test.sh

# Constraint-level witness checks and optional static analysis.
bash proofs/formal_verify.sh
cargo install circomspect --locked || cargo install circomspect
bash proofs/circomspect.sh
```

Circuit verification and the dynamic testing layers are described in
[FORMAL_VERIFICATION.md](./FORMAL_VERIFICATION.md).

## Production Ceremony

The dev setup path uses one Phase 2 contributor and is not court-grade. For a
production release, each circuit needs a Phase 2 contribution chain with at
least three independent parties:

```bash
bash proofs/setup_circuits.sh --compile-only
bash proofs/phase2_ceremony.sh prepare ceremony/round0
bash proofs/phase2_ceremony.sh contribute ceremony/round0 ceremony/round1 \
    --name "Alice <alice@example.com>"
bash proofs/phase2_ceremony.sh verify ceremony/roundN
bash proofs/phase2_ceremony.sh finalize ceremony/roundN \
    --beacon "$(openssl rand -hex 32)" --beacon-iter 10
```

`finalize` writes runtime artifacts, verification keys, and
`proofs/keys/PROVENANCE.md` with the PTAU hash, vkey fingerprints, and
contribution transcript.

## Active Circuits

| Circuit | Purpose |
|---|---|
| `document_existence` | Poseidon Merkle inclusion proof with public root, leaf index, and tree size. |
| `non_existence` | Sparse-tree absence proof for a key and public root. |
| `unified_canonicalization_inclusion_root_sign` | Historical artifact stem for the structured section commitment, Merkle inclusion, and ledger-root SMT inclusion proof; it proves neither canonicalization nor signatures. |
| `federation_quorum` | Optional quorum attestation circuit for federation checkpoint policy. |

The combined `unified_canonicalization_inclusion_root` protocol is not a new
Circom circuit. Its fixed RISC Zero guest runs the exact shared Rust
JCS/NFC/decimal canonicalizer and emits a one-section journal binding the source
commitment, canonical length, and canonical digest. The verifier derives the
existing unified-circuit section commitment from that journal. The raw
`unified_section_commitment_inclusion_root` Groth16 statement remains available,
and the misleading historical `_sign` public identifier remains retired.

ADR-0030 removed the former `redaction_validity` Groth16 circuit. Redaction
verification now uses signed Merkle replay in the Rust/JavaScript verifiers
rather than a SNARK.

## Directory Layout

```text
proofs/
├── circuits/                      active Circom sources and shared libraries
├── zkvm/                          pinned canonicalization guest + build script
├── keys/                          runtime .wasm/.r1cs/.ark.zkey artifacts
│   └── verification_keys/         exported snarkjs vkey JSON files
├── test_inputs/                   witness input generators for smoke checks
├── build/                         compiled artifacts (gitignored)
├── setup_circuits.sh              PTAU download, compile, dev setup, export
├── phase2_ceremony.sh             multi-contributor ceremony orchestration
├── smoke_test.sh                  end-to-end snarkjs prove + verify
├── formal_verify.sh               witness constraint checks
└── circomspect.sh                 static Circom analysis gate
```

Circuit parameters live in `proofs/circuits/parameters.circom`. Edit that file
directly, then rerun `bash proofs/setup_circuits.sh`.

## Scripts

`setup_circuits.sh` downloads and checksum-verifies the Hermez/Polygon
`powersOfTau28_hez_final_20.ptau`, compiles circuits, runs dev Phase 2 setup,
exports vkeys, converts zkeys to arkworks `.ark.zkey`, and writes provenance.

`smoke_test.sh` generates JSON inputs, builds witnesses from the compiled WASM,
creates Groth16 proofs, and verifies them with snarkjs. RapidSNARK can be used
for proving on Linux x86-64 by setting `OLYMPUS_ENABLE_RAPIDSNARK=1` and
putting `rapidsnark` on `PATH`.

`formal_verify.sh` runs `snarkjs wtns check`, reports constraint counts when
requested, verifies that the retired `redaction_validity` source has not
silently re-entered the workflow, and can delegate to circomspect/Ecne/Picus.

`circomspect.sh` is strict by default. It fails on any current finding not
listed in `circomspect_baseline.txt`. Use `--advisory` for exploratory runs,
`--ci` for machine-readable output, and `--update-baseline` only after an
intentional circuit change and review.

## Security Notes

- Development keys are not production-safe.
- Production use requires a reviewed multi-contributor Phase 2 ceremony,
  published verification keys, and an auditable transcript.
- The Rust runtime consumes `.ark.zkey` files. The snarkjs
  `${circuit}_final.zkey` files are still required by `smoke_test.sh` and other
  snarkjs proof tooling.
- `.ptau`, `.zkey`, witness, proof, and public-signal artifacts should be
  treated as sensitive until reviewed.
- The canonicalization receipt is verified against the image ID derived from
  the committed guest ELF; RISC Zero development-mode receipts are invalid.
- Local RISC Zero proving is enabled only by the `zkvm-prover` feature on a
  supported Linux environment (including WSL2). Receipt verification remains
  available on native Windows and the other supported desktop targets.
- Adding the receipt composition changes no Groth16 constraints, R1CS, vkey,
  zkey, or ceremony manifest and therefore requires no Groth16 ceremony. Any
  later executable circuit or artifact change still follows the atomic ceremony
  workflow.

## References

- [Circom documentation](https://docs.circom.io/)
- [snarkjs documentation](https://github.com/iden3/snarkjs)
- [ADR-0030 redaction signed Merkle replay](../docs/adr/ADR-0030-redaction-signed-merkle-drop-groth16.md)
- [ADR-0040 RISC Zero canonicalization receipts](../docs/adr/ADR-0040-risc-zero-canonicalization-receipts.md)
- [Court evidence runbook](../docs/court-evidence.md)
