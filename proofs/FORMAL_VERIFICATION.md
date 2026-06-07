# Circuit Verification & Dynamic Testing

This document describes the two complementary layers that guard the Olympus
zero-knowledge circuits beyond the round-trip smoke tests:

1. **Formal circuit verification** — static / constraint-level analysis of the
   Circom sources and R1CS (does the circuit *say* what we think it says?).
2. **Dynamic testing** — randomised and adversarial execution of the witness
   validators and the in-process Groth16 verifier (does the implementation
   *behave* soundly on inputs we didn't hand-pick?).

---

## 1. Formal verification

### Fast lane — `circomspect` (static analysis)

[`circomspect`](https://github.com/trailofbits/circomspect) (Trail of Bits) is a
static analyser for Circom. It reads the `.circom` sources directly — **no
compilation, witness, or trusted-setup artifact required** — and flags classic
soundness/quality issues: under-constrained signals, signals assigned with
`<--` but never constrained with `===`, unused outputs, shadowing, and
non-quadratic constraints.

```bash
# Install once:
cargo install circomspect

# Analyse every production circuit (human-readable):
pnpm --dir proofs formal:circomspect
#   ≡ bash proofs/circomspect.sh

# Machine-readable: JSON summary + per-circuit SARIF under proofs/build/:
bash proofs/circomspect.sh --ci

# Fail on any finding (use once the baseline below is cleared):
bash proofs/circomspect.sh --strict
```

`circomspect.sh` is **advisory by default** (exit 0 unless `--strict`): it
surfaces findings without breaking the build. CI runs it on every PR that
touches `proofs/circuits/**` (job `formal-circuit-verify`) and uploads the
results as the `circomspect-results` artifact, but does **not** gate merges yet
— see *Baseline* below.

#### Current baseline (advisory)

As of this writing the five production circuits produce **8 warnings, 0 errors**:

| Circuit | Warnings | Notes |
|---|---|---|
| `document_existence` | 2 | unused `Num2BitsStrict` output / `<--` assignment notice |
| `non_existence` | 0 | clean |
| `redaction_validity` | 2 | unused `Num2BitsStrict` output / `<--` assignment notice |
| `unified_canonicalization_inclusion_root_sign` | 4 | unused `Num2BitsStrict` outputs |
| `federation_quorum` | 0 | clean |

All 8 fall into two categories:

* **"output signal `out` … is not constrained"** — `Num2BitsStrict(n)` is
  instantiated purely for its *range-enforcing* side-effect constraints; the
  decomposed `out` bits are intentionally not consumed. This is the documented
  circomspect false-positive for range-check-only `Num2Bits*` usage.
* **"`<--` does not constrain the assigned signal"** — a witness-only
  assignment that is separately constrained by a paired `===`.

These are reviewed and accepted; the intent is to **clear or explicitly
allow-list each one, then flip CI to `--strict`** so any *new* finding blocks
the build. Until then the job is informational (gate-later).

### Constraint lane — `formal_verify.sh`

`formal_verify.sh` works on the *compiled* artifacts (needs
`bash setup_circuits.sh` first). It generates fresh witnesses and runs
`snarkjs wtns check` to confirm each witness satisfies its R1CS, and bundles a
few circuit-specific grep assertions (domain-separation tags, L4-C binding,
binary-mask constraints).

```bash
bash proofs/formal_verify.sh                       # witness constraint checks
bash proofs/formal_verify.sh --constraint-report   # + per-circuit constraint counts
bash proofs/formal_verify.sh --circomspect          # + the static fast lane above
bash proofs/formal_verify.sh --ci --circomspect      # JSON results for CI

# Everything at once:
pnpm --dir proofs formal:all
```

### Deep lane — Ecne / Picus (optional)

`formal_verify.sh --ecne` / `--picus` invoke the
[Ecne](https://github.com/franklynwang/EcneProject) and
[Picus](https://github.com/Veridise/Picus) under-constrained-signal analysers
over the R1CS when their binaries are on `PATH`. They use SMT/Gröbner
techniques to find under-constrained signals that witness-level checks miss.
Both gracefully **skip** (recording a `skip` result) when not installed, so they
never break the build — install them locally for a deeper pass before a release.

---

## 2. Dynamic testing

### Adversarial soundness battery — `tests/zk_soundness.rs`

For **every production circuit** this builds a genuinely-verifying proof with
the in-process prover, then asserts the verifier rejects:

* every single-public-signal `+1` perturbation (Groth16 binds *all* public
  inputs),
* a structurally-forged proof (negated `A` component),
* wrong public-signal arity (too few / too many).

The valid-witness constructions live in the shared `tests/zk_fixtures/` module
(reused, not duplicated, from the round-trip fixtures). Like the round-trip
tests these **skip cleanly** when the ceremony artifacts from
`setup_circuits.sh` are absent.

```bash
cargo test -p olympus-desktop --features prover,zk-test-utils --test zk_soundness
```

CI runs this in the existing `tauri-prover-tests` job (it carries the
`prover,zk-test-utils` features).

### Property-based witness validation — `tests/zk_witness_proptest.rs`

[`proptest`](https://docs.rs/proptest) drives thousands of randomised inputs
through the **witness validators** (`ExistenceWitness::new`,
`NonExistenceWitness::new`, `RedactionWitness::new` and their
`verify_merkle_root` / `path_indices` helpers), asserting the *invariants over
the whole input space*:

* any wrong array length is rejected,
* any non-binary path index is rejected (at the first offending position),
* an index that doesn't LSB-reconstruct its leaf position is rejected
  (anti-leaf-reuse, audit L4-C),
* the Merkle-root round-trip is self-consistent for arbitrary field values, and
  any other root is a `RootMismatch`,
* `path_indices` derivation is deterministic and key-sensitive.

These need neither the `prover` feature nor any artifact, so they run in the
lean (`--no-default-features`) test job:

```bash
cargo test -p olympus-desktop --test zk_witness_proptest
```

---

## How the layers fit together

| Layer | Target | Needs artifacts? | Gates CI? |
|---|---|---|---|
| `circomspect` | circuit *sources* | no | advisory (gate-later) |
| `formal_verify.sh` (wtns check) | compiled R1CS | yes | local / opt-in |
| Ecne / Picus | R1CS | yes + binary | local / opt-in |
| `zk_soundness.rs` | verifier (real proofs) | yes (skips if absent) | yes (prover job) |
| `zk_witness_proptest.rs` | witness validators | no | yes (lean job) |
