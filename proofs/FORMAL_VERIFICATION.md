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

# Analyse every production circuit (strict gate, baseline-diffed):
pnpm --dir proofs formal:circomspect
#   ≡ bash proofs/circomspect.sh

# Machine-readable: JSON summary + per-circuit SARIF under proofs/build/:
bash proofs/circomspect.sh --ci

# Report only, never fail (exploratory local runs):
bash proofs/circomspect.sh --advisory

# Accept the CURRENT findings as the new baseline (after an intentional
# circuit change — review the diff before committing):
bash proofs/circomspect.sh --update-baseline
```

`circomspect.sh` is a **gating check, strict by default**. It is run on every PR
that touches `proofs/circuits/**` or the baseline (CI job
`formal-circuit-verify`, which also uploads the `circomspect-results` artifact).

#### Baseline allow-list (`circomspect_baseline.txt`)

To gate without failing on a known set of reviewed false-positives, each finding
is reduced to a stable signature `ruleId|file|line` and diffed against the
committed `proofs/circomspect_baseline.txt`:

* a current finding **not** in the baseline → **NEW** → fails the build;
* a baseline entry **not** in the current output → **stale** → reported,
  non-fatal (prune it).

Because the signature includes the **source line**, the baseline allow-lists
*exact locations*, not whole rule classes — a new instance of an already-accepted
rule class at a new line still blocks. Update the baseline only via
`--update-baseline` (never hand-edit), and justify every entry here.

#### Accepted findings (the committed baseline — 8, all reviewed false-positives)

| Rule | Locations | Why it is accepted |
|---|---|---|
| **CS0005** "`<--` does not constrain the assigned signal" | `document_existence:27`, `redaction_validity:44`, `unified_…:61` | The idiomatic `Num2Bits` bit-decomposition `out[i] <-- (in >> i) & 1`. The `<--` is *mandatory* — bit extraction is non-quadratic so it cannot be a `<==` — and `out[i]` is fully pinned by the paired `out[i]*(1-out[i])===0` binary constraint **and** the `sum === in` reconstruction. Byte-identical to circomlib's `Num2Bits`. Unfixable by design. |
| **CS0018** "output signal `out` … is not constrained" | `document_existence:58`, `redaction_validity:99`, `unified_…:128,138,170` | `Num2BitsStrict(n)` instantiated purely for its range-enforcing constraints (`leafIndex`/`sectionCount`/`sectionLength` `< 2^n`); the decomposed `out` bits are intentionally discarded. Consuming them only to satisfy the linter would *add* constraints for no soundness benefit. |

> These are deliberately **allow-listed, not "fixed"**: editing security-critical
> circuit source to silence an idiomatic false-positive would change the R1CS
> (forcing a vkey/manifest regeneration) for no soundness gain. A genuine new
> finding — anything outside this table — fails CI and must be fixed or, if
> reviewed and accepted, added via `--update-baseline` with a justification row
> above.

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
* a truncated public-signal vector (a dropped input changes the prepared-input
  commitment, so the pairing fails). Surplus *trailing* inputs are deliberately
  not asserted on: ark-groth16 `zip`s inputs against `gamma_abc_g1` and silently
  ignores extras — an arkworks detail, not a soundness gap, since every verify
  path builds the exact-arity vector from the circuit definition.

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
| `circomspect` | circuit *sources* | no | **yes** — strict, baseline-diffed |
| `formal_verify.sh` (wtns check) | compiled R1CS | yes | local / opt-in |
| Ecne / Picus | R1CS | yes + binary | local / opt-in |
| `zk_soundness.rs` | verifier (real proofs) | yes (skips if absent) | yes (prover job) |
| `zk_witness_proptest.rs` | witness validators | no | yes (lean job) |
