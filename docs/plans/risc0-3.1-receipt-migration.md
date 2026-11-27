# Plan (for review): RISC Zero 3.1 receipt migration

**Status:** Core bump merged in [#1752](https://github.com/OlympusLedgerOrg/Olympus/pull/1752)
(`359c7c7c`, 2026-11-27); the P1/P2/P5 slice (CHANGELOG, pinned-digest tests,
operator note) landed in `a86c9d13` (2026-11-27). What remains: keep the guest
rebuild canary green (P3) and, only if it starts failing, migrate the guest to
3.1.0 (P4).
**Scope:** ADR-0040 canonicalization receipts. No Groth16, journal, or ceremony
change.

---

## 0. Where this stands

- Host-side `risc0-zkvm` moved from `=3.0.5` to `=3.1.0` in `src-tauri`,
  `verifiers/rust` (plus its fuzz crate), and
  `proofs/zkvm/canonicalization/host-tools`. `risc0-circuit-recursion` moved
  from 4.0.5 to 4.1.0, which ships its circuits as crates instead of downloading
  them at build time.
- The guest deliberately stays on RISC Zero 3.0.5. Its combined user-and-kernel
  ELF, image ID (`ab7f2f33…8e9d`), and 96-byte journal are byte-identical before
  and after the migration; only the receipt bytes changed.
- The committed fixture was re-proven by the `measure cycles and generate
receipt fixture` job (run 45935028508) and both verifiers accept it:
  `committed_succinct_receipt_fixture_verifies_offline` (`verifiers/rust`, 10/10)
  and `committed_succinct_receipt_fixture_verifies` (`olympus-desktop`, 7/7).
- ADR-0040 gained a **Verifier and prover version** section recording the split
  pins, the changed control IDs, and the no-dual-root rule.
- The `rebuild pinned guest ELF` job in `zkvm-guest.yml` still installs
  `cargo-risczero 3.0.5` from crates.io and reproduces the committed ELF/`.id`
  byte-for-byte after the yank (run 45945233498 on `714c055c`). So the pinned
  guest is currently rebuildable, not merely present.
- The six Dependabot alerts this work was aimed at (#179–181 root `Cargo.lock`,
  #208–210 host-tools) were all `zip`, reached only through
  `risc0-circuit-recursion 4.0.5`. They report `fixed` at
  `2026-11-27T06:56:57Z`; `zip` no longer appears in the host-tools lockfile, and
  the root lockfile's remaining `zip` is 9.8.1 (the advisories cover ≤ 9.0.4).
  No further dependency change is needed to close them.
- The P1/P2/P5 slice landed as `a86c9d13`: the CHANGELOG entry, the operator
  re-prove note in `proofs/zkvm/canonicalization/README.md`, and the pinned
  parameters-digest regression test in both verifiers —
  `canonicalization::tests::pinned_succinct_verifier_parameters_match_risc_zero_3_1_0`
  in `verifiers/rust` and
  `zk::canonicalization::tests::pinned_succinct_verifier_parameters_match_risc_zero_3_1_0`
  in `olympus-desktop`. Both assert the strict context carries the 3.1.0 digest
  (`f57f355f…`) and not the 3.0.x digest (`ece5e9b8…`).

So the dependency, fixture, and boundary work is done: what happens to _other_
3.0.x receipts is now stated in the CHANGELOG and the canonicalization README,
and the boundary is a tested property rather than a paragraph. What remains is
P3's canary and the conditional P4 guest migration.

## 1. What changed for a receipt

| Fact                                | Before (3.0.5 / 4.0.5) | After (host 3.1.0 / 4.1.0) |
| ----------------------------------- | ---------------------- | -------------------------- |
| Guest ELF + image ID                | `ab7f2f33…8e9d`        | unchanged                  |
| Journal encoding (96 bytes)         | `OLYCAN01`             | unchanged                  |
| Source / canonical commitments      | BLAKE3 domains         | unchanged                  |
| Recursion circuit                   | 4.0.5                  | 4.1.0 (new circuit)        |
| Allowed control root                | `a54dc85a…`            | `e6feef13…`                |
| Succinct verifier parameters digest | `ece5e9b8…`            | `f57f355f…`                |
| Receipt bytes                       | 3.0.5-proven           | re-proven under 3.1.0      |
| Olympus claim format                | `version: 1`           | unchanged                  |

The claim contract is stable. The _proof system_ configuration is not, and
RISC Zero binds it into verification: a succinct receipt names the parameters
digest it was produced under, and the verifier accepts exactly one.

## 2. The compatibility boundary

**3.0.x receipts do not verify under the 3.1.0 pin, by design.** The failure is
`ReceiptRejected("receipt was produced for a version of the verifier with
parameters digest ece5e9b8…; expected f57f355f…")`.

That is the right default. The alternative — building a `VerifierContext` per
receipt or accepting both allowed control roots — makes the receipt's own
metadata select a trust configuration. It doubles the accepted recursion-circuit
surface, and it would let an old-circuit proof satisfy a statement whose
verifier was deliberately moved off a yanked release. ADR-0040 records the
no-dual-root decision; the rest of this plan assumes it.

Two consequences worth stating plainly:

1. **Re-proving is the only path for an old receipt.** The verifier never sees
   the source JSON, so Olympus cannot re-prove on a caller's behalf. A holder
   must retain the source bytes and run the pinned prover again.
2. **Olympus does not persist receipts.** `canonicalizationReceipt` is a request
   payload (`src-tauri/src/api/zk/mod.rs`), and the offline verifier reads it
   from a file (`verifiers/rust/src/bin/verify.rs`). There is no database
   column, so there is no data migration and no stored artifact to invalidate.

The error text already names both digests, which is enough for an operator to
tell "stale receipt" from "tampered receipt". No new diagnostic field is
required; §4 P5 just documents where that message comes from.

## 3. Decisions

**D1 — Keep the guest at 3.0.5 for this migration.** Moving the guest changes
the image ID, the committed ELF/`.id`, every fixture, and the cycle baseline — a
trust-root change that deserves its own review. 3.0.5 is yanked, so the
remaining question is whether the pinned build still runs; the existing
`reproducible-guest` job answers that, and it passed on `714c055c` after the
yank. If it later fails, P4 becomes mandatory and this plan grows by one PR; do
not paper over it with a locally built ELF.

**D2 — Test the boundary with pinned digests, not a second 778 KB receipt.**
The positive fixture is already 778 KB. Committing the old receipt purely as a
negative fixture would nearly double that for one assertion. Instead, pin both
succinct-parameters digests and the two allowed control roots in a unit test:
the current context must equal the 3.1.0 values and differ from the 3.0.5
values. Keep the one-off manual reproduction (the exact `ReceiptRejected` text
above) in the PR description.

**D3 — Treat this as a verifier change, not a claim-format change.** The
journal magic stays `OLYCAN01` and the fixture `version` stays `1`; bumping
either would falsely imply the claim encoding moved. The compatibility note
belongs in the CHANGELOG, ADR-0040 (already added), and the release notes for
the first build that ships 3.1.0.

## 4. Work items

| #   | Item                                                                                                 | Size | Status            | Files                                                                            |
| --- | ---------------------------------------------------------------------------------------------------- | ---- | ----------------- | -------------------------------------------------------------------------------- |
| P1  | CHANGELOG entry: verifier pin, rejected 3.0.x receipts, re-prove requirement                         | S    | Done (`a86c9d13`) | `CHANGELOG.md`                                                                   |
| P2  | Parameters-digest regression test in both verifiers                                                  | S    | Done (`a86c9d13`) | `verifiers/rust/src/canonicalization.rs`, `src-tauri/src/zk/canonicalization.rs` |
| P3  | Keep the existing guest rebuild canary green (no new code)                                           | —    | Existing CI       | `.github/workflows/zkvm-guest.yml` (already implemented)                         |
| P4  | _Conditional:_ guest 3.1.0 migration (new image ID, ELF/`.id`, fixture, cycle report, ADR amendment) | L    | Conditional       | `proofs/zkvm/canonicalization/**`, `docs/adr/ADR-0040…`                          |
| P5  | Operator note: what a parameters-digest rejection means, how to re-prove                             | S    | Done (`a86c9d13`) | `proofs/zkvm/canonicalization/README.md`                                         |

P1, P2, and P5 landed as `a86c9d13`. P3 is existing CI coverage, not a change.
P4 is separate and only if P3 starts failing.

**P2 shape (landed in `a86c9d13`).** `strict_verifier_context()` exists in both
verifiers. Assert `context.succinct_verifier_parameters.digest()` equals the
pinned 3.1.0 digest and is not the 3.0.5 digest. That makes a future silent
`risc0-zkvm` bump fail CI instead of quietly changing which receipts are
accepted — the exact failure #1752 had to discover through a red fixture test.

**P3 shape.** Nothing to build. `zkvm-guest.yml`'s `reproducible-guest` job
already runs `bash proofs/zkvm/build_canonicalization_guest.sh` after installing
`cargo-risczero 3.0.5`, then `git diff --exit-code`s the ELF and `.id`. The
`measure-and-fixture` job consumes its artifact, so a toolchain or lockfile
regression fails before a fixture is produced. Watch this job when touching the
guest manifest; do not add a second canary.

## 5. Verification

| Check              | Command                                                                                           | Proves                                            |
| ------------------ | ------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Offline verifier   | `(cd verifiers/rust && cargo test --locked canonicalization)`                                     | Fixture verifies; digest pins hold                |
| Desktop verifier   | `cargo test --locked -p olympus-desktop --no-default-features --features prover canonicalization` | Same, on the shipping path                        |
| Fixture job        | `zkvm-guest.yml` → `measure cycles and generate receipt fixture`                                  | Re-prove still works under the pin                |
| Guest canary (P3)  | `zkvm-guest.yml` → `rebuild pinned guest ELF`                                                     | ELF/`.id` byte-identical, toolchain installable   |
| Dependency closure | `cargo tree -i zip` at root and in host-tools                                                     | No `zip` under 9.0.5 on any shipped or tools path |

The fixture test alone is not enough: it proves the new receipt verifies, not
that the old one is rejected. P2's inequality assertion is what covers the
boundary.

## 6. Rollout and rollback

- **Rollout** is the merged bump; there is no staged flag. Any build older than
  #1752 will reject receipts from a 3.1.0 prover and vice versa, so a prover and
  verifier must be upgraded together. That is the same atomicity ADR-0040
  already requires for guest changes.
- **Rollback is not available.** RISC Zero yanked every 3.0.x/4.0.x release and
  the 4.0.x circuit download returns 403, so re-pinning the old graph would
  break builds rather than restore verification. The forward fix for a bad
  3.1.0 pin is a new pin, not a downgrade.
- Clients holding 3.0.x receipts re-prove from retained source bytes; Olympus
  has nothing to migrate or delete.

## 7. Done criteria

1. P1, P2, and P5 are merged (`a86c9d13`); P2 fails if the context digest
   drifts.
2. The guest canary is green (it is today), or P4 has an owner and a separate
   ADR amendment.
3. No open Dependabot alert for `zip` (already true) and `cargo tree -i zip`
   shows nothing below 9.0.5 on a shipped path.
4. ADR-0040, README, and CHANGELOG tell the same story: 3.0.x receipts are
   rejected, re-proving is required, and there is no dual-root path. Compared
   against all three — ADR-0040 §"Verifier and prover version", the README's
   "Receipt compatibility and re-proving", and the Unreleased CHANGELOG entry —
   they agree on the split pins, the rejected receipt class, and the absence of
   a dual-root path.

**Explicitly not in scope:** changing the journal, the Groth16 circuit, the
ceremony artifacts, or the receipt's base64/JSON envelope.
