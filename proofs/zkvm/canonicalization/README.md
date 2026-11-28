# Olympus canonicalization zkVM guest

This RISC Zero guest executes the canonical Rust implementation
`olympus_crypto::canonical::canonicalize_bytes` over private source JSON and
publishes only the fixed-width `OLYCAN01` claim defined in
`olympus_crypto::canonical_proof`.

The committed ELF is built with pinned RISC Zero `3.0.5` tooling and a running
Docker daemon. The script also pins the `risczero/risc0-guest-builder` image to
`r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3`
and stages the combined user-and-kernel `.bin` bytes that correspond to the
reported image ID:

```bash
bash proofs/zkvm/build_canonicalization_guest.sh
```

The desktop verifier computes the RISC Zero image ID from the committed ELF and
requires an exact match with the committed lowercase-hex `.id`; it never accepts
an image identifier supplied by the caller. Production startup exits instead
of serving with a placeholder or mismatched artifact. Builds compile RISC
Zero's `disable-dev-mode` feature so fake receipts cannot verify.

Native Windows receipt verification is supported. RISC Zero does not
officially provide native Windows proving tooling; proof generation therefore
runs on Linux/WSL2 via the explicit `zkvm-prover` feature and is never silently
delegated to a network service.

## Validation artifacts

`cycle-report.json` records deterministic execution of eight adversarial inputs
against the pinned guest. The worst case is the 1 MiB reverse-key object at
744,183,696 user cycles. Olympus enforces a shared 1,073,741,824-user-cycle
ceiling (2^30), leaving roughly 30.7% of the enforced ceiling unused while
keeping every proof bounded.

`receipt-fixture.json` is a real succinct receipt generated with
`RISC0_DEV_MODE` unset and re-proven under RISC Zero 3.1.0. Desktop verifier
tests and the standalone Rust verifier both authenticate it against the
committed ELF/image ID; the JavaScript conformance test independently consumes
its fixed-width journal claim.

## Receipt compatibility and re-proving

The guest is pinned to RISC Zero `3.0.5`; the host-side prover and both
verifiers are pinned to `risc0-zkvm 3.1.0` (`risc0-circuit-recursion` 4.1.0).
RISC Zero binds the succinct verifier parameters into verification: a receipt
names the parameters digest it was produced under, and the verifier accepts
exactly one. 4.1.0 is a different recursion circuit, so the accepted digest
moved from `ece5e9b8…` to `f57f355f…`.

A receipt produced by a RISC Zero 3.0.x prover therefore fails with:

```text
receipt was produced for a version of the verifier with parameters digest
ece5e9b8…; expected f57f355f…
```

That is a stale proof, not a tampered one: the receipt is bound to a proof
system configuration this verifier no longer accepts. The two digests in the
message are what distinguish the two cases.

Re-proving is the only remedy. The verifier never sees the source JSON, so a
holder must keep the original source bytes and run the pinned prover again —
the `host-tools` prover, or `POST /zk/prove` on a build with the `zkvm-prover`
feature. Olympus persists neither the receipt nor its source
(`canonicalizationReceipt` is a request payload), so there is no stored
artifact to migrate or delete, and Olympus cannot re-prove on a holder's
behalf.

There is no path that accepts both control roots. Letting a receipt's own
parameters digest select its trust configuration would double the accepted
recursion-circuit surface and let an old-circuit proof satisfy a statement
whose verifier was deliberately moved off a yanked release. Prover and
verifier must be upgraded together; builds on either side of this change do not
interoperate.

Both verifiers pin the expected succinct parameters digest in a unit test, so a
future `risc0-zkvm` bump fails CI instead of quietly changing which receipts
are accepted. See
[ADR-0040](../../../docs/adr/ADR-0040-risc-zero-canonicalization-receipts.md).
